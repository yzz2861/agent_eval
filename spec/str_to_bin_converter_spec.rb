# encoding: ascii-8bit

require "spec_helper"
require "stringio"

describe MessagePack::StrToBinConverter do
  def str(value)
    value.dup.force_encoding(Encoding::UTF_8)
  end

  it "converts only explicit nested paths and preserves all other wire bytes" do
    large = str("L" * 256)
    input = MessagePack.dump(
      str("data") => {
        str("small") => str("abc"),
        str("large") => large,
        str("keep") => str("same"),
        str("nested") => {str("value") => str("xyz")},
      },
      str("items") => [
        {300 => str("array-key")},
        42,
      ],
      str("extension") => MessagePack::ExtensionValue.new(99, "unknown".b),
    )

    bad_factory = MessagePack::Factory.new
    bad_factory.register_type(
      99,
      Object,
      unpacker: ->(_payload) { raise "registered extension decoder must not be called" },
    )
    expect { bad_factory.load(input) }.to raise_error(RuntimeError, /registered extension decoder/)

    converter = described_class.new(
      described_class::Path.map(str("data")).map(str("small")),
      described_class::Path.map(str("data")).map(str("large")),
      described_class::Path.map(str("data")).map(str("nested")).map(str("value")),
      described_class::Path.map(str("items")).index(0).map(300),
    )
    result = converter.convert(input)
    output = result.output

    expect(result.mismatches).to eq([])
    expect(output.bytesize).to eq(input.bytesize + 3)

    small_key = input.index("\xa5small")
    small_offset = input.index("\xa3abc", small_key)
    large_key = input.index("\xa5large")
    large_offset = input.index("\xda\x01\x00#{large}".b, large_key)
    nested_key = input.index("\xa5value")
    nested_offset = input.index("\xa3xyz", nested_key)
    array_offset = input.index("\xa9array-key")

    changes = [
      [small_offset, "\xa3abc".b, "\xc4\x03abc".b],
      [large_offset, "\xda\x01\x00#{large}".b, "\xc5\x01\x00#{large}".b],
      [nested_offset, "\xa3xyz".b, "\xc4\x03xyz".b],
      [array_offset, "\xa9array-key".b, "\xc4\x09array-key".b],
    ]
    expected = String.new.b
    cursor = 0
    changes.sort_by(&:first).each do |source_position, original, replacement|
      expected << input[cursor...source_position]
      expected << replacement
      cursor = source_position + original.bytesize
    end
    expected << input[cursor..-1]
    expect(output).to eq(expected)

    ext_header = "\xc7\x07cunknown"
    ext_offset = input.index(ext_header)
    expect(output[ext_offset + 3, ext_header.bytesize]).to eq(ext_header)
    expect(output[ext_offset + 3, 3]).to eq("\xc7\x07c")

    factory = MessagePack::Factory.new
    factory.register_type(99, Object, unpacker: ->(payload) { [:custom_ext, payload] })
    converted = factory.load(output)
    expect(converted[str("data")][str("small")].encoding).to eq(Encoding::ASCII_8BIT)
    expect(converted[str("data")][str("large")].encoding).to eq(Encoding::ASCII_8BIT)
    expect(converted[str("data")][str("nested")][str("value")].encoding).to eq(Encoding::ASCII_8BIT)
    expect(converted[str("data")][str("keep")]).to eq(str("same"))
    expect(converted[str("extension")]).to eq([:custom_ext, "unknown".b])
  end

  it "keeps container length headers unchanged when a short string gains a byte" do
    input = "\x81\xa3foo\xa3bar".b
    output = described_class.convert(input, described_class::Path.map(str("foo")))

    expect(output).to eq("\x81\xa3foo\xc4\x03bar".b)
    expect(output.bytesize).to eq(input.bytesize + 1)
    expect(output.getbyte(0)).to eq(input.getbyte(0))
  end

  it "rejects a non-string match with path and byte offset by default" do
    integer = MessagePack.dump(42)
    input = MessagePack.dump(str("foo") => 42, str("bar") => str("x"))
    path = described_class::Path.map(str("foo"))

    expect do
      described_class.new(path).convert(input)
    end.to raise_error(described_class::PathTypeMismatchError) do |error|
      expect(error.path).to eq(path)
      expect(error.type).to eq(:integer)
      expect(error.offset).to eq(input.index(integer))
    end
  end

  it "skips non-string matches, reports position, and converts siblings" do
    integer = MessagePack.dump(42)
    input = MessagePack.dump(str("foo") => 42, str("bar") => str("x"))
    path = described_class::Path.map(str("foo"))
    sibling_path = described_class::Path.map(str("bar"))

    result = described_class.new(path, sibling_path, on_non_string: :skip).convert(input)

    expect(result.mismatches).to eq([
      described_class::Mismatch.new(path, :integer, input.index(integer)),
    ])
    expect(result.output).to eq("\x82\xa3foo#{integer}\xa3bar\xc4\x01x".b)
  end

  it "distinguishes map keys from array positions" do
    input = MessagePack.dump([{str("0") => str("map")}, str("array")])
    map_path = described_class::Path.index(0).map(str("0"))
    array_path = described_class::Path.index(1)

    output = described_class.new(map_path, array_path).convert(input).output

    expect(output).to eq(MessagePack.dump([{str("0") => "map".b}, "array".b]))
  end

  it "matches map keys by MessagePack value rather than integer length encoding" do
    key_raw = "\xcc\x2a".b
    input = "\x81#{key_raw}\xa1z".b
    output = described_class.convert(input, described_class::Path.map(42))

    expect(output).to eq("\x81#{key_raw}\xc4\x01z".b)
  end

  it "does not match a binary key as a string rule" do
    input = "\x82\xa1a\xa4text\xc4\x01a\xaabinary-key".b
    output = described_class.convert(input, described_class::Path.map(str("a")))

    expect(output).to eq("\x82\xa1a\xc4\x04text\xc4\x01a\xaabinary-key".b)
  end

  it "matches nil map keys" do
    input = "\x81\xc0\xa1z".b
    output = described_class.convert(input, described_class::Path.map(nil))

    expect(output).to eq("\x81\xc0\xc4\x01z".b)
  end

  it "streams to an output IO without instantiating a Ruby representation" do
    input = StringIO.new("\x81\xa1a\xa1z".b)
    output = StringIO.new
    described_class.new(described_class::Path.map(str("a"))).convert(input, output)

    expect(output.string).to eq("\x81\xa1a\xc4\x01z".b)
  end

  it "converts str32 and preserves an unhit unknown extension byte for byte" do
    value = str("X" * 65_536)
    input = MessagePack.dump(
      str("big") => value,
      str("ext") => MessagePack::ExtensionValue.new(123, "?".b),
    )

    result = described_class.new(
      described_class::Path.map(str("big")),
    ).convert(input)

    big_key = input.index("\xa3big".b)
    old_value = "\xdb" + [value.bytesize].pack("L>") + value
    new_value = "\xc6" + [value.bytesize].pack("L>") + value
    source_position = input.index(old_value.b, big_key)
    expected = input.byteslice(0, source_position) + new_value.b +
      input.byteslice(source_position + old_value.bytesize, input.bytesize)
    expect(result.output).to eq(expected)
    expect(result.output.index("\xd4{?".b)).to eq(input.index("\xd4{?".b))
  end

  it "can target the root value" do
    expect(described_class.convert(MessagePack.dump(str("root")), described_class::Path.root)).to eq("\xc4\x04root".b)
  end

  it "exposes the conversion at the MessagePack module level" do
    input = MessagePack.dump(str("a") => str("z"))
    output = MessagePack.convert_str_to_bin(input, described_class::Path.map(str("a")))

    expect(output).to eq("\x81\xa1a\xc4\x01z".b)
  end

  it "keeps already-binary values untouched even when a sibling path converts" do
    input = MessagePack.dump(str("binary") => "bytes".b, str("string") => str("text"))
    result = described_class.new(
      described_class::Path.map(str("binary")),
      described_class::Path.map(str("string")),
      on_non_string: :skip,
    ).convert(input)

    expect(result.mismatches.map(&:type)).to eq([:bin])
    expect(result.output).to eq(MessagePack.dump(str("binary") => "bytes".b, str("string") => "text".b))
  end

  it "raises on truncated and trailing wire data" do
    expect { described_class.new.convert("\xda\x00".b) }.to raise_error(described_class::MalformedWireError)
    expect do
      described_class.new.convert("\xa0\xa0".b)
    end.to raise_error(described_class::MalformedWireError, /extra bytes/)
  end
end
