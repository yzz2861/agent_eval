# encoding: ascii-8bit
require "spec_helper"
require "objspace"
require "stringio"
require "weakref"
require "json"

describe MessagePack::Unpacker::BinaryView do
  let(:payload) do
    (0...100_000).map { |i| (i * 1103515245 + 12345) % 256 }.pack("C*")
  end

  def dump_reference(object)
    JSON.parse(ObjectSpace.dump(object)).fetch("references", []).first
  end

  it "returns binary views only when binary_view is enabled" do
    packed = MessagePack.pack(payload)

    default_value = MessagePack::Unpacker.new.tap { |u| u.feed(packed) }.read
    view_value = MessagePack::Unpacker.new(binary_view: true).tap { |u| u.feed(packed) }.read

    expect(default_value).to be_a(String)
    expect(default_value).not_to be_a(described_class)
    expect(view_value).to be_a(described_class)
    expect(view_value.encoding).to eq(Encoding::ASCII_8BIT)
    expect(view_value).to eq(payload)
  end

  it "accepts the option through Factory" do
    factory = MessagePack::Factory.new
    expect(factory.unpacker(binary_view: true).binary_view?).to be(true)
    expect(factory.load(MessagePack.pack(payload), binary_view: true)).to be_a(described_class)
  end

  it "keeps text strings as ordinary strings" do
    text = "hello".dup.force_encoding(Encoding::UTF_8)
    unpacker = MessagePack::Unpacker.new(binary_view: true)
    unpacker.feed(MessagePack.pack(text))

    value = unpacker.read
    expect(value).to eq("hello")
    expect(value).to be_a(String)
    expect(value).not_to be_a(described_class)
  end

  it "exposes length, ranged reads, and IO writes" do
    unpacker = MessagePack::Unpacker.new(binary_view: true)
    unpacker.feed(MessagePack.pack(payload))
    view = unpacker.read
    io = StringIO.new("".b)

    expect(view.bytesize).to eq(payload.bytesize)
    expect(view.byteslice(10, 5)).to eq(payload.byteslice(10, 5))
    expect(view.slice(10, 5)).to be_a(described_class)
    expect(view[10, 5]).to be_a(described_class)
    expect(view.write_to(io)).to eq(payload.bytesize)
    expect(io.string).to eq(payload)
  end

  it "is immutable and remains stable across feed, reset, GC, and input reuse" do
    input = MessagePack.pack(payload)
    unpacker = MessagePack::Unpacker.new(binary_view: true)
    unpacker.feed(input)
    view = unpacker.read

    unpacker.feed(MessagePack.pack("remaining"))
    unpacker.reset
    input.replace("")
    input << MessagePack.pack("reused")
    GC.start
    GC.compact if GC.respond_to?(:compact)

    expect(view).to eq(payload)
    expect(view.byteslice(99_990, 10)).to eq(payload.byteslice(99_990, 10))
    expect { view << "changed" }.to raise_error(FrozenError)
    expect(input).to eq(MessagePack.pack("reused"))
  end

  it "shares one complete mapped input chunk without copying the payload" do
    input = MessagePack.pack(payload)
    unpacker = MessagePack::Unpacker.new(binary_view: true)
    unpacker.feed(input)
    view = unpacker.read
    input_reference = dump_reference(input)
    view_reference = dump_reference(view)

    expect(view.zero_copy?).to be(true)
    expect(ObjectSpace.memsize_of(view)).to be < payload.bytesize / 10
    expect(view_reference).to eq(input_reference)
  end

  it "uses an explicit copied fallback for payloads split across inputs" do
    packed = MessagePack.pack(payload)
    unpacker = MessagePack::Unpacker.new(binary_view: true)
    chunks = packed.bytes.each_slice(5000).map { |bytes| bytes.pack("C*") }
    chunks.each do |chunk|
      unpacker.feed(chunk)
    end
    view = unpacker.read
    chunk_references = chunks.map { |chunk| dump_reference(chunk) }

    expect(view.zero_copy?).to be(false)
    expect(view).to eq(payload)
    expect(ObjectSpace.memsize_of(view)).to be > payload.bytesize
    expect(dump_reference(view)).to be_nil
    expect(chunk_references.compact).not_to be_empty
  end

  it "uses the copied fallback for data read from IO" do
    io = StringIO.new(MessagePack.pack(payload))
    unpacker = MessagePack::Unpacker.new(io, binary_view: true)
    view = unpacker.read

    expect(view.zero_copy?).to be(false)
    expect(view).to eq(payload)
    expect(ObjectSpace.memsize_of(view)).to be > payload.bytesize
  end

  it "allows the unpacker input chunk to be released after reset while retaining the view" do
    large_input = MessagePack.pack(payload)
    retained_input = MessagePack.pack("retained".b)
    unpacker = MessagePack::Unpacker.new(binary_view: true)
    large_ref = WeakRef.new(large_input)
    retained_ref = WeakRef.new(retained_input)
    unpacker.feed(large_input)
    unpacker.feed(retained_input)
    view = unpacker.read
    retained_view = unpacker.read
    expect(retained_view).to eq("retained".b)

    unpacker.reset
    large_input = nil
    GC.start
    GC.compact if GC.respond_to?(:compact)

    expect(large_ref.weakref_alive?).to be_falsey
    expect(retained_ref.weakref_alive?).to be(true)
    expect(view).to eq(payload)
    expect(retained_view).to eq("retained".b)
  end
end
