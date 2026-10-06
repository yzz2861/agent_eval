require 'spec_helper'

describe MessagePack::Map do
  let(:duplicate_payload) do
    MessagePack::Packer.new.tap do |packer|
      packer.write_map_header(8)
      packer.write('dup')
      packer.write('first')
      packer.write('dup')
      packer.write('second')
      packer.write(1)
      packer.write('integer')
      packer.write(1.0)
      packer.write('float')
      packer.write([1, 2])
      packer.write('compound-first')
      packer.write([1, 2])
      packer.write('compound-second')
      packer.write('nested')
      packer.write_map_header(2)
      packer.write('nested_dup')
      packer.write('one')
      packer.write('nested_dup')
      packer.write('two')
      packer.write('ext')
      packer.write_extension(MessagePack::ExtensionValue.new(7, 'value'))
    end.full_pack
  end

  it 'preserves every wire entry as ordered key-value pairs' do
    map = MessagePack::Factory.new.load(duplicate_payload, preserve_maps: true, allow_unknown_ext: true)

    expect(map).to be_a(described_class)
    expect(map.to_a).to eq([
      ['dup', 'first'],
      ['dup', 'second'],
      [1, 'integer'],
      [1.0, 'float'],
      [[1, 2], 'compound-first'],
      [[1, 2], 'compound-second'],
      ['nested', MessagePack::Map.from_pairs([
        ['nested_dup', 'one'],
        ['nested_dup', 'two'],
      ])],
      ['ext', MessagePack::ExtensionValue.new(7, 'value')],
    ])
    expect(map.keys).to eq(['dup', 'dup', 1, 1.0, [1, 2], [1, 2], 'nested', 'ext'])
  end

  it 'does not merge integer and float keys or duplicate compound keys' do
    map = MessagePack.load(duplicate_payload, preserve_maps: true, allow_unknown_ext: true)

    expect(map.length).to eq(8)
    expect(map.values_at_key(1)).to eq(['integer'])
    expect(map.values_at_key(1.0)).to eq(['float'])
    expect(map.values_at_key([1, 2])).to eq(['compound-first', 'compound-second'])
  end

  it 'packs entries and nested maps using the map wire type' do
    map = MessagePack::Factory.new.load(duplicate_payload, preserve_maps: true, allow_unknown_ext: true)
    expect(MessagePack.pack(map)).to eq(duplicate_payload)

    nested_map = map.fetch('nested')
    expected_nested_payload = MessagePack::Packer.new.tap do |packer|
      packer.write_map_header(2)
      packer.write('nested_dup')
      packer.write('one')
      packer.write('nested_dup')
      packer.write('two')
    end.full_pack
    expect(MessagePack.pack(nested_map)).to eq(expected_nested_payload)
    expect(MessagePack.unpack(MessagePack.pack(nested_map))).to eq('nested_dup' => 'two')
  end

  it 'uses the configured map class' do
    custom_map_class = Class.new(MessagePack::Map)
    map = MessagePack::Factory.new.load(duplicate_payload, map_class: custom_map_class, allow_unknown_ext: true)
    expect(map).to be_a(custom_map_class)
    expect(map.fetch('nested')).to be_a(custom_map_class)
  end

  it 'keeps the default Hash behavior unless preservation is enabled' do
    map = MessagePack.load(duplicate_payload, allow_unknown_ext: true)
    expect(map).to be_a(Hash)
    expect(map.fetch('dup')).to eq('second')
    expect(map.keys).to eq(['dup', 1, 1.0, [1, 2], 'nested', 'ext'])
  end

  it 'freezes nested maps and pair arrays in freeze mode' do
    unpacker = MessagePack::Unpacker.new(freeze: true, preserve_maps: true, allow_unknown_ext: true)
    unpacker.feed(duplicate_payload)
    map = unpacker.read
    nested = map.fetch('nested')

    expect(map).to be_frozen
    expect(nested).to be_frozen
    expect(map.first).to be_frozen
    expect(nested.first).to be_frozen
    expect(map.fetch(1)).to eq('integer').and be_frozen
  end

  it 'keeps the wire sequence when a map arrives across multiple feeds' do
    unpacker = MessagePack::Unpacker.new(preserve_maps: true, allow_unknown_ext: true)
    partial_feed_points = [0, 1, 2, 3, 7, duplicate_payload.bytesize / 2, duplicate_payload.bytesize - 1]

    partial_feed_points.each do |point|
      bytes = duplicate_payload.dup.force_encoding(Encoding::BINARY)
      unpacker.feed(bytes.byteslice(0, point))
      expect { unpacker.read }.to raise_error(EOFError) if point < duplicate_payload.bytesize
      unpacker.feed(bytes.byteslice(point, bytes.bytesize - point))
      expected = MessagePack.load(duplicate_payload, preserve_maps: true, allow_unknown_ext: true).to_a
      expect(unpacker.read.to_a).to eq(expected)
      unpacker.reset
    end
  end

  it 'waits for a multi-byte map header to arrive across feeds' do
    payload = MessagePack::Packer.new.tap do |packer|
      packer.write_map_header(1)
      packer.write('key')
      packer.write('value')
    end.full_pack

    [1, 2].each do |point|
      unpacker = MessagePack::Unpacker.new(preserve_maps: true)
      unpacker.feed(payload.byteslice(0, point))
      expect { unpacker.read }.to raise_error(EOFError)
      unpacker.feed(payload.byteslice(point, payload.bytesize - point))
      expect(unpacker.read.to_a).to eq([['key', 'value']])
    end
  end

  it 'lets factory extension callbacks receive nested preserved maps' do
    extension_type = Class.new
    factory = MessagePack::Factory.new
    factory.register_type(7, extension_type, packer: nil,
      unpacker: ->(_data) { :extension })

    map = factory.load(duplicate_payload, preserve_maps: true)
    expect(map.fetch('ext')).to eq(:extension)
    expect(map.fetch('nested')).to be_a(described_class)
  end

  it 'lets registered extensions override ordered map subclasses during packing' do
    custom_map_class = Class.new(MessagePack::Map)
    factory = MessagePack::Factory.new
    type_module = Module.new
    custom_map_class.include(type_module)
    factory.register_type(8, type_module, packer: ->(_map) { 'custom' })
    map = custom_map_class.from_pairs([['key', 'value']])

    expect(factory.dump(map)).to eq(MessagePack::ExtensionValue.new(8, 'custom').to_msgpack)
  end

  it 'requires an explicit conflict strategy when converting to a Hash' do
    map = described_class.from_pairs([
      ['a', 1],
      ['a', 2],
      [1.0, 3],
      [1, 4],
    ])

    expect { map.to_h }.to raise_error(ArgumentError)
    expect { map.to_h(:raise) }.to raise_error(described_class::DuplicateKeyError)
    expect(map.to_h(:keep_last)).to eq('a' => 2, 1.0 => 3, 1 => 4)
    expect(map.to_h(:first)).to eq('a' => 1, 1.0 => 3, 1 => 4)
    expect(map.to_h(:last)).to eq('a' => 2, 1.0 => 3, 1 => 4)
    resolver = proc { |_key, old_value, new_value| [old_value, new_value].sum }
    expect(map.to_h(resolver)).to eq('a' => 3, 1.0 => 3, 1 => 4)
    expect(map.to_h { |_key, old_value, new_value| old_value + new_value }).to eq('a' => 3, 1.0 => 3, 1 => 4)
  end
end
