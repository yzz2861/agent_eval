require 'spec_helper'

describe MessagePack::Map do
  subject(:factory) { MessagePack::Factory.new }

  def packed_map(*pairs)
    factory.dump(described_class.new(pairs))
  end

  it 'preserves the wire order of every entry' do
    payload = packed_map(
      ['string', 'first'],
      ['string', 'second'],
      [1, 'integer'],
      [1.0, 'float'],
      [[1, 2], 'composite'],
      [[1.0, 2.0], 'numeric composite'],
    )

    map = factory.load(payload, ordered_maps: true)

    expect(map).to be_a(described_class)
    expect(map.pairs).to eq([
      ['string', 'first'],
      ['string', 'second'],
      [1, 'integer'],
      [1.0, 'float'],
      [[1, 2], 'composite'],
      [[1.0, 2.0], 'numeric composite'],
    ])
  end

  it 'does not let Ruby Hash key equivalence collapse integer and float entries' do
    payload = packed_map([1, 'integer'], [1.0, 'float'], [1, 'third'])

    expect(factory.load(payload)).to eq(1 => 'third', 1.0 => 'float')

    map = factory.load(payload, ordered_maps: true)
    expect(map.pairs).to eq([
      [1, 'integer'],
      [1.0, 'float'],
      [1, 'third'],
    ])
  end

  it 'keeps repeated composite keys distinct in the entry sequence' do
    payload = packed_map(
      [described_class.new([[:x, 1]]), 'first'],
      [described_class.new([[:x, 1]]), 'second'],
    )

    map = factory.load(payload, ordered_maps: true)

    expect(map.size).to eq(2)
    expect(map.values).to eq(%w[first second])
    expect(map.keys).to all(be_a(described_class))
  end

  it 'works for maps nested inside arrays, maps, and extensions' do
    custom_class = Class.new do
      attr_reader :value

      def initialize(value)
        @value = value
      end
    end

    factory.register_type(
      0x01,
      custom_class,
      packer: ->(object) { object.value.to_msgpack },
      unpacker: ->(data) { custom_class.new(factory.load(data, ordered_maps: true)) },
    )

    nested = described_class.new([
      [:outer, [described_class.new([[:a, 1], [:a, 2]])]],
      [:ext, custom_class.new(described_class.new([[:b, 3], [:b, 4]]))],
    ])

    decoded = factory.load(factory.dump(nested), ordered_maps: true)

    expect(decoded['outer'][0].pairs).to eq([['a', 1], ['a', 2]])
    expect(decoded['ext'].value.pairs).to eq([['b', 3], ['b', 4]])
  end

  it 'uses the current factory for non-recursive extensions containing ordered maps' do
    factory.register_type(
      0x04,
      custom_class = Class.new do
        attr_reader :map

        def initialize(map)
          @map = map
        end
      end,
      packer: ->(object) { object.map.to_msgpack },
      unpacker: ->(data) { custom_class.new(factory.load(data, ordered_maps: true)) },
    )

    object = custom_class.new(described_class.new([['a', 1], ['a', 2]]))

    expect(factory.load(factory.dump(object)).map.pairs).to eq([['a', 1], ['a', 2]])
  end

  it 'encodes the complete ordered mapping instead of converting it to a Hash' do
    map = described_class.new([['a', 1], ['a', 2], [1, 'x'], [1.0, 'y']])

    expect(factory.dump(map)).to eq(packed_map(['a', 1], ['a', 2], [1, 'x'], [1.0, 'y']))
  end

  it 'lets the current factory register an extension for the container' do
    factory.register_type(
      0x02,
      described_class,
      packer: ->(map, packer) {
        packer.write_map_header(map.size)
        map.each do |key, value|
          packer.write(key)
          packer.write(value)
        end
      },
      unpacker: ->(unpacker) {
        map = described_class.new
        unpacker.read_map_header.times do
          map.add(unpacker.read, unpacker.read)
        end
        map
      },
      recursive: true,
    )

    map = described_class.new([[:a, 1], [:a, 2]])

    expect(factory.load(factory.dump(map))).to be_a(described_class)
  end

  it 'requires an explicit conflict strategy when converting to a Hash' do
    duplicate_map = described_class.new([['a', 1], ['a', 2]])
    unique_map = described_class.new([['a', 1]])

    expect { duplicate_map.to_h }.to raise_error(ArgumentError, /conflict/)
    expect { unique_map.to_h }.to raise_error(ArgumentError, /conflict/)
    expect(duplicate_map.to_h(:first)).to eq('a' => 1)
    expect(duplicate_map.to_h(:last)).to eq('a' => 2)
    expect(unique_map.to_h(:raise)).to eq('a' => 1)
    expect { duplicate_map.to_h(:raise) }.to raise_error(ArgumentError, /duplicate map key/)
  end

  it 'returns copies of its pair arrays' do
    map = described_class.new([['a', 1]])

    map.pairs[0][0] = 'b'

    expect(map.pairs).to eq([['a', 1]])
  end

  it 'can be constructed from one pair sequence' do
    map = described_class[[['a', 1], ['a', 2]]]

    expect(map.pairs).to eq([['a', 1], ['a', 2]])
  end

  it 'freezes the stored protocol entries in freeze mode' do
    payload = packed_map(
      ['a', described_class.new([[:b, 'c']])],
      [[:d], ['e', 'f']],
    )

    map = factory.load(payload, ordered_maps: true, freeze: true)

    expect(map).to be_frozen
    expect(map.keys[0]).to be_frozen
    expect(map.keys[1]).to be_frozen
    expect(map.values[0]['b']).to eq('c')
    expect(map.values[0]).to be_frozen
    expect(map.values[1][1]).to be_frozen
    expect { map.add('z', 1) }.to raise_error(FrozenError)
  end

  it 'preserves the entry sequence when the map arrives across multiple feeds' do
    payload = "\x83\xa1a\x01\xa1a\x02\xcb?\xf0\x00\x00\x00\x00\x00\x00\xa5float".b
    unpacker = factory.unpacker(ordered_maps: true)

    chunks = [payload[0...1], payload[1...3], payload[3..]]
    chunks.each { |chunk| unpacker.feed(chunk) }

    expect(unpacker.read.pairs).to eq([
      ['a', 1],
      ['a', 2],
      [1.0, 'float'],
    ])
  end

  it 'preserves ordered maps nested in arrays when feeds split at container boundaries' do
    payload = "\x92\x81\xa1a\x01\x81\xa1a\x02".b
    unpacker = factory.unpacker(ordered_maps: true)

    unpacker.feed(payload.byteslice(0, 2))
    unpacker.feed(payload.byteslice(2..))

    decoded = unpacker.read
    expect(decoded.map(&:pairs)).to eq([
      [['a', 1]],
      [['a', 2]],
    ])
  end

  it 'supports an explicit MessagePack::Map map class' do
    unpacker = factory.unpacker(map_class: described_class)
    unpacker.feed(packed_map(['a', 1], ['a', 2]))

    expect(unpacker.read.pairs).to eq([['a', 1], ['a', 2]])
  end

  it 'exposes whether ordered map decoding is enabled' do
    expect(factory.unpacker.ordered_maps?).to be(false)
    expect(factory.unpacker(ordered_maps: true).ordered_maps?).to be(true)
  end

  it 'accepts a MessagePack::Map subclass as an explicit map class' do
    subclass = Class.new(described_class)
    stub_const("OrderedTestMap", subclass)
    unpacker = factory.unpacker(map_class: OrderedTestMap)
    unpacker.feed(packed_map(['a', 1], ['a', 2]))

    expect(unpacker.read).to be_a(OrderedTestMap)
  end

  it 'does not affect ordinary Hash decoding by default' do
    payload = packed_map(['a', 'first'], ['a', 'last'])

    expect(factory.load(payload)).to eq('a' => 'last')
  end
end
