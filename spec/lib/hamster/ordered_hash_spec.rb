require "spec_helper"
require "hamster/ordered_hash"
require "hamster/ordered_map"

describe Hamster::OrderedHash do
  let(:empty) { described_class.empty }

  it "is aliased as Hamster::OrderedMap" do
    expect(Hamster::OrderedMap).to be(described_class)
  end

  it "is immutable" do
    expect(empty).to be_frozen
    expect(empty.put(:a, 1)).to be_frozen
  end

  it "preserves insertion order" do
    map = empty.put(:a, 1).put(:b, 2).put(:c, 3)
    expect(map.to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
    expect(map.each_key.to_a).to eq([:a, :b, :c])
    expect(map.each_value.to_a).to eq([1, 2, 3])
    expect(map.reverse_each.to_a).to eq([[:c, 3], [:b, 2], [:a, 1]])
  end

  it "updates an existing key without changing its position" do
    original = empty.put(:a, 1).put(:b, 2)
    updated = original.put(:a, 99)

    expect(updated.to_a).to eq([[:a, 99], [:b, 2]])
    expect(original.to_a).to eq([[:a, 1], [:b, 2]])
  end

  it "moves a deleted key to the end when it is reinserted" do
    map = empty.put(:a, 1).put(:b, 2).put(:c, 3)
    reinserted = map.delete(:a).put(:a, 9)

    expect(reinserted.to_a).to eq([[:b, 2], [:c, 3], [:a, 9]])
    expect(map.to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
  end

  it "returns self for deleting a missing key or storing the same value object" do
    map = empty.put(:a, [1])
    value = map[:a]

    expect(map.delete(:b)).to be(map)
    expect(map.put(:a, value)).to be(map)
  end

  it "keeps nil keys and nil values distinct from missing keys" do
    map = empty.put(nil, nil)

    expect(map.key?(nil)).to be(true)
    expect(map[nil]).to be(nil)
    expect(map.fetch(nil, :default)).to be(nil)
    expect(map.fetch(:missing, :default)).to be(:default)
    expect(map.to_a).to eq([[nil, nil]])
  end

  it "keeps a default block through empty results and store updates" do
    map = described_class.new { |key| "default-#{key}" }
    populated = map.store(:a, 1)
    emptied = populated.delete(:a)

    expect(populated[:missing]).to eq("default-missing")
    expect(emptied[:missing]).to eq("default-missing")
    expect(emptied.class).to be(described_class)
    expect(emptied.store(:b, 2).to_a).to eq([[:b, 2]])
  end

  it "supports keys which are equivalent by hash and eql? but not ==" do
    first = DeterministicHash.new("a", 7)
    second = DeterministicHash.new("b", 7)
    lookup_a = DeterministicHash.new("a", 7)
    lookup_b = DeterministicHash.new("b", 7)
    map = empty.put(first, 1).put(second, 2)

    expect(map.size).to eq(2)
    expect(map[lookup_a]).to eq(1)
    expect(map[lookup_b]).to eq(2)
    expect(map.each_key.map(&:value)).to eq(["a", "b"])
  end

  it "does not treat hash collisions as duplicate keys" do
    values = Array.new(500) { |index| [DeterministicHash.new("k#{index}", index % 5), index] }
    map = values.reduce(empty) { |result, (key, value)| result.put(key, value) }

    values.each do |key, value|
      expect(map[key]).to eq(value)
    end
    expect(map.size).to eq(500)
    expect(map.each_key.map(&:value)).to eq(values.map { |key, _| key.value })
  end

  it "freezes mutable string keys copied into the map" do
    string = +"a"
    map = empty.put(string, 1)
    string.upcase!

    expect(map["a"]).to eq(1)
    expect(map["A"]).to be_nil
    expect(map.each_key.first).to be_frozen
  end

  it "keeps existing keys in receiver order and appends new keys in source order" do
    receiver = empty.put(:a, 1).put(:b, 2).put(:c, 3)
    source = empty.put(:c, 30).put(:d, 40).put(:a, 10).put(:e, 50)

    merged = receiver.merge(source)
    expect(merged.to_a).to eq([[:a, 10], [:b, 2], [:c, 30], [:d, 40], [:e, 50]])

    merged_with_block = receiver.merge(source) { |_, old_value, new_value| old_value + new_value }
    expect(merged_with_block.to_a).to eq([[:a, 11], [:b, 2], [:c, 33], [:d, 40], [:e, 50]])

    ruby_merged = receiver.merge(c: 30, d: 40, a: 10, e: 50)
    expect(ruby_merged.to_a).to eq([[:a, 10], [:b, 2], [:c, 30], [:d, 40], [:e, 50]])
  end

  it "initializes from a Ruby hash and preserves its iteration order" do
    source = {a: 1, b: 2, c: 3}
    expect(described_class.new(source).to_a).to eq(source.to_a)
    expect(described_class[source].to_a).to eq(source.to_a)
  end

  it "supports filtering in insertion order" do
    map = empty.put(:a, 1).put(:b, 2).put(:c, 3)

    expect(map.select { |_, value| value != 2 }.to_a).to eq([[:a, 1], [:c, 3]])
    expect(map.reject { |_, value| value == 2 }.to_a).to eq([[:a, 1], [:c, 3]])
    expect(map.slice(:c, :a).to_a).to eq([[:a, 1], [:c, 3]])
  end

  it "preserves the order of many retained versions during interleaved reads" do
    versions = []
    map = empty

    200.times do |index|
      map = map.put(index, index)
      versions << map if index.even?
    end

    100.times do |offset|
      index = offset * 2
      expected = (0..index).map { |number| [number, number] }
      expect(versions[offset].to_a).to eq(expected)
    end

    versions.each do |version|
      expect(version[version.size - 1]).to eq(version.size - 1)
    end
  end

  it "removes order nodes for deleted keys and remains balanced through repeated churn" do
    version = empty
    300.times { |index| version = version.put(index, index) }

    100.times do |cycle|
      deleted = (cycle * 3) % 300
      keys = 30.times.map { |offset| (deleted + offset) % 300 }
      keys.each { |key| version = version.delete(key) }
      expect(version.instance_variable_get(:@order).size).to eq(270)
      keys.each { |key| version = version.put(key, key) }
      expect(version.size).to eq(300)
      expect(version.each_key.count).to eq(300)
      expect(version.each_key.uniq.size).to eq(300)
      expect(version.instance_variable_get(:@order).size).to eq(300)
      expect(version.instance_variable_get(:@next_sequence)).to eq(300 + 30 * (cycle + 1))
    end

    expect(version[0]).to eq(0)
    expect(version[299]).to eq(299)
  end

  it "keeps the persistent order tree balanced after arbitrary deletions and reinsertions" do
    empty_node = described_class::OrderNode::Empty
    root = empty_node
    versions = []
    500.times do |sequence|
      root = root.put(sequence, [sequence, sequence])
      versions << root if sequence.even?
    end

    deletion_order = (0...500).to_a.shuffle
    deletion_order.each { |sequence| root = root.delete(sequence) }
    deletion_order.first(300).each { |sequence| root = root.put(sequence, [sequence, sequence]) }

    expect(height_balanced?(root)).to be(true)
    keys = []
    root.each { |key, _| keys << key }
    expect(keys).to eq(keys.sort)

    versions.each_with_index do |version, index|
      keys = []
      version.each { |key, _| keys << key }
      expect(keys).to eq((0..(index * 2)).to_a)
    end
  end

  it "compares ordered pairs with eql? while remaining compatible with Ruby hashes" do
    abc = described_class[a: 1, b: 2, c: 3]
    acb = described_class[a: 1, c: 3, b: 2]

    expect(abc.eql?(described_class.new(abc.to_a))).to be(true)
    expect(abc.eql?(acb)).to be(false)
    expect(abc == {a: 1, b: 2, c: 3}).to be(true)
    expect(abc == {a: 1, c: 3, b: 2}).to be(false)
    expect(abc.hash).not_to eq(acb.hash)
  end

  it "survives marshalling with its order intact" do
    map = described_class[a: 1, b: 2, c: 3].delete(:b).put(:b, 20)
    reloaded = Marshal.load(Marshal.dump(map))

    expect(reloaded).to be_a(described_class)
    expect(reloaded.to_a).to eq([[:a, 1], [:c, 3], [:b, 20]])
  end

  def height_balanced?(node)
    return true if node.equal?(described_class::OrderNode::Empty)
    balanced_height(node)[2]
  end

  def balanced_height(node)
    return [0, 0, true, nil] if node.equal?(described_class::OrderNode::Empty)

    left_height, _, left_balanced, left_key = balanced_height(node.left)
    right_height, _, right_balanced, right_key = balanced_height(node.right)
    ordered = left_balanced && right_balanced &&
              (left_key.nil? || left_key < node.key) &&
              (right_key.nil? || node.key < right_key)
    balanced = ordered && (left_height - right_height).abs <= 1

    [[left_height, right_height].max + 1, node.size, balanced, node.key]
  end
end
