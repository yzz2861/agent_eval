require "spec_helper"
require "hamster/ordered_hash"

class CollidingEqlNotEqual < EqlNotEqual
  def hash
    7
  end
end

describe Hamster::OrderedHash do
  let(:ordered_hash_class) { described_class }

  def max_rank(hash)
    order = hash.instance_variable_get(:@order)
    order && described_class::OrderedSequence.max_key(order)
  end

  it "traverses pairs in insertion order" do
    hash = described_class[a: 1, b: 2, c: 3]

    expect(hash.to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
    expect(hash.keys.to_a).to eq([:a, :b, :c])
    expect(hash.values.to_a).to eq([1, 2, 3])
    expect(hash.reverse_each.to_a).to eq([[:c, 3], [:b, 2], [:a, 1]])
  end

  it "updates an existing key without moving it" do
    original = described_class[a: 1, b: 2, c: 3]
    updated = original.put(:b, 20)

    expect(updated.to_a).to eq([[:a, 1], [:b, 20], [:c, 3]])
    expect(original.to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
  end

  it "moves a deleted key to the end when it is reinserted" do
    hash = described_class[a: 1, b: 2, c: 3]
    result = hash.delete(:a).put(:a, 10)

    expect(result.to_a).to eq([[:b, 2], [:c, 3], [:a, 10]])
    expect(hash.to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
  end

  it "supports nil keys and nil values" do
    hash = described_class.new([[:a, nil], [nil, :nil_value]])

    expect(hash.key?(nil)).to be(true)
    expect(hash.key?(:a)).to be(true)
    expect(hash[nil]).to be(:nil_value)
    expect(hash[:a]).to be_nil
    expect(hash.delete(:a).to_a).to eq([[nil, :nil_value]])
  end

  it "resolves hash collisions with eql?" do
    first = DeterministicHash.new("a", 1)
    second = DeterministicHash.new("b", 1)
    third = DeterministicHash.new("a", 1)
    hash = described_class.new([[first, 1], [second, 2]])

    expect(hash.get(third)).to eq(1)
    expect(hash.put(third, 10).to_a).to eq([[first, 10], [second, 2]])
    expect(hash.delete(third).to_a).to eq([[second, 2]])
  end

  it "keeps many keys with the same hash code in insertion order" do
    keys = 40.times.map { |index| DeterministicHash.new("k#{index}", 99) }
    hash = described_class.new(keys.zip(0...40))
    replacement = DeterministicHash.new("k10", 99)

    expect(hash.keys).to eql(Hamster::Vector.new(keys))
    expect(hash.get(replacement)).to eq(10)
    expect(hash.put(replacement, 100).keys.to_a).to eq(keys)
    expect(hash.delete(replacement).keys.to_a).to eq(keys - [keys[10]])
  end

  it "does not call the default block for a stored nil value" do
    hash = described_class.new({a: nil}) { raise "default block called" }

    expect(hash.get(:a)).to be_nil
    expect { hash.put(:a) { |value| value } }.not_to raise_error
  end

  it "does not treat merely equal keys as the same key" do
    first = CollidingEqlNotEqual.new
    second = CollidingEqlNotEqual.new
    hash = described_class.new([[first, 1], [second, 2]])

    expect(hash.size).to eq(1)
    expect(hash.get(first)).to eq(2)
  end

  describe "#merge" do
    it "keeps existing key positions and appends new keys in the other's order" do
      left = described_class[a: 1, b: 2, c: 3]
      right = { d: 4, b: 20, e: 5, c: 30 }

      expect(left.merge(right).to_a).to eq(
        [[:a, 1], [:b, 20], [:c, 30], [:d, 4], [:e, 5]]
      )
    end

    it "keeps existing positions when conflict values come from a block" do
      left = described_class[a: 1, b: 2]
      right = described_class[b: 20, c: 3, a: 10]

      result = left.merge(right) { |_key, old_value, new_value| old_value + new_value }

      expect(result.to_a).to eq([[:a, 11], [:b, 22], [:c, 3]])
    end
  end

  describe "persistence" do
    it "can interleave reads from many historical versions" do
      versions = {}
      hash = described_class[a: 1, b: 2]
      versions[:initial] = hash

      hash = hash.put(:c, 3)
      versions[:added_c] = hash
      hash = hash.put(:b, 20)
      versions[:updated_b] = hash
      hash = hash.delete(:a)
      versions[:deleted_a] = hash
      hash = hash.put(:a, 10)
      versions[:readded_a] = hash

      expect(versions[:initial].to_a).to eq([[:a, 1], [:b, 2]])
      expect(versions[:added_c].to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
      expect(versions[:updated_b].to_a).to eq([[:a, 1], [:b, 20], [:c, 3]])
      expect(versions[:deleted_a].to_a).to eq([[:b, 20], [:c, 3]])
      expect(versions[:readded_a].to_a).to eq([[:b, 20], [:c, 3], [:a, 10]])
    end

    it "shares order-tree paths for an update" do
      hash = described_class[(0..6).zip(0..6)]
      order = hash.instance_variable_get(:@order)
      updated = hash.put(1, 100)
      deleted = hash.delete(1)

      expect(updated.instance_variable_get(:@order)).not_to equal(order)
      expect(updated.instance_variable_get(:@order).right).to equal(order.right)
      expect(updated.instance_variable_get(:@directory)).not_to equal(hash.instance_variable_get(:@directory))
      expect(deleted.instance_variable_get(:@order).right).to equal(order.right)
    end

    it "does not mutate a previous version when compaction creates a new one" do
      hash = described_class[a: 1, b: 2, c: 3]
      before_compaction = hash

      35.times do |index|
        hash = hash.put(:temp, index).delete(:temp)
      end

      expect(before_compaction.to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
      expect(hash.to_a).to eq([[:a, 1], [:b, 2], [:c, 3]])
      expect(hash.instance_variable_get(:@order)).not_to equal(before_compaction.instance_variable_get(:@order))
      expect(max_rank(hash)).to be < hash.size * 2 + 32
    end

    it "keeps internal ranks bounded after a long sequence of deletions and reinserts" do
      hash = described_class[a: 1, b: 2, c: 3]

      50.times do |index|
        hash = hash.put(:temp, index)
        hash = hash.delete(:a)
        hash = hash.put(:a, index)
        hash = hash.delete(:temp)
      end

      expect(hash.size).to eq(3)
      expect(max_rank(hash)).to be < 40
      expect(hash.to_a).to eq([[:b, 2], [:c, 3], [:a, 49]])
    end
  end

  describe "equality" do
    it "compares independently allocated empty hashes" do
      expect(described_class.allocate.tap { |hash| hash.send(:initialize) }.eql?(described_class.empty)).to be(true)
    end

    it "is eql? only when insertion order is the same" do
      one = described_class[a: 1, b: 2]
      other_order = described_class[b: 2, a: 1]

      expect(one.eql?(described_class[a: 1, b: 2])).to be(true)
      expect(one.eql?(other_order)).to be(false)
      expect(one == other_order).to be(true)
      expect(one.hash).not_to eq(other_order.hash)
    end
  end

  describe "marshalling" do
    it "preserves order and values" do
      hash = described_class[c: 3, a: 1, b: 2]
      reloaded = Marshal.load(Marshal.dump(hash))

      expect(reloaded).to eql(hash)
      expect(reloaded.to_a).to eq(hash.to_a)
      expect(reloaded).to be_immutable
    end
  end
end
