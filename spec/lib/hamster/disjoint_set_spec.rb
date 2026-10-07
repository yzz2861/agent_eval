require "spec_helper"

describe Hamster::DisjointSet do
  class EquivalentKey
    attr_reader :value

    def initialize(value)
      @value = value
    end

    def eql?(other)
      other.is_a?(EquivalentKey) && value.eql?(other.value)
    end

    def hash
      value.hash
    end
  end

  class DistinctKey
    def self.next_id
      @id = (@id || 0) + 1
    end

    def initialize
      @id = self.class.next_id
    end

    def eql?(other)
      other.is_a?(DistinctKey) && @id.eql?(other.instance_variable_get(:@id))
    end

    def hash
      @id
    end
  end

  class MutableDisjointSet
    def initialize(elements = [])
      @parents = {}
      @sizes = {}
      elements.each { |element| add(element) }
    end

    def add(element)
      return self if @parents.key?(element)
      @parents[element] = element
      @sizes[element] = 1
      self
    end

    def include?(element)
      @parents.key?(element)
    end

    def find(element)
      root = element
      root = @parents[root] until @parents[root].eql?(root)
      @parents[element] = root
      root
    end

    def connected?(first, second)
      find(first).eql?(find(second))
    end

    def union(first, second)
      first_root = find(first)
      second_root = find(second)
      return self if first_root.eql?(second_root)

      if @sizes[first_root] < @sizes[second_root]
        first_root, second_root = second_root, first_root
      end

      @parents[second_root] = first_root
      @sizes[first_root] += @sizes.delete(second_root)
      self
    end

    def partition_size(element)
      @sizes[find(element)]
    end

    def partitions
      groups = {}
      @parents.each_key do |element|
        (groups[find(element)] ||= []) << element
      end
      groups.values
    end

    def state
      partitions.map(&:sort).sort_by(&:first)
    end
  end

  def partitions_of(set)
    set.each_partition.map { |partition| partition.to_a.sort }.sort_by(&:first)
  end

  it "creates an empty set" do
    set = described_class.empty

    expect(set).to be_empty
    expect(set.size).to eq(0)
    expect(set.length).to eq(0)
    expect(set.partition_count).to eq(0)
    expect(set.to_a).to eq([])
    expect(set.partitions).to eql(Hamster::Set.empty)
  end

  it "accepts an enumerable of initial elements" do
    expect(described_class.new([1, 2, 2, 3]).size).to eq(3)
    expect(described_class[1, 2, 2, 3].size).to eq(3)
  end

  it "supports false and nil as elements" do
    set = described_class[nil, false, true].union(nil, false)

    expect(set.include?(nil)).to be(true)
    expect(set.include?(false)).to be(true)
    expect(set.connected?(nil, false)).to be(true)
    expect(set.partition_size(true)).to eq(1)
  end

  describe "#add" do
    it "returns a new set without changing the old one" do
      original = described_class[:a]
      updated = original.add(:b)

      expect(original.to_a).to eq([:a])
      expect(updated.to_a).to match_array([:a, :b])
      expect(updated).to be_frozen
    end

    it "returns the same instance when an equivalent element already exists" do
      original = described_class["root"]
      updated = original.add("root".dup)

      expect(updated).to equal(original)
    end

    it "supports <<" do
      expect(described_class.empty << :a).to include(:a)
    end

    it "shares unchanged persistent maps between versions" do
      original = described_class[1, 2, 3]
      updated = original.add(4)
      original_parents = original.instance_variable_get(:@parents)
      updated_parents = updated.instance_variable_get(:@parents)

      expect(updated_parents[1]).to equal(original_parents[1])
      expect(updated_parents[2]).to equal(original_parents[2])
      expect(updated_parents[3]).to equal(original_parents[3])
    end
  end

  describe "#find and #connected?" do
    it "uses Hamster's eql? and hash key semantics" do
      set = described_class["x", "y"]
      x = "x".dup

      expect(set.find(x)).to eq("x")
      expect(set.connected?(x, "x".dup)).to be(true)
      expect(set.connected?("x", "y")).to be(false)
    end

    it "does not treat eql?-distinct keys as equivalent" do
      first = DistinctKey.new
      second = DistinctKey.new
      set = described_class[first, second]

      expect(set.size).to eq(2)
      expect(set.connected?(first, second)).to be(false)
      expect(set.partition_count).to eq(2)
      joined = set.union(first, second)
      expect(joined.connected?(first, second)).to be(true)
      expect(joined.partition_size(first)).to eq(2)
    end

    it "treats different objects with matching eql? and hash as the same key" do
      set = described_class[EquivalentKey.new(:a), EquivalentKey.new(:b)]

      expect(set.add(EquivalentKey.new(:a))).to equal(set)
      expect(set.find(EquivalentKey.new(:a))).to eql(EquivalentKey.new(:a))
      expect { set.union(EquivalentKey.new(:a), EquivalentKey.new(:b)) }.not_to raise_error
    end

    it "does not perform path compression during a read-only find" do
      set = described_class[1, 2, 3, 4, 5, 6, 7, 8, 9]
      set = set.union(1, 2).union(3, 4).union(1, 3)
      set = set.union(5, 6).union(7, 8).union(5, 7)
      set = set.union(1, 5)
      parents_before_find = set.instance_variable_get(:@parents)

      expect(set.find(7)).to eq(1)
      expect(set.find(8)).to eq(1)

      parents_after_find = set.instance_variable_get(:@parents)
      expect(parents_after_find).to equal(parents_before_find)
      expect(parents_before_find[7]).to eq(5)
      expect(parents_before_find[5]).to eq(1)
    end

    it "raises KeyError for a missing element" do
      set = described_class[:a]

      expect { set.find(:missing) }.to raise_error(KeyError)
      expect { set.connected?(:a, :missing) }.to raise_error(KeyError)
      expect { set.partition_size(:missing) }.to raise_error(KeyError)
    end
  end

  describe "#union" do
    it "joins components and reports their representative and size" do
      set = described_class[:a, :b, :c].union(:a, :b)

      expect(set.find(:b)).to eq(set.find(:a))
      expect(set.connected?(:a, :b)).to be(true)
      expect(set.connected?(:a, :c)).to be(false)
      expect(set.partition_size(:b)).to eq(2)
      expect(set.partition_size(:c)).to eq(1)
      expect(set.partition_count).to eq(2)
      expect(partitions_of(set)).to eq([[:a, :b], [:c]])
    end

    it "returns the same instance when the elements are already connected" do
      set = described_class[:a, :b].union(:a, :b)

      expect(set.union(:b, :a)).to equal(set)
    end

    it "controls height by component size" do
      set = (1..128).reduce(described_class.empty) { |result, n| result.add(n) }
      set = (1...128).reduce(set) { |result, n| result.union(n, n + 1) }
      parents = set.instance_variable_get(:@parents)

      height = 0
      node = 128
      until parents[node].eql?(node)
        node = parents[node]
        height += 1
      end

      expect(height).to be <= Math.log2(128).ceil
      expect(set.partition_size(128)).to eq(128)
    end

    it "keeps tree height logarithmic and compresses only in a returned version" do
      set = described_class[1, 2, 3, 4, 5, 6, 7, 8, 9]
      set = set.union(1, 2).union(3, 4).union(1, 3)
      set = set.union(5, 6).union(7, 8).union(5, 7)
      set = set.union(1, 5)
      parents_before_union = set.instance_variable_get(:@parents)

      updated = set.union(7, 9)
      updated_parents = updated.instance_variable_get(:@parents)

      expect(parents_before_union[7]).to eq(5)
      expect(updated_parents[7]).to eq(1)
      expect(updated_parents[5]).to eq(1)
      expect(updated.find(9)).to eq(1)
      expect(updated.partition_size(9)).to eq(9)
      expect(set.partition_size(9)).to eq(1)
    end

    it "raises and leaves the receiver unchanged when an element is missing" do
      set = described_class[:a, :b]

      expect { set.union(:a, :missing) }.to raise_error(KeyError)
      expect(partitions_of(set)).to eq([[:a], [:b]])
    end
  end

  describe "#union_all" do
    it "joins an enumerable of pairs atomically" do
      set = described_class[:a, :b, :c, :d]
      joined = set.union_all([[:a, :b], [:b, :c]])

      expect(partitions_of(joined)).to eq([[:a, :b, :c], [:d]])
      expect(partitions_of(set)).to eq([[:a], [:b], [:c], [:d]])
    end

    it "accepts pairs yielded by a hash" do
      set = described_class[:a, :b, :c]
      joined = set.union_all(a: :b, b: :c)

      expect(joined.partition_count).to eq(1)
    end

    it "returns the same instance when every pair is a no-op" do
      set = described_class[:a, :b].union(:a, :b)

      expect(set.union_all([[:a, :b], [:b, :a]])).to equal(set)
    end

    it "does not expose a half-finished batch when a later pair fails" do
      set = described_class[:a, :b, :c]

      expect do
        set.union_all([[:a, :b], [:c, :missing], [:a, :c]])
      end.to raise_error(KeyError)
      expect(partitions_of(set)).to eq([[:a], [:b], [:c]])
    end

    it "rejects malformed pairs without changing the receiver" do
      set = described_class[:a, :b]

      expect { set.union_all([:bad]) }.to raise_error(ArgumentError)
      expect { set.union_all(nil) }.to raise_error(ArgumentError)
      expect(partitions_of(set)).to eq([[:a], [:b]])
    end

    it "accepts an enumerator and rejects pairs with the wrong size" do
      set = described_class[:a, :b, :c]
      pairs = [[:a, :b], [:b]].to_enum

      expect { set.union_all(pairs) }.to raise_error(ArgumentError)
      expect(partitions_of(set)).to eq([[:a], [:b], [:c]])
    end
  end

  describe "partitions and enumeration" do
    it "enumerates elements and frozen component sets" do
      set = described_class[:a, :b, :c].union(:a, :b)

      expect(set.to_a).to match_array([:a, :b, :c])
      expect(set.each_partition.to_a).to match_array([
        Hamster::Set[:a, :b],
        Hamster::Set[:c]
      ])
      set.each_partition do |partition|
        expect(partition).to be_a(Hamster::Set)
        expect(partition).to be_frozen
      end
      expect(set.each_component.to_a).to eq(set.each_partition.to_a)
      expect(set.components).to eql(set.partitions)
    end

    it "compares partitions rather than internal tree shape" do
      left = described_class[1, 2, 3].union(1, 2)
      right = described_class[1, 2, 3].union(2, 1)

      expect(left).to eql(right)
      expect(left.hash).to eq(right.hash)
    end

    it "survives marshalling" do
      set = described_class[:a, :b, :c].union(:a, :b)
      reloaded = Marshal.load(Marshal.dump(set))

      expect(reloaded).to eql(set)
      expect(reloaded.partition_size(:b)).to eq(2)
    end
  end

  describe "randomized equivalence with a mutable union-find" do
    it "matches add, union, find, connected?, size and partition queries" do
      srand(20261008)

      50.times do
        elements = (0...10).map { |value| "element-#{value}" }
        persistent = described_class.empty
        mutable = MutableDisjointSet.new

        80.times do
          first = elements.sample
          second = elements.sample

          case rand(5)
          when 0
            persistent = persistent.add(first)
            mutable.add(first)
          when 1
            if mutable.include?(first) && mutable.include?(second)
              persistent = persistent.union(first, second)
              mutable.union(first, second)
            else
              expect { persistent.union(first, second) }.to raise_error(KeyError)
            end
          when 2
            if mutable.include?(first)
              expect(persistent.find(first)).to eq(mutable.find(first))
            else
              expect { persistent.find(first) }.to raise_error(KeyError)
            end
          when 3
            if mutable.include?(first) && mutable.include?(second)
              expect(persistent.connected?(first, second)).to eq(
                mutable.connected?(first, second)
            )
            else
              expect { persistent.connected?(first, second) }.to raise_error(KeyError)
            end
          else
            next unless mutable.include?(first)
            expect(persistent.partition_size(first)).to eq(mutable.partition_size(first))
          end

          expect(persistent.size).to eq(mutable.instance_variable_get(:@parents).size)
          expect(persistent.partition_count).to eq(mutable.partitions.size)
          expect(persistent.to_a).to match_array(
            mutable.instance_variable_get(:@parents).keys
          )
          expect(partitions_of(persistent)).to eq(mutable.state)
        end
      end
    end
  end

  describe "branching" do
    it "keeps each version's partitions independent while sharing persistent history" do
      base = described_class[1, 2, 3, 4, 5, 6, 7, 8]
      base = base.union_all([[1, 2], [3, 4], [5, 6], [7, 8]])
      snapshot = base

      left = base.union(2, 3).union(4, 5)
      right = base.union(6, 7).union(7, 8)
      left_again = left.union(6, 7)

      expect(partitions_of(base)).to eq([[1, 2], [3, 4], [5, 6], [7, 8]])
      expect(partitions_of(snapshot)).to eq([[1, 2], [3, 4], [5, 6], [7, 8]])
      expect(partitions_of(left)).to eq([[1, 2, 3, 4, 5, 6], [7, 8]])
      expect(partitions_of(right)).to eq([[1, 2], [3, 4], [5, 6, 7, 8]])
      expect(partitions_of(left_again)).to eq([[1, 2, 3, 4, 5, 6, 7, 8]])

      expect(base.connected?(1, 5)).to be(false)
      expect(left.connected?(1, 5)).to be(true)
      expect(right.connected?(5, 8)).to be(true)
      expect(right.connected?(1, 8)).to be(false)
    end

    it "does not let path compression in one branch alter another branch" do
      base = described_class[1, 2, 3, 4, 5, 6, 7, 8]
      base = base.union(1, 2).union(3, 4).union(1, 3)
      base = base.union(5, 6).union(7, 8).union(5, 7)
      base = base.union(1, 5)

      compressed_branch = base.add(9).union(7, 9)
      other_branch = base.add(10).union(6, 10)

      expect(base.instance_variable_get(:@parents)[7]).to eq(5)
      expect(compressed_branch.instance_variable_get(:@parents)[7]).to eq(1)
      expect(other_branch.instance_variable_get(:@parents)[7]).to eq(5)
      expect(compressed_branch.partition_size(9)).to eq(9)
      expect(other_branch.partition_size(10)).to eq(9)
      expect(base.size).to eq(8)
    end
  end
end
