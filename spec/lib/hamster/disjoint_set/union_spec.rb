require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe "#union" do
    it "connects two elements" do
      ds = DS[:a, :b].union(:a, :b)
      expect(ds.connected?(:a, :b)).to be(true)
      expect(ds.partition_count).to eq(1)
      expect(ds.partition_size(:a)).to eq(2)
    end

    it "returns a new set and leaves the receiver unchanged" do
      ds1 = DS[:a, :b]
      ds2 = ds1.union(:a, :b)
      expect(ds1.connected?(:a, :b)).to be(false)
      expect(ds1.partition_count).to eq(2)
      expect(ds2.connected?(:a, :b)).to be(true)
    end

    it "returns self when the elements are already connected" do
      ds = DS[:a, :b, :c].union(:a, :b).union(:b, :c)
      expect(ds.union(:a, :c)).to equal(ds)
      expect(ds.union(:c, :b)).to equal(ds)
    end

    it "returns self when unioning an element with itself" do
      ds = DS[:a]
      expect(ds.union(:a, :a)).to equal(ds)
    end

    it "implicitly adds elements which are not yet members" do
      ds = DS.empty.union(:a, :b)
      expect(ds.size).to eq(2)
      expect(ds.connected?(:a, :b)).to be(true)

      ds2 = DS[:a].union(:a, :b)
      expect(ds2.size).to eq(2)
      expect(ds2.connected?(:a, :b)).to be(true)
    end

    it "merges transitively" do
      ds = DS.empty.union(:a, :b).union(:b, :c).union(:d, :e).union(:c, :d)
      expect(ds.connected?(:a, :e)).to be(true)
      expect(ds.partition_count).to eq(1)
      expect(ds.partition_size(:a)).to eq(5)
    end

    it "treats eql? but non-identical objects as the same element" do
      key1 = DeterministicHash.new("a", 1)
      key2 = DeterministicHash.new("a", 1)
      ds = DS.empty.add(key1).add(:b)
      expect(ds.union(key2, :b).connected?(key1, :b)).to be(true)
      ds2 = ds.union(key1, :b)
      expect(ds2.union(key2, :b)).to equal(ds2)
    end

    it "merges by size, keeping tree depth logarithmic" do
      ds = DS.empty
      16.times { |i| ds = ds.add(i) }
      [1, 2, 4, 8].each do |stride|
        (0...16).step(stride * 2) { |i| ds = ds.union(i, i + stride) }
      end
      expect(ds.partition_count).to eq(1)
      parents = ds.instance_variable_get(:@parents)
      16.times do |i|
        depth = 0
        node = i
        until parents.get(node).eql?(node)
          node = parents.get(node)
          depth += 1
        end
        expect(depth).to be <= 4 # log2(16)
      end
    end

    it "attaches the smaller partition below the larger one's root" do
      ds = DS.empty.union(:a, :b).union(:c, :d).union(:a, :c)
      ds = ds.union(:e, :f)
      ds = ds.union(:a, :e)
      root = ds.find(:a)
      expect(ds.partition_size(root)).to eq(6)
      expect(ds.find(:e)).to eq(root)
      expect(ds.find(:f)).to eq(root)
    end
  end
end
