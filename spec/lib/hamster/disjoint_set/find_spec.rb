require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  # Build a set whose internal tree has depth greater than 1, so that hidden
  # path compression would be observable. Yields a set of 0..7.
  def deep_disjoint_set
    ds = DS.empty
    8.times { |i| ds = ds.add(i) }
    ds = ds.union(0, 1).union(2, 3).union(4, 5).union(6, 7)
    ds.union(0, 2).union(4, 6).union(0, 4)
  end

  describe "#find" do
    it "returns the element itself for a singleton partition" do
      expect(DS[:a].find(:a)).to eq(:a)
    end

    it "returns the same representative for connected elements" do
      ds = DS[:a, :b, :c].union(:a, :b)
      expect(ds.find(:a)).to eq(ds.find(:b))
      expect(ds.find(:c)).to_not eq(ds.find(:a))
    end

    it "returns nil for elements which are not members" do
      expect(DS[:a].find(:zzz)).to be_nil
      expect(DS.empty.find(:a)).to be_nil
    end

    it "resolves representatives through deep trees" do
      ds = deep_disjoint_set
      root = ds.find(0)
      8.times { |i| expect(ds.find(i)).to eq(root) }
    end

    it "never modifies the internal structure (no hidden path compression)" do
      ds = deep_disjoint_set
      parents_before = ds.instance_variable_get(:@parents)
      sizes_before = ds.instance_variable_get(:@sizes)
      8.times { |i| ds.find(i) }
      8.times { |i| ds.connected?(0, i) }
      expect(ds.instance_variable_get(:@parents)).to equal(parents_before)
      expect(ds.instance_variable_get(:@sizes)).to equal(sizes_before)
    end

    it "leaves derived versions usable and unchanged after repeated finds" do
      ds = deep_disjoint_set
      snapshot = ds.partitions.map { |members| members.to_a.sort }.sort
      100.times { ds.find(7) }
      expect(ds.partitions.map { |members| members.to_a.sort }.sort).to eq(snapshot)
    end
  end
end
