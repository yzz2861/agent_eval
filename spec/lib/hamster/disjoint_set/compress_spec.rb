require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe "#compress" do
    # Tree after these unions: 7 -> 6 -> 4 -> 0 (root)
    let(:ds) do
      set = DS.empty
      8.times { |i| set = set.add(i) }
      set = set.union(0, 1).union(2, 3).union(4, 5).union(6, 7)
      set.union(0, 2).union(4, 6).union(0, 4)
    end

    it "returns a new version with the search path flattened" do
      compressed = ds.compress(7)
      parents = compressed.instance_variable_get(:@parents)
      root = compressed.find(7)
      expect(parents.get(7)).to eq(root)
      expect(parents.get(6)).to eq(root)
    end

    it "leaves the receiver's internal structure untouched" do
      parents_before = ds.instance_variable_get(:@parents)
      ds.compress(7)
      expect(ds.instance_variable_get(:@parents)).to equal(parents_before)
      expect(parents_before.get(7)).to eq(6)
    end

    it "preserves the partitioning" do
      compressed = ds.compress(7)
      expect(compressed).to eql(ds)
      expect(compressed.partition_count).to eq(ds.partition_count)
      8.times { |i| expect(compressed.find(i)).to eq(ds.find(i)) }
    end

    it "returns self when the path is already fully compressed" do
      set = DS[:a, :b].union(:a, :b)
      expect(set.compress(:a)).to equal(set)
      expect(set.compress(:b)).to equal(set)
    end

    it "returns self for elements which are not members" do
      set = DS[:a]
      expect(set.compress(:zzz)).to equal(set)
    end
  end
end
