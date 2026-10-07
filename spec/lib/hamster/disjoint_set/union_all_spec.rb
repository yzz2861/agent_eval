require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe "#union_all" do
    it "unions each pair in order" do
      ds = DS.empty.union_all([[:a, :b], [:c, :d], [:b, :c]])
      expect(ds.connected?(:a, :d)).to be(true)
      expect(ds.partition_count).to eq(1)
      expect(ds.partition_size(:a)).to eq(4)
    end

    it "accepts any enumerable of 2-element collections" do
      ds = DS.empty.union_all(Hamster::Vector[Hamster::Vector[:a, :b], Hamster::Vector[:b, :c]])
      expect(ds.connected?(:a, :c)).to be(true)
    end

    it "returns self when every pair is already connected" do
      ds = DS[:a, :b].union(:a, :b)
      expect(ds.union_all([[:a, :b]])).to equal(ds)
    end

    it "returns self for an empty list of pairs" do
      ds = DS[:a]
      expect(ds.union_all([])).to equal(ds)
    end

    it "raises ArgumentError for malformed pairs" do
      expect { DS.empty.union_all([[:a]]) }.to raise_error(ArgumentError)
      expect { DS.empty.union_all([[:a, :b, :c]]) }.to raise_error(ArgumentError)
      expect { DS.empty.union_all([[:a, :b], nil]) }.to raise_error(ArgumentError)
    end

    it "does not expose a partially merged result when a pair is invalid" do
      ds = DS[:a, :b, :c]
      expect {
        ds.union_all([[:a, :b], [:x], [:b, :c]])
      }.to raise_error(ArgumentError)
      expect(ds.partition_count).to eq(3)
      expect(ds.connected?(:a, :b)).to be(false)
      expect(ds.connected?(:b, :c)).to be(false)
    end
  end
end
