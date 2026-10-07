require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe "#add" do
    it "returns a new set with the element added, leaving the original unchanged" do
      ds1 = DS[:a]
      ds2 = ds1.add(:b)
      expect(ds2.size).to eq(2)
      expect(ds2.include?(:b)).to be(true)
      expect(ds1.size).to eq(1)
      expect(ds1.include?(:b)).to be(false)
    end

    it "returns self when the element is already present" do
      ds = DS[:a]
      expect(ds.add(:a)).to equal(ds)
    end

    it "adds the element as a singleton partition" do
      ds = DS[:a].add(:b)
      expect(ds.connected?(:a, :b)).to be(false)
      expect(ds.partition_size(:b)).to eq(1)
      expect(ds.partition_count).to eq(2)
    end

    it "treats eql? but non-identical objects as the same element" do
      key1 = DeterministicHash.new("a", 1)
      key2 = DeterministicHash.new("a", 1)
      expect(key1).to_not equal(key2)
      ds = DS.empty.add(key1)
      expect(ds.include?(key2)).to be(true)
      expect(ds.add(key2)).to equal(ds)
      expect(ds.size).to eq(1)
    end

    it "distinguishes objects which are == but not eql?" do
      ds = DS.empty.add(EqualNotEql.new)
      expect(ds.include?(EqualNotEql.new)).to be(false)
      expect(ds.add(EqualNotEql.new).size).to eq(2)
    end

    it "is aliased as #<<" do
      expect(DS[:a] << :b).to eql(DS[:a, :b])
    end
  end
end
