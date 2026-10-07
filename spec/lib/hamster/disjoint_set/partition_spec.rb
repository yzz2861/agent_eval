require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  let(:ds) { DS.empty.union_all([[:a, :b], [:b, :c], [:d, :e]]).add(:f) }

  describe "#partition_size" do
    it "returns the size of the partition containing the element" do
      expect(ds.partition_size(:a)).to eq(3)
      expect(ds.partition_size(:b)).to eq(3)
      expect(ds.partition_size(:d)).to eq(2)
      expect(ds.partition_size(:f)).to eq(1)
    end

    it "returns 0 for elements which are not members" do
      expect(ds.partition_size(:zzz)).to eq(0)
      expect(DS.empty.partition_size(:a)).to eq(0)
    end
  end

  describe "#partition_count" do
    it "returns the number of disjoint partitions" do
      expect(ds.partition_count).to eq(3)
      expect(DS.empty.partition_count).to eq(0)
    end
  end

  describe "#partition" do
    it "returns the members of the partition containing the element" do
      expect(ds.partition(:a)).to eql(S[:a, :b, :c])
      expect(ds.partition(:c)).to eql(S[:a, :b, :c])
      expect(ds.partition(:d)).to eql(S[:d, :e])
      expect(ds.partition(:f)).to eql(S[:f])
    end

    it "returns an empty Set for elements which are not members" do
      expect(ds.partition(:zzz)).to eql(S.empty)
    end
  end

  describe "#partitions" do
    it "returns one Set per partition" do
      expect(ds.partitions.to_set).to eql(S[S[:a, :b, :c], S[:d, :e], S[:f]])
    end

    it "returns an empty Vector for an empty set" do
      expect(DS.empty.partitions).to eql(V.empty)
    end
  end
end
