require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  let(:ds) { DS.empty.union_all([[:a, :b], [:c, :d]]) }

  describe "#each" do
    it "yields every element exactly once" do
      yielded = []
      result = ds.each { |item| yielded << item }
      expect(yielded.sort).to eq([:a, :b, :c, :d])
      expect(result).to equal(ds)
    end

    it "returns an Enumerator when no block is given" do
      expect(ds.each.to_a.sort).to eq([:a, :b, :c, :d])
    end
  end

  describe "Enumerable" do
    it "supports map, select, and friends" do
      expect(ds.map { |x| x.to_s }.sort).to eq(%w[a b c d])
      expect(ds.select { |x| x == :a }).to eq([:a])
      expect(DS.new([1, 2, 3]).reduce(:+)).to eq(6)
    end
  end

  describe "#to_a" do
    it "returns an Array of all elements" do
      expect(ds.to_a.sort).to eq([:a, :b, :c, :d])
    end
  end

  describe "#to_set" do
    it "returns a Hamster::Set of all elements" do
      expect(ds.to_set).to eql(S[:a, :b, :c, :d])
    end
  end
end
