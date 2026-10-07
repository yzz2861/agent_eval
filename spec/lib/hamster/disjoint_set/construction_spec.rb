require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe ".new" do
    it "creates a singleton partition for each element" do
      ds = DS.new([:a, :b, :c])
      expect(ds.size).to eq(3)
      expect(ds.partition_count).to eq(3)
      [:a, :b, :c].each do |item|
        expect(ds.include?(item)).to be(true)
        expect(ds.partition_size(item)).to eq(1)
      end
    end

    it "ignores duplicate elements" do
      ds = DS.new([:a, :a, :b])
      expect(ds.size).to eq(2)
      expect(ds.partition_count).to eq(2)
    end

    it "accepts any enumerable" do
      expect(DS.new(1..3).size).to eq(3)
    end

    it "is empty when given no elements" do
      expect(DS.new.empty?).to be(true)
      expect(DS.new.size).to eq(0)
      expect(DS.new.partition_count).to eq(0)
    end
  end

  describe ".[]" do
    it "creates a set from the given elements" do
      ds = DS[:a, :b]
      expect(ds.size).to eq(2)
      expect(ds.include?(:a)).to be(true)
      expect(ds.include?(:b)).to be(true)
    end

    it "returns the canonical empty set when given no elements" do
      expect(DS[]).to equal(DS.empty)
    end
  end

  describe ".empty" do
    it "returns a memoized empty instance" do
      expect(DS.empty).to equal(DS.empty)
      expect(DS.empty).to be_empty
    end
  end

  describe "#clear" do
    it "returns an empty set of the same class" do
      ds = DS[:a, :b].union(:a, :b)
      expect(ds.clear).to equal(DS.empty)
      expect(ds.size).to eq(2)
    end
  end

  describe "#inspect" do
    it "shows the partitions" do
      ds = DS[:a].union(:b, :c)
      expect(ds.inspect).to match(/\AHamster::DisjointSet\[.*\]\z/)
      expect(ds.inspect).to include("[:a]")
      expect(ds.inspect.scan(/:b|:c/).size).to eq(2)
    end
  end
end
