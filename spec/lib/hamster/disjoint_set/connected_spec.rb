require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe "#connected?" do
    let(:ds) { DS[:a, :b, :c].union(:a, :b) }

    it "is true for elements in the same partition" do
      expect(ds.connected?(:a, :b)).to be(true)
      expect(ds.connected?(:b, :a)).to be(true)
    end

    it "is false for elements in different partitions" do
      expect(ds.connected?(:a, :c)).to be(false)
      expect(ds.connected?(:b, :c)).to be(false)
    end

    it "is true for an element and itself, when it is a member" do
      expect(ds.connected?(:a, :a)).to be(true)
    end

    it "is false when either element is not a member" do
      expect(ds.connected?(:a, :zzz)).to be(false)
      expect(ds.connected?(:zzz, :a)).to be(false)
      expect(ds.connected?(:yyy, :zzz)).to be(false)
    end

    it "does not modify the set" do
      before = ds.instance_variable_get(:@parents)
      ds.connected?(:a, :b)
      expect(ds.instance_variable_get(:@parents)).to equal(before)
    end
  end
end
