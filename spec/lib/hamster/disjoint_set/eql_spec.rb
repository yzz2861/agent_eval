require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe "#eql?" do
    it "is true for the same partitions built in a different order" do
      ds1 = DS.empty.union_all([[:a, :b], [:c, :d], [:a, :c]])
      ds2 = DS.empty.union_all([[:c, :d], [:a, :b], [:b, :d]])
      expect(ds1).to eql(ds2)
      expect(ds1.hash).to eq(ds2.hash)
    end

    it "is true regardless of internal tree shape" do
      ds1 = DS.empty.union_all([[:a, :b], [:b, :c], [:c, :d]])
      ds2 = DS.empty.union_all([[:a, :b], [:c, :d], [:a, :c]]).compress(:d)
      expect(ds1).to eql(ds2)
      expect(ds1.hash).to eq(ds2.hash)
    end

    it "is true for two empty sets" do
      expect(DS.empty).to eql(DS.new)
    end

    it "is false when the partitioning differs" do
      expect(DS[:a, :b].union(:a, :b)).to_not eql(DS[:a, :b])
      expect(DS.empty.union_all([[:a, :b], [:c, :d]])).to_not eql(DS.empty.union_all([[:a, :c], [:b, :d]]))
    end

    it "is false when the elements differ" do
      expect(DS[:a]).to_not eql(DS[:a, :b])
      expect(DS[:a]).to_not eql(DS[:b])
    end

    it "is false for objects of other types" do
      expect(DS[:a]).to_not eql(S[:a])
      expect(DS[:a]).to_not eql(nil)
    end

    it "is aliased as #==" do
      expect(DS[:a, :b].union(:a, :b) == DS.empty.union(:a, :b)).to be(true)
    end
  end
end
