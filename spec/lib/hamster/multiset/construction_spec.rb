require "spec_helper"

describe Hamster::Multiset do
  describe ".[]" do
    it "creates a multiset counting each occurrence" do
      multiset = MS[:a, :b, :a, :c, :a]
      expect(multiset.multiplicity(:a)).to eq(3)
      expect(multiset.multiplicity(:b)).to eq(1)
      expect(multiset.size).to eq(5)
    end

    it "returns an empty multiset when given no items" do
      expect(MS[]).to be_empty
    end
  end

  describe ".new" do
    it "accepts any enumerable of items" do
      expect(MS.new((1..4).to_a + [2, 2]).to_hash).to eq(1 => 1, 2 => 3, 3 => 1, 4 => 1)
    end

    it "returns an empty multiset by default" do
      expect(MS.new).to be_empty
    end
  end

  describe ".empty" do
    it "returns an empty, frozen multiset" do
      expect(MS.empty).to be_empty
      expect(MS.empty.frozen?).to eq(true)
    end

    it "memoizes the empty instance" do
      expect(MS.empty).to equal(MS.empty)
    end
  end

  describe ".from_counts" do
    it "builds a multiset from a Ruby hash of counts" do
      multiset = MS.from_counts(a: 2, b: 1)
      expect(multiset.to_hash).to eq(a: 2, b: 1)
      expect(multiset.size).to eq(3)
    end

    it "builds a multiset from a Hamster::Hash of counts" do
      multiset = MS.from_counts(H[a: 3])
      expect(multiset.multiplicity(:a)).to eq(3)
    end

    it "drops zero counts" do
      multiset = MS.from_counts(a: 0, b: 2)
      expect(multiset).not_to include(:a)
      expect(multiset.distinct_count).to eq(1)
    end

    it "rejects negative counts" do
      expect { MS.from_counts(a: -1) }.to raise_error(ArgumentError)
    end

    it "rejects non-integer counts" do
      expect { MS.from_counts(a: 1.5) }.to raise_error(ArgumentError)
      expect { MS.from_counts(a: "2") }.to raise_error(ArgumentError)
      expect { MS.from_counts(a: nil) }.to raise_error(ArgumentError)
    end
  end

  describe "#multiplicity" do
    it "returns 0 for absent values" do
      expect(MS[:a].multiplicity(:b)).to eq(0)
    end

    it "is aliased as #occurrences" do
      expect(MS[:a, :a].occurrences(:a)).to eq(2)
    end
  end

  describe "#include?" do
    it "is true only for values with positive multiplicity" do
      multiset = MS[:a, :a]
      expect(multiset.include?(:a)).to eq(true)
      expect(multiset.include?(:b)).to eq(false)
    end
  end

  describe "#empty?" do
    it "is true only when no values remain" do
      expect(MS.empty.empty?).to eq(true)
      expect(MS[:a].empty?).to eq(false)
    end
  end
end

