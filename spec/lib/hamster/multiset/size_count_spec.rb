require "spec_helper"

describe Hamster::Multiset do
  let(:multiset) { MS.new([:a, :a, :a, :b, :b, :c]) }

  describe "#size" do
    it "counts every occurrence, not just distinct values" do
      expect(multiset.size).to eq(6)
    end

    it "is aliased as #length and #total_count" do
      expect(multiset.length).to eq(6)
      expect(multiset.total_count).to eq(6)
    end

    it "stays accurate across additions and removals" do
      derived = multiset.add(:d, 4).remove(:a, 2)
      expect(derived.size).to eq(8)
    end
  end

  describe "#distinct_count" do
    it "counts each value once, ignoring multiplicity" do
      expect(multiset.distinct_count).to eq(3)
    end

    it "shrinks when a value is fully removed" do
      expect(multiset.delete(:a).distinct_count).to eq(2)
    end
  end

  describe "#count" do
    it "returns the total number of occurrences without an argument" do
      expect(multiset.count).to eq(6)
    end

    it "returns the multiplicity of the given value" do
      expect(multiset.count(:a)).to eq(3)
      expect(multiset.count(:missing)).to eq(0)
    end

    it "counts matching occurrences when given a block" do
      expect(multiset.count { |item| item == :b }).to eq(2)
    end
  end

  describe "size metrics with huge multiplicities" do
    let(:huge) { MS.empty.add(:token, 1_000_000_000) }

    it "reports the total without allocating per-occurrence storage" do
      expect(huge.size).to eq(1_000_000_000)
      expect(huge.distinct_count).to eq(1)
      expect(huge.multiplicity(:token)).to eq(1_000_000_000)
    end

    it "tracks totals through bulk operations" do
      combined = huge + huge
      expect(combined.size).to eq(2_000_000_000)
      expect(combined.distinct_count).to eq(1)
      expect((combined - huge).size).to eq(1_000_000_000)
      expect((huge | MS[:token]).size).to eq(1_000_000_000)
      expect((huge & MS[:token]).size).to eq(1)
    end
  end
end

