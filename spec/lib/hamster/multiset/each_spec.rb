require "spec_helper"

describe Hamster::Multiset do
  describe "#each" do
    it "yields each value once per occurrence" do
      yielded = []
      MS[:a, :a, :b].each { |item| yielded << item }
      expect(yielded.sort).to eq([:a, :a, :b])
    end

    it "returns self when given a block" do
      multiset = MS[:a]
      expect(multiset.each { |item| }).to equal(multiset)
    end

    it "returns an enumerator when given no block" do
      expect(MS[:a, :a].each).to be_an(Enumerator)
      expect(MS[:a, :a].each.to_a).to eq([:a, :a])
    end

    it "expands huge multiplicities lazily" do
      huge = MS.empty.add(:token, 1_000_000_000)
      expect(huge.each.first(3)).to eq([:token, :token, :token])
    end
  end

  describe "#each_pair" do
    it "yields each distinct value with its multiplicity, without expanding" do
      pairs = []
      MS[:a, :a, :b].each_pair { |item, count| pairs << [item, count] }
      expect(pairs.sort_by { |pair| pair[0].to_s }).to eq([[:a, 2], [:b, 1]])
    end

    it "returns an enumerator when given no block" do
      expect(MS[:a].each_pair.to_a).to eq([[:a, 1]])
    end

    it "does not expand huge multiplicities" do
      pairs = MS.empty.add(:token, 1_000_000_000).each_pair.to_a
      expect(pairs).to eq([[:token, 1_000_000_000]])
    end
  end

  describe "#to_a" do
    it "expands multiplicities into an array" do
      expect(MS[:a, :a, :b].to_a.sort).to eq([:a, :a, :b])
    end
  end

  describe "#to_hash" do
    it "returns a plain Ruby hash of counts" do
      hash = MS[:a, :a, :b].to_hash
      expect(hash).to be_a(::Hash)
      expect(hash).to eq(a: 2, b: 1)
    end

    it "returns an independent copy" do
      multiset = MS[:a]
      multiset.to_hash[:b] = 99
      expect(multiset.include?(:b)).to eq(false)
    end
  end

  describe "#to_set" do
    it "returns a Hamster::Set of the distinct values" do
      expect(MS[:a, :a, :b].to_set).to eq(S[:a, :b])
    end
  end

  describe "enumerable behavior" do
    it "treats occurrences as individual elements" do
      multiset = MS[:a, :a, :b]
      expect(multiset.map { |item| item.to_s }.sort).to eq(["a", "a", "b"])
      expect(multiset.select { |item| item == :a }).to eq([:a, :a])
    end
  end
end

