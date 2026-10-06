require "spec_helper"

describe Hamster::Multiset do
  describe "#eql? and #==" do
    it "is true for multisets with the same values and multiplicities" do
      expect(MS[:a, :a, :b]).to eq(MS[:b, :a, :a])
      expect(MS[:a, :a, :b].eql?(MS[:a, :a, :b])).to eq(true)
    end

    it "is false when multiplicities differ" do
      expect(MS[:a, :a]).not_to eq(MS[:a])
    end

    it "is false for other types" do
      expect(MS[:a]).not_to eq(S[:a])
      expect(MS[:a]).not_to eq({ a: 1 })
    end
  end

  describe "#hash" do
    it "matches for equal multisets" do
      expect(MS[:a, :a, :b].hash).to eq(MS[:b, :a, :a].hash)
    end
  end

  describe "#inspect" do
    it "shows values with their multiplicities" do
      expect(MS[:a, :a].inspect).to eq("Hamster::Multiset[:a => 2]")
    end

    it "does not expand huge multiplicities" do
      expect(MS.empty.add(:x, 1_000_000_000).inspect).to eq("Hamster::Multiset[:x => 1000000000]")
    end
  end

  describe "marshalling" do
    it "round-trips values and multiplicities" do
      multiset = MS[:a, :a, :b]
      expect(Marshal.load(Marshal.dump(multiset))).to eq(multiset)
    end
  end
end

