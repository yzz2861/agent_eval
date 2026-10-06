require "spec_helper"
require "hamster/interval_map"

describe Hamster::IntervalMap do
  describe "#get" do
    it "returns nil for every point of an empty map" do
      map = Hamster::IntervalMap.new
      expect(map.get(0)).to be_nil
      expect(map.get(-100)).to be_nil
    end

    it "returns the value of the fragment containing the point" do
      map = Hamster::IntervalMap.new.put(0, 5, "a").put(10, 15, "b").put(20, 25, "c")
      expect(map.get(0)).to eq("a")
      expect(map.get(12)).to eq("b")
      expect(map.get(24)).to eq("c")
    end

    it "returns nil for points in holes" do
      map = Hamster::IntervalMap.new.put(0, 5, "a").put(10, 15, "b")
      expect(map.get(-1)).to be_nil
      expect(map.get(7)).to be_nil
      expect(map.get(15)).to be_nil
    end

    it "is aliased as #[]" do
      map = Hamster::IntervalMap.new.put(0, 5, "a")
      expect(map[2]).to eq("a")
      expect(map[8]).to be_nil
    end

    it "distinguishes values which are false or nil" do
      map = Hamster::IntervalMap.new.put(0, 5, false)
      expect(map.get(2)).to eq(false)
      expect(map.get(9)).to be_nil
    end
  end
end
