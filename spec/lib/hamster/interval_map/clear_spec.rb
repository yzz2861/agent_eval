require "spec_helper"
require "hamster/interval_map"

describe Hamster::IntervalMap do
  describe "#clear" do
    it "removes every point in [start, stop)" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").clear(3, 7)
      expect(map.get(2)).to eq("a")
      expect(map.get(3)).to be_nil
      expect(map.get(6)).to be_nil
      expect(map.get(7)).to eq("a")
    end

    it "splits a fragment which extends past both sides" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").clear(3, 7)
      expect(map.to_a).to eq([[0, 3, "a"], [7, 10, "a"]])
    end

    it "trims fragments which overlap either edge" do
      map = Hamster::IntervalMap.new.put(0, 5, "a").put(7, 12, "b").clear(3, 9)
      expect(map.to_a).to eq([[0, 3, "a"], [9, 12, "b"]])
    end

    it "drops fragments entirely inside the range" do
      map = Hamster::IntervalMap.new.put(0, 3, "a").put(5, 8, "b").put(10, 13, "c")
      expect(map.clear(4, 9).to_a).to eq([[0, 3, "a"], [10, 13, "c"]])
    end

    it "leaves a hole instead of merging the remaining neighbours" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").clear(4, 6)
      expect(map.size).to eq(2)
      expect(map.get(5)).to be_nil
    end

    it "returns an empty map when everything is cleared" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").clear(0, 10)
      expect(map).to be_empty
      expect(map.size).to eq(0)
    end

    it "is a no-op on an empty range" do
      map = Hamster::IntervalMap.new.put(0, 10, "a")
      expect(map.clear(4, 4)).to be(map)
    end

    it "is a no-op on a range which is already a hole" do
      map = Hamster::IntervalMap.new.put(0, 5, "a")
      expect(map.clear(10, 20)).to be(map)
    end

    it "raises ArgumentError on a reversed range" do
      map = Hamster::IntervalMap.new
      expect { map.clear(10, 5) }.to raise_error(ArgumentError)
    end

    it "preserves the original map" do
      original = Hamster::IntervalMap.new.put(0, 10, "a")
      derived  = original.clear(3, 7)
      expect(original.to_a).to eq([[0, 10, "a"]])
      expect(derived.to_a).to eq([[0, 3, "a"], [7, 10, "a"]])
    end
  end
end
