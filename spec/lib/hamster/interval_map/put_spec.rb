require "spec_helper"
require "hamster/interval_map"

describe Hamster::IntervalMap do
  describe "#put" do
    it "associates every point in [start, stop) with the value" do
      map = Hamster::IntervalMap.new.put(2, 5, "a")
      expect(map.get(1)).to be_nil
      expect(map.get(2)).to eq("a")
      expect(map.get(4)).to eq("a")
      expect(map.get(5)).to be_nil
    end

    it "treats the range as left-closed and right-open" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").put(10, 20, "b")
      expect(map.get(9)).to eq("a")
      expect(map.get(10)).to eq("b")
      expect(map.get(19)).to eq("b")
      expect(map.get(20)).to be_nil
    end

    it "splits an existing fragment which extends past both sides" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").put(3, 5, "b")
      expect(map.to_a).to eq([[0, 3, "a"], [3, 5, "b"], [5, 10, "a"]])
    end

    it "trims fragments which overlap either edge" do
      map = Hamster::IntervalMap.new.put(0, 5, "a").put(7, 12, "b").put(3, 9, "c")
      expect(map.to_a).to eq([[0, 3, "a"], [3, 9, "c"], [9, 12, "b"]])
    end

    it "merges adjacent fragments which carry equal values" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").put(10, 20, "a")
      expect(map.size).to eq(1)
      expect(map.to_a).to eq([[0, 20, "a"]])
    end

    it "merges with neighbours on both sides when filling a gap" do
      map = Hamster::IntervalMap.new.put(0, 5, "a").put(10, 15, "a").put(5, 10, "a")
      expect(map.to_a).to eq([[0, 15, "a"]])
    end

    it "does not merge adjacent fragments with different values" do
      map = Hamster::IntervalMap.new.put(0, 10, "a").put(10, 20, "b")
      expect(map.size).to eq(2)
    end

    it "does not bridge holes when merging" do
      map = Hamster::IntervalMap.new.put(0, 5, "a").put(10, 15, "a")
      expect(map.size).to eq(2)
      expect(map.get(7)).to be_nil
    end

    it "is a no-op on an empty range" do
      map = Hamster::IntervalMap.new.put(0, 10, "a")
      expect(map.put(4, 4, "b")).to be(map)
      expect(map.put(12, 12, "b")).to be(map)
    end

    it "raises ArgumentError on a reversed range" do
      map = Hamster::IntervalMap.new
      expect { map.put(10, 5, "a") }.to raise_error(ArgumentError)
    end

    it "returns self when the assignment changes nothing" do
      map = Hamster::IntervalMap.new.put(0, 10, "a")
      expect(map.put(0, 10, "a")).to be(map)
      expect(map.put(3, 7, "a")).to be(map)
    end

    it "preserves the original map" do
      original = Hamster::IntervalMap.new.put(0, 10, "a")
      derived  = original.put(3, 7, "b")
      expect(original.to_a).to eq([[0, 10, "a"]])
      expect(derived.to_a).to eq([[0, 3, "a"], [3, 7, "b"], [7, 10, "a"]])
    end

    context "with a custom 2-argument comparator" do
      it "orders endpoints using the comparator" do
        map = Hamster::IntervalMap.new { |a, b| a.length <=> b.length }
        map = map.put("a", "fffff", 1)
        expect(map.get("bb")).to eq(1)
        expect(map.get("fffff")).to be_nil
      end
    end

    context "with a 1-argument sort-key block" do
      it "orders endpoints by the derived key" do
        map = Hamster::IntervalMap.new { |point| point[0] }
        map = map.put([1, :x], [5, :y], "a")
        expect(map.get([3, :z])).to eq("a")
        expect(map.get([5, :x])).to be_nil
      end
    end
  end
end
