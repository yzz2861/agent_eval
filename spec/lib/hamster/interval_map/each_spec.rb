require "spec_helper"
require "hamster/interval_map"

describe Hamster::IntervalMap do
  let(:map) { Hamster::IntervalMap.new.put(0, 5, "a").put(10, 15, "b").put(20, 25, "c") }

  describe "#each" do
    context "with no range" do
      it "yields every fragment in order as [start, stop, value]" do
        yielded = []
        map.each { |fragment| yielded << fragment }
        expect(yielded).to eq([[0, 5, "a"], [10, 15, "b"], [20, 25, "c"]])
      end

      it "returns an Enumerator when no block is given" do
        expect(map.each).to be_instance_of(Enumerator)
        expect(map.each.to_a).to eq(map.to_a)
      end
    end

    context "with a range" do
      it "yields only fragments intersecting the range" do
        expect(map.each(3, 12).to_a).to eq([[0, 5, "a"], [10, 15, "b"]])
      end

      it "yields fragments whole, without clipping them to the range" do
        expect(map.each(3, 4).to_a).to eq([[0, 5, "a"]])
      end

      it "treats the range as left-closed and right-open" do
        expect(map.each(5, 10).to_a).to eq([])
        expect(map.each(4, 10).to_a).to eq([[0, 5, "a"]])
        expect(map.each(5, 11).to_a).to eq([[10, 15, "b"]])
      end

      it "yields nothing for an empty range" do
        expect(map.each(7, 7).to_a).to eq([])
      end

      it "raises ArgumentError on a reversed range" do
        expect { map.each(10, 5).to_a }.to raise_error(ArgumentError)
      end

      it "returns an Enumerator when no block is given" do
        expect(map.each(0, 30)).to be_instance_of(Enumerator)
      end
    end

    it "supports Enumerable methods over fragments" do
      expect(map.map { |start, stop, value| [value, stop - start] })
        .to eq([["a", 5], ["b", 5], ["c", 5]])
    end
  end
end
