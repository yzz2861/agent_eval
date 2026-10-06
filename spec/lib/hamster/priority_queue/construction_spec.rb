require "spec_helper"
require "hamster/priority_queue"

describe Hamster::PriorityQueue do
  describe ".new" do
    it "returns an empty queue" do
      expect(PQ.new).to be_empty
      expect(PQ.new.size).to eq(0)
    end

    it "accepts a comparator callable" do
      queue = PQ.new(->(a, b) { b <=> a })
      queue, _ = queue.push(1, :low)
      queue, _ = queue.push(9, :high)
      expect(queue.peek).to eq([9, :high])
    end

    it "accepts a comparator block" do
      queue = PQ.new { |a, b| b <=> a }
      queue, _ = queue.push(1, :low)
      queue, _ = queue.push(9, :high)
      expect(queue.peek).to eq([9, :high])
    end

    it "raises ArgumentError for a non-callable comparator" do
      expect { PQ.new(42) }.to raise_error(ArgumentError)
    end

    it "returns a frozen instance" do
      expect(PQ.new).to be_frozen
    end
  end

  describe ".empty" do
    it "returns an empty queue" do
      expect(PQ.empty).to be_empty
    end

    it "uses the default comparator" do
      queue, _ = PQ.empty.push(2, :b)
      queue, _ = queue.push(1, :a)
      expect(queue.peek).to eq([1, :a])
    end
  end

  describe "#inspect" do
    it "shows the class name and size" do
      queue, _ = PQ.new.push(1, :a)
      queue, _ = queue.push(2, :b)
      expect(queue.inspect).to eq("Hamster::PriorityQueue[size=2]")
    end
  end
end

