require "spec_helper"
require "hamster/priority_queue"

describe Hamster::PriorityQueue do
  describe "#push" do
    it "returns a new queue and a handle" do
      queue, handle = PQ.new.push(1, :a)
      expect(queue).to be_a(PQ)
      expect(handle).to be_a(PQ::Handle)
    end

    it "does not modify the receiver" do
      queue = PQ.new
      queue.push(1, :a)
      expect(queue).to be_empty
    end

    it "returns a frozen instance" do
      queue, _ = PQ.new.push(1, :a)
      expect(queue).to be_frozen
    end

    it "orders elements by priority" do
      queue = PQ.new
      [[3, :c], [1, :a], [2, :b]].each { |p, v| queue, _ = queue.push(p, v) }
      expect(queue.to_a).to eq([[1, :a], [2, :b], [3, :c]])
    end

    it "is stable: equal priorities come out in insertion order" do
      queue = PQ.new
      %w[first second third].each { |v| queue, _ = queue.push(1, v) }
      expect(queue.to_a).to eq([[1, "first"], [1, "second"], [1, "third"]])
    end

    it "raises ArgumentError when the comparator returns nil" do
      queue, _ = PQ.new.push(1, :a)
      expect { queue.push("incomparable", :b) }.to raise_error(ArgumentError)
    end
  end

  describe "#peek" do
    it "returns nil on an empty queue" do
      expect(PQ.new.peek).to be_nil
    end

    it "returns the smallest priority and its value" do
      queue = PQ.new
      [[3, :c], [1, :a], [2, :b]].each { |p, v| queue, _ = queue.push(p, v) }
      expect(queue.peek).to eq([1, :a])
    end

    it "does not remove anything" do
      queue, _ = PQ.new.push(1, :a)
      queue.peek
      expect(queue.size).to eq(1)
    end
  end

  describe "#pop" do
    it "returns [self, nil] on an empty queue" do
      queue = PQ.new
      new_queue, pair = queue.pop
      expect(new_queue).to be(queue)
      expect(pair).to be_nil
    end

    it "returns the smallest element and a queue without it" do
      queue = PQ.new
      [[3, :c], [1, :a], [2, :b]].each { |p, v| queue, _ = queue.push(p, v) }
      queue, pair = queue.pop
      expect(pair).to eq([1, :a])
      expect(queue.to_a).to eq([[2, :b], [3, :c]])
    end

    it "drains a large queue in stable sorted order" do
      queue = PQ.new
      pairs = (0...1000).map { |i| [(i * 37) % 100, i] }
      pairs.each { |p, v| queue, _ = queue.push(p, v) }
      expected = pairs.each_with_index.sort_by { |(p, _), i| [p, i] }.map(&:first)
      expect(queue.to_a).to eq(expected)
    end

    it "returns a frozen instance" do
      queue, _ = PQ.new.push(1, :a)
      new_queue, _ = queue.pop
      expect(new_queue).to be_frozen
    end
  end

  describe "#size and #empty?" do
    it "tracks the number of live elements" do
      queue = PQ.new
      expect(queue.size).to eq(0)
      queue, handle = queue.push(1, :a)
      queue, _ = queue.push(2, :b)
      expect(queue.size).to eq(2)
      queue = queue.adjust(handle, 0)
      expect(queue.size).to eq(2)
      queue, _ = queue.pop
      expect(queue.size).to eq(1)
      expect(queue).not_to be_empty
      queue, _ = queue.pop
      expect(queue).to be_empty
    end
  end

  describe "#clear" do
    it "returns an empty queue with the same comparator" do
      queue = PQ.new { |a, b| b <=> a }
      queue, _ = queue.push(1, :a)
      cleared = queue.clear
      expect(cleared).to be_empty
      cleared, _ = cleared.push(1, :low)
      cleared, _ = cleared.push(9, :high)
      expect(cleared.peek).to eq([9, :high])
    end
  end
end

