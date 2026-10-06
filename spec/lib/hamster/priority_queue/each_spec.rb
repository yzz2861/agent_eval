require "spec_helper"
require "hamster/priority_queue"

describe Hamster::PriorityQueue do
  describe "#each" do
    let(:queue) do
      q = PQ.new
      [[3, :c], [1, :a], [2, :b], [1, :aa]].each { |p, v| q, _ = q.push(p, v) }
      q
    end

    it "yields [priority, value] pairs, smallest first, stable on ties" do
      seen = []
      queue.each { |priority, value| seen << [priority, value] }
      expect(seen).to eq([[1, :a], [1, :aa], [2, :b], [3, :c]])
    end

    it "returns an enumerator when no block is given" do
      expect(queue.each).to be_a(Enumerator)
      expect(queue.each.to_a).to eq([[1, :a], [1, :aa], [2, :b], [3, :c]])
    end

    it "does not modify the queue" do
      queue.each { |_| }
      expect(queue.size).to eq(4)
      expect(queue.to_a).to eq([[1, :a], [1, :aa], [2, :b], [3, :c]])
    end

    it "supports Enumerable helpers" do
      expect(queue.map { |_, v| v }).to eq([:a, :aa, :b, :c])
      expect(queue.select { |p, _| p > 1 }.map(&:last)).to eq([:b, :c])
    end
  end
end

