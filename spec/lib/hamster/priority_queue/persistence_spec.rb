require "spec_helper"
require "hamster/priority_queue"

describe Hamster::PriorityQueue do
  describe "persistence" do
    it "never modifies earlier versions" do
      v0 = PQ.new
      v1, handle = v0.push(2, :b)
      v2, _ = v1.push(1, :a)
      v3 = v2.adjust(handle, 0)
      v4, _ = v3.pop
      v5 = v4.merge(v2) # v4 and v2 share element :a; it appears once

      expect(v0.to_a).to eq([])
      expect(v1.to_a).to eq([[2, :b]])
      expect(v2.to_a).to eq([[1, :a], [2, :b]])
      expect(v3.to_a).to eq([[0, :b], [1, :a]])
      expect(v4.to_a).to eq([[1, :a]])
      expect(v5.to_a).to eq([[1, :a], [2, :b]])
    end

    it "shares structure safely between a merged queue and its inputs" do
      qa = PQ.new
      qb = PQ.new
      100.times { |i| qa, _ = qa.push(i, i) }
      100.times { |i| qb, _ = qb.push(i * 2, i) }
      merged = qa.merge(qb)
      50.times { merged, _ = merged.pop }
      expect(qa.size).to eq(100)
      expect(qb.size).to eq(100)
      expect(qa.to_a).to eq((0...100).map { |i| [i, i] })
      expect(merged.size).to eq(150)
    end

    it "stays correct through many forks, merges, and adjustments" do
      srand(20261006)
      base = PQ.new
      handles = []
      200.times { |i| base, h = base.push(rand(100), i); handles << h }
      left = base
      right = base
      100.times do |i|
        left, = left.push(rand(100), "L#{i}")
        left = left.adjust(handles[i], rand(50))
      end
      80.times do |i|
        right, = right.pop
        right, = right.push(rand(100), "R#{i}")
      end
      merged = left.merge(right)

      left_list = left.to_a
      right_list = right.to_a
      left_values = left_list.map(&:last)
      model = left_list + right_list.reject { |_, v| left_values.include?(v) }
      expected = model.each_with_index.sort { |x, y|
        (x[0][0] <=> y[0][0]).nonzero? || (x[1] <=> y[1])
      }.map(&:first)

      expect(merged.size).to eq(model.size)
      expect(merged.to_a).to eq(expected)
      expect(base.size).to eq(200)
    end
  end

  describe "comparator failure" do
    it "propagates comparator errors from #push and leaves the queue intact" do
      comparator = ->(a, b) { raise "boom" if a == 13 || b == 13; a <=> b }
      queue = PQ.new(comparator)
      queue, _ = queue.push(1, :a)
      queue, _ = queue.push(5, :b)
      expect { queue.push(13, :c) }.to raise_error("boom")
      expect(queue.to_a).to eq([[1, :a], [5, :b]])
    end

    it "propagates comparator errors from #pop and leaves the queue intact" do
      bombed = false
      comparator = ->(a, b) do
        if a == 9 && b == 7 && !bombed
          bombed = true
          raise "boom"
        end
        a <=> b
      end
      queue = PQ.new(comparator)
      [5, 7, 9].each { |i| queue, _ = queue.push(i, i) }
      expect { queue.pop }.to raise_error("boom")
      expect(queue.to_a).to eq([[5, 5], [7, 7], [9, 9]])
    end

    it "propagates comparator errors from #merge and leaves both queues intact" do
      comparator = ->(a, b) { raise "boom" if a == 1 && b == 2; a <=> b }
      qa, _ = PQ.new(comparator).push(1, :a)
      qb, _ = PQ.new(comparator).push(2, :b)
      expect { qa.merge(qb) }.to raise_error("boom")
      expect(qa.to_a).to eq([[1, :a]])
      expect(qb.to_a).to eq([[2, :b]])
    end

    it "propagates comparator errors from #adjust and leaves the queue intact" do
      comparator = ->(a, b) { raise "boom" if a == 50 || b == 50; a <=> b }
      queue = PQ.new(comparator)
      queue, handle = queue.push(1, :a)
      queue, _ = queue.push(99, :b)
      expect { queue.adjust(handle, 50) }.to raise_error("boom")
      expect(queue.to_a).to eq([[1, :a], [99, :b]])
    end

    it "raises ArgumentError when the comparator does not return a numeric" do
      queue, _ = PQ.new(->(a, b) { nil }).push(1, :a)
      expect { queue.push(2, :b) }.to raise_error(ArgumentError)
      expect(queue.to_a).to eq([[1, :a]])
    end
  end
end
