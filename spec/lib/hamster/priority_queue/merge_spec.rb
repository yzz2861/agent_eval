require "spec_helper"
require "hamster/priority_queue"

describe Hamster::PriorityQueue do
  describe "#merge" do
    it "combines the elements of both queues" do
      qa = PQ.new
      qb = PQ.new
      [[3, :c], [1, :a]].each { |p, v| qa, _ = qa.push(p, v) }
      [[4, :d], [2, :b]].each { |p, v| qb, _ = qb.push(p, v) }
      expect(qa.merge(qb).to_a).to eq([[1, :a], [2, :b], [3, :c], [4, :d]])
    end

    it "orders equal priorities with the receiver's elements first" do
      qa = PQ.new
      qb = PQ.new
      qa, _ = qa.push(1, :from_a)
      qb, _ = qb.push(1, :from_b)
      expect(qa.merge(qb).to_a).to eq([[1, :from_a], [1, :from_b]])
      expect(qb.merge(qa).to_a).to eq([[1, :from_b], [1, :from_a]])
    end

    it "preserves insertion order within each side" do
      qa = PQ.new
      qb = PQ.new
      %w[a1 a2 a3].each { |v| qa, _ = qa.push(1, v) }
      %w[b1 b2].each { |v| qb, _ = qb.push(1, v) }
      expect(qa.merge(qb).to_a).to eq(
        [[1, "a1"], [1, "a2"], [1, "a3"], [1, "b1"], [1, "b2"]]
      )
    end

    it "returns self when merging an empty queue" do
      qa, _ = PQ.new.push(1, :a)
      expect(qa.merge(PQ.new)).to be(qa)
    end

    it "merges into an empty receiver" do
      qa = PQ.new
      qb = PQ.new
      qb, _ = qb.push(1, :low)
      qb, _ = qb.push(9, :high)
      merged = qa.merge(qb)
      expect(merged.size).to eq(2)
      expect(merged.to_a).to eq([[1, :low], [9, :high]])
    end

    it "uses the receiver's comparator for the merged queue" do
      qa = PQ.new { |a, b| b <=> a }
      qa, _ = qa.push(1, :low)
      qb = PQ.new { |a, b| b <=> a }
      qb, _ = qb.push(9, :high)
      expect(qa.merge(qb).to_a).to eq([[9, :high], [1, :low]])
    end

    it "does not modify either queue" do
      qa, _ = PQ.new.push(1, :a)
      qb, _ = PQ.new.push(2, :b)
      qa.merge(qb)
      expect(qa.to_a).to eq([[1, :a]])
      expect(qb.to_a).to eq([[2, :b]])
    end

    it "returns a frozen instance" do
      qa, _ = PQ.new.push(1, :a)
      qb, _ = PQ.new.push(2, :b)
      expect(qa.merge(qb)).to be_frozen
    end

    it "keeps handles from both sides valid" do
      qa, ha = PQ.new.push(1, :a)
      qb, hb = PQ.new.push(1, :b)
      merged = qa.merge(qb)
      expect(merged.adjust(ha, 5).to_a).to eq([[1, :b], [5, :a]])
      expect(merged.adjust(hb, 0).to_a).to eq([[0, :b], [1, :a]])
    end

    it "raises TypeError for a non-queue argument" do
      expect { PQ.new.merge([1, 2]) }.to raise_error(TypeError)
    end

    it "deduplicates elements shared through a common ancestor, receiver wins" do
      base, handle = PQ.new.push(5, :shared)
      left = base.adjust(handle, 1)
      right = base.adjust(handle, 9)
      merged = left.merge(right)
      expect(merged.size).to eq(1)
      expect(merged.to_a).to eq([[1, :shared]])
    end

    it "orders nested merges consistently" do
      qa = PQ.new
      qb = PQ.new
      qc = PQ.new
      qa, _ = qa.push(1, :a)
      qb, _ = qb.push(1, :b)
      qc, _ = qc.push(1, :c)
      expect(qa.merge(qb).merge(qc).to_a).to eq([[1, :a], [1, :b], [1, :c]])
      expect(qa.merge(qb.merge(qc)).to_a).to eq([[1, :a], [1, :b], [1, :c]])
    end

    context "fork, diverge, and merge" do
      it "merges two independently modified versions of one queue" do
        base = PQ.new
        base, handle_a = base.push(2, :a)
        base, handle_b = base.push(1, :b)

        left, _ = base.push(3, :left)
        left = left.adjust(handle_b, 5)

        right, handle_r = base.push(1, :right)
        right, popped = right.pop
        expect(popped).to eq([1, :b])

        merged = left.merge(right)
        expect(merged.to_a).to eq(
          [[1, :right], [2, :a], [3, :left], [5, :b]]
        )

        # the merged queue still accepts handles issued on either branch
        expect(merged.adjust(handle_r, 0).peek).to eq([0, :right])
        expect(merged.adjust(handle_a, 9).to_a.last).to eq([9, :a])

        # all earlier versions are untouched
        expect(base.to_a).to eq([[1, :b], [2, :a]])
        expect(left.to_a).to eq([[2, :a], [3, :left], [5, :b]])
        expect(right.to_a).to eq([[1, :right], [2, :a]])
      end
    end
  end
end
