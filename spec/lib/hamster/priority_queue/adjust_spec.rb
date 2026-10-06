require "spec_helper"
require "hamster/priority_queue"

describe Hamster::PriorityQueue do
  describe "#adjust" do
    let(:queue) do
      q = PQ.new
      @handles = {}
      [[5, :a], [3, :b], [8, :c]].each do |p, v|
        q, @handles[v] = q.push(p, v)
      end
      q
    end
    let(:handles) { @handles }

    it "moves an element to its new priority" do
      adjusted = queue.adjust(handles[:c], 1)
      expect(adjusted.peek).to eq([1, :c])
    end

    it "can both decrease and increase priority" do
      adjusted = queue.adjust(handles[:b], 10)
      expect(adjusted.to_a).to eq([[5, :a], [8, :c], [10, :b]])
    end

    it "does not modify the receiver" do
      queue.adjust(handles[:c], 1)
      expect(queue.peek).to eq([3, :b])
    end

    it "returns a frozen instance" do
      expect(queue.adjust(handles[:c], 1)).to be_frozen
    end

    it "keeps the handle valid for repeated adjustments" do
      adjusted = queue.adjust(handles[:c], 1)
      adjusted = adjusted.adjust(handles[:c], 20)
      expect(adjusted.to_a).to eq([[3, :b], [5, :a], [20, :c]])
    end

    it "accepts a handle issued by an ancestor version" do
      derived, _ = queue.push(0, :d)
      adjusted = derived.adjust(handles[:a], 0)
      expect(adjusted.to_a.first(2).map(&:last)).to include(:a)
      expect(adjusted.size).to eq(4)
    end

    it "treats the adjusted element as newly arrived among equal priorities" do
      q = PQ.new
      q, handle = q.push(1, :adjusted)
      q, _ = q.push(1, :later)
      q = q.adjust(handle, 1)
      expect(q.to_a).to eq([[1, :later], [1, :adjusted]])
    end

    it "raises KeyError for a stale handle whose element was popped" do
      q = PQ.new
      q, handle = q.push(1, :gone)
      q, _ = q.pop
      expect { q.adjust(handle, 5) }.to raise_error(KeyError)
    end

    it "raises KeyError for a handle belonging to an unrelated queue" do
      _, foreign = PQ.new.push(1, :elsewhere)
      expect { queue.adjust(foreign, 1) }.to raise_error(KeyError)
    end

    it "cannot hit a different element with a stale or foreign handle" do
      q = PQ.new
      q, handle = q.push(1, :gone)
      q, _ = q.pop
      q, _ = q.push(1, :new)
      expect { q.adjust(handle, 0) }.to raise_error(KeyError)
      expect(q.peek).to eq([1, :new])
    end

    it "raises TypeError for something that is not a handle" do
      expect { queue.adjust(:nope, 1) }.to raise_error(TypeError)
    end

    it "leaves the queue unchanged when it raises" do
      _, foreign = PQ.new.push(1, :elsewhere)
      begin
        queue.adjust(foreign, 1)
      rescue KeyError
      end
      expect(queue.to_a).to eq([[3, :b], [5, :a], [8, :c]])
    end
  end

  describe Hamster::PriorityQueue::Handle do
    it "is equal to itself and different from other handles" do
      q = PQ.new
      _, h1 = q.push(1, :a)
      _, h2 = q.push(1, :b)
      expect(h1).to eq(h1)
      expect(h1).not_to eq(h2)
      expect(h1).not_to eq(:something_else)
    end
  end
end

