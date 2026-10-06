require "spec_helper"
require "hamster/priority_queue"

describe Hamster::PriorityQueue do
  it "creates entries from item/priority pairs" do
    queue = described_class[["a", 2], ["b", 1]]
    expect(queue.to_a).to eq(["b", "a"])
    expect(queue.pairs).to eq([["b", 1], ["a", 2]])
  end

  it "keeps equal priorities in original insertion order" do
    queue = described_class.empty
    queue, first = queue.insert(:first, 1)
    queue, second = queue.insert(:second, 1)
    queue, _third = queue.insert(:third, 2)

    expect(queue.to_a).to eq([:first, :second, :third])
    expect(queue.update_priority(first, 0).pairs).to eq([[:first, 0], [:second, 1], [:third, 2]])
  end

  it "returns a new queue from insertion, pop, and priority adjustment" do
    original = described_class.empty
    updated, handle = original.insert(:item, 2)
    adjusted = updated.update_priority(handle, 0)
    item, popped = adjusted.pop

    expect(item).to eq(:item)
    expect(original).to be_empty
    expect(updated.pairs).to eq([[:item, 2]])
    expect(adjusted.pairs).to eq([[:item, 0]])
    expect(popped).to be_empty
    expect(updated.frozen?).to be(true)
  end

  it "merges distinct queues in priority and original insertion order" do
    base = described_class.empty
    base, shared = base.insert(:shared, 2)
    left, left_only = base.insert(:left, 1)
    right, right_only = base.insert(:right, 1)

    expect(left.merge(right).to_a).to eq([:left, :right, :shared])
    expect(right.merge(left).to_a).to eq([:left, :right, :shared])

    item, popped = left.merge(right).pop
    expect(item).to eq(:left)
    expect(popped.to_a).to eq([:right, :shared])
  end

  it "merges two branches after independent priority changes" do
    base = described_class.empty
    base, first = base.insert(:first, 2)
    base, second = base.insert(:second, 3)
    base, third = base.insert(:third, 4)

    branch_a = base.update_priority(first, 5)
    branch_b = base.update_priority(second, 1)
    merged = branch_a.merge(branch_b)

    expect(merged.pairs).to eq([
      [:second, 1], [:third, 4], [:first, 5]
    ])
    expect(merged.priority_for(first)).to eq(5)
    expect(merged.priority_for(second)).to eq(1)
    expect(merged.priority_for(third)).to eq(4)
    expect(base.pairs).to eq([[:first, 2], [:second, 3], [:third, 4]])
    expect(branch_a.pairs).to eq([[:second, 3], [:third, 4], [:first, 5]])
    expect(branch_b.pairs).to eq([[:second, 1], [:first, 2], [:third, 4]])
  end

  it "keeps the receiver when both branches set the same handle to the same priority" do
    base = described_class.empty
    base, handle = base.insert("receiver", 1)

    branch_a = base.update_priority(handle, 0)
    branch_b = base.update_priority(handle, 0)
    merged = branch_a.merge(branch_b)

    expect(merged.size).to eq(1)
    expect(merged.pairs).to eq([["receiver", 0]])
  end

  it "rejects stale, foreign, and malformed handles without hitting a new entry" do
    queue = described_class.empty
    queue, handle = queue.insert(:old, 1)
    _, queue = queue.pop
    queue, replacement = queue.insert(:new, 1)
    other = described_class.empty
    _, other_handle = other.insert(:foreign, 1)

    expect(queue.handle?(handle)).to be(false)
    expect(queue.handle?(other_handle)).to be(false)
    expect { queue.update_priority(handle, 0) }.to raise_error(
      described_class::InvalidHandleError
    )
    expect { queue.update_priority(other_handle, 0) }.to raise_error(
      described_class::InvalidHandleError
    )
    expect { queue.update_priority(:not_a_handle, 0) }.to raise_error(
      described_class::InvalidHandleError
    )
    expect(queue.pairs).to eq([[:new, 1]])
    expect(replacement).to eql(queue.min_handle)
  end

  it "leaves the existing version usable when the comparator fails" do
    bad_comparison = lambda do |a, b|
      next a <=> b unless a == :boom || b == :boom
      raise ArgumentError, "bad priority"
    end
    queue = described_class.empty(&bad_comparison)
    queue, handle = queue.insert(:safe, 1)

    expect { queue.insert(:broken, :boom) }.to raise_error(ArgumentError, "bad priority")
    expect { queue.update_priority(handle, :boom) }.to raise_error(ArgumentError, "bad priority")
    expect(queue.pairs).to eq([[:safe, 1]])
    expect(queue.priority_for(handle)).to eq(1)
  end

  it "refuses to merge queues with different comparators" do
    queue = described_class.empty
    other = described_class.empty { |a, b| b <=> a }

    expect { queue.merge(other) }.to raise_error(ArgumentError)
  end

  it "maintains priority-queue behavior across repeated persistent operations" do
    states = {}
    queue = described_class.empty
    handles = {}

    1.upto(20) do |number|
      queue, handles[number] = queue.insert(number, number % 7)
      states[number] = queue
    end

    1.upto(10) do |number|
      queue = queue.update_priority(handles[number], 7 + number)
    end

    10.times { _, queue = queue.pop }

    expect(queue.to_a).to eq((1..10).to_a)
    expect(states[5].to_a).to eq([1, 2, 3, 4, 5])
    expect(states[20].size).to eq(20)
  end
end
