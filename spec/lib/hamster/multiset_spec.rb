require "spec_helper"
require "hamster/multiset"

describe Hamster::Multiset do
  def counts_from(items)
    items.each_with_object(Hash.new(0)) { |item, counts| counts[item] += 1 }
  end

  let(:left_items) { [:a, :a, :b, :c, :c, :c] }
  let(:right_items) { [:a, :b, :b, :d] }
  let(:left) { described_class.new(left_items) }
  let(:right) { described_class.new(right_items) }
  let(:left_counts) { counts_from(left_items) }
  let(:right_counts) { counts_from(right_items) }

  it "records occurrences without changing the original collection" do
    expect(left.to_counts).to eq(a: 2, b: 1, c: 3)
    expect(left).to be_frozen

    added = left.add(:a, 2).add(:d)
    decremented = added.decrement(:c, 5)
    removed = decremented.delete(:b)

    expect(added.to_counts).to eq(a: 4, b: 1, c: 3, d: 1)
    expect(decremented.to_counts).to eq(a: 4, b: 1, d: 1)
    expect(removed.to_counts).to eq(a: 4, d: 1)
    expect(left.to_counts).to eq(a: 2, b: 1, c: 3)
  end

  it "distinguishes total size from the number of distinct values" do
    expect(left.size).to eq(6)
    expect(left.length).to eq(6)
    expect(left.distinct_size).to eq(3)
    expect(left.count).to eq(6)
    expect(left.count(:a)).to eq(2)
    expect(left.multiplicity(:missing)).to eq(0)
    expect(left.count { |item| item == :a }).to eq(2)
    expect(described_class.empty.size).to eq(0)
    expect(described_class.empty.distinct_size).to eq(0)
  end

  it "expands every occurrence only when explicitly iterated" do
    expect(left.each_distinct.to_a.sort).to eq([:a, :b, :c])
    expect(left.each_pair.to_a).to match_array(left_counts.to_a)
    expect(left.sort).to eq([:a, :a, :b, :c, :c, :c])

    huge = described_class.from_counts([[:large, 1_000_000_000]])
    expect(huge.size).to eq(1_000_000_000)
    expect(huge.distinct_size).to eq(1)
    expect(huge.each_distinct.to_a).to eq([:large])
    expect(huge.each.first(3)).to eq([:large, :large, :large])
    expect(huge.lazy.first).to eq(:large)
    expect(huge.add(:other).size).to eq(1_000_000_001)
    expect(huge.decrement(:large, 1_000_000_000).distinct_size).to eq(0)
  end

  it "removes keys when their count reaches zero and never emits negative counts" do
    zeroed = left.put(:b, 0)
    over_decremented = left.decrement(:b, 2)

    expect(zeroed).not_to include(:b)
    expect(over_decremented).not_to include(:b)
    expect(zeroed.to_counts).to eq(a: 2, c: 3)
    expect(over_decremented.to_counts).to eq(a: 2, c: 3)
    expect(described_class.from_counts([[:zero, 0]]).to_counts).to eq({})
    expect(described_class.new(zero: 0).to_counts).to eq({})
  end

  it "rejects negative and non-integer counts" do
    invalid_values = [-1, 1.5, Rational(1, 2), true, "1", nil]

    invalid_values.each do |invalid|
      expect { left.add(:a, invalid) }.to raise_error(ArgumentError)
      expect { left.decrement(:a, invalid) }.to raise_error(ArgumentError)
      expect { left.put(:a, invalid) }.to raise_error(ArgumentError)
      expect { described_class.from_counts([[:a, invalid]]) }.to raise_error(ArgumentError)
      expect { described_class.new(a: invalid) }.to raise_error(ArgumentError)
    end

    expect(left.to_counts).to eq(a: 2, b: 1, c: 3)
  end

  it "adds multiplicities" do
    expected = Hash.new(0)
    left_counts.each { |item, count| expected[item] += count }
    right_counts.each { |item, count| expected[item] += count }

    result = left + right

    expect(result.to_counts).to eq(expected)
    expect(result.size).to eq(expected.values.reduce(0, :+))
    expect(result.distinct_size).to eq(expected.size)
    expect(result).to eql(left.add_multiset(right))
    expect(result).to eql(left.merge(right))
  end

  it "takes the maximum multiplicity for union" do
    expected = {}
    left_counts.each do |item, count|
      expected[item] = [count, right_counts.fetch(item, 0)].max
    end
    right_counts.each do |item, count|
      expected[item] = [count, left_counts.fetch(item, 0)].max
    end

    expect((left | right).to_counts).to eq(expected)
    expect(left.union(right).to_counts).to eq(expected)
  end

  it "takes the minimum multiplicity for intersection" do
    expected = {}
    left_counts.each do |item, count|
      minimum = [count, right_counts.fetch(item, 0)].min
      expected[item] = minimum if minimum > 0
    end

    expect((left & right).to_counts).to eq(expected)
    expect(left.intersection(right).to_counts).to eq(expected)
  end

  it "truncates difference at zero" do
    expected = {}
    left_counts.each do |item, count|
      remaining = count - right_counts.fetch(item, 0)
      expected[item] = remaining if remaining > 0
    end

    result = left - right

    expect(result.to_counts).to eq(expected)
    expect(result.to_counts.values).to all(be > 0)
    expect(result).to eql(left.difference(right))
    expect(result).to eql(left.subtract(right))
    expect(result).to eql(left.truncated_difference(right))
  end

  it "matches ordinary count dictionaries through a sequence of versions" do
    reference = left_counts.dup
    multiset = left
    versions = [[left, left_counts.dup]]

    [
      [:add_d,        ->(counts) { increment(counts, :d, 4) }],
      [:decrement_a,  ->(counts) { decrement(counts, :a, 2) }],
      [:set_c,        ->(counts) { set_count(counts, :c, 1) }],
      [:remove_b,     ->(counts) { set_count(counts, :b, 0) }],
      [:add_right,    ->(counts) { add_counts(counts, right_counts) }],
      [:intersect_right, ->(counts) { min_counts(counts, right_counts) }],
      [:difference_right, ->(counts) { subtract_counts(counts, right_counts) }]
    ].each do |name, operation|
      operation.call(reference)
      multiset = multiset_for(name, multiset, right)
      versions << [multiset, reference.dup]
      expect(multiset.to_counts).to eq(reference)
      expect(multiset.size).to eq(reference.values.reduce(0, :+))
      expect(multiset.distinct_size).to eq(reference.size)
    end

    versions.each do |version, expected|
      expect(version.to_counts).to eq(expected)
    end
  end

  it "distinguishes unequal keys even when their hash codes collide" do
    first = DeterministicHash.new("first", 7)
    second = DeterministicHash.new("second", 7)
    third = DeterministicHash.new("third", 7)
    multiset = described_class.from_counts([[first, 2], [second, 3]])

    expect(multiset.distinct_size).to eq(2)
    expect(multiset.multiplicity(first)).to eq(2)
    expect(multiset.multiplicity(second)).to eq(3)
    expect(multiset.multiplicity(third)).to eq(0)
    expect((multiset + described_class.from_counts([[second, 2], [third, 4]])).to_counts).to eq(
      first => 2, second => 5, third => 4
    )
    expect((multiset - described_class.from_counts([[first, 5]])).to_counts).to eq(
      second => 3
    )
    expect(multiset.delete(first).to_counts).to eq(second => 3)
    expect(multiset.put(second, 0).to_counts).to eq(first => 2)
  end

  it "accepts expanded enumerable operands and Hash count maps" do
    expect((left + [:a, :d, :d]).to_counts).to eq(a: 3, b: 1, c: 3, d: 2)
    expect((left & [:a, :a, :b]).to_counts).to eq(a: 2, b: 1)
    expect((left - [:a, :a, :b, :missing]).to_counts).to eq(c: 3)
    expect(described_class.new(a: 2, b: 1).to_counts).to eq(a: 2, b: 1)
    expect(described_class[a: 2, b: 1].to_counts).to eq(a: 2, b: 1)
    expect(described_class[H[a: 2, b: 1]].to_counts).to eq(a: 2, b: 1)
  end

  it "supports equality, hashing, selection, mapping and marshalling" do
    copy = described_class.new(left_items)
    expect(left).to eql(copy)
    expect(left.hash).to eq(copy.hash)
    expect(left).not_to eql(right)

    expect(left.select { |item| item != :b }.to_counts).to eq(a: 2, c: 3)
    expect(left.map { |item| item == :a ? :x : :y }.to_counts).to eq(x: 2, y: 4)

    reloaded = Marshal.load(Marshal.dump(left))
    expect(reloaded).to eql(left)
    expect(reloaded).to be_frozen
  end

  def increment(counts, item, amount = 1)
    counts[item] += amount
  end

  def decrement(counts, item, amount)
    counts[item] -= amount
    counts.delete(item) if counts[item] <= 0
  end

  def set_count(counts, item, count)
    count.zero? ? counts.delete(item) : counts[item] = count
  end

  def add_counts(left, right)
    right.each { |item, count| left[item] += count }
  end

  def min_counts(left, right)
    left.keys.each do |item|
      minimum = [left.fetch(item, 0), right.fetch(item, 0)].min
      minimum.zero? ? left.delete(item) : left[item] = minimum
    end
  end

  def subtract_counts(left, right)
    left.keys.each do |item|
      remaining = left[item] - right.fetch(item, 0)
      remaining > 0 ? left[item] = remaining : left.delete(item)
    end
  end

  def multiset_for(name, multiset, right)
    case name
    when :add_d then multiset.add(:d, 4)
    when :decrement_a then multiset.decrement(:a, 2)
    when :set_c then multiset.put(:c, 1)
    when :remove_b then multiset.put(:b, 0)
    when :add_right then multiset + right
    when :intersect_right then multiset & right
    when :difference_right then multiset - right
    else multiset
    end
  end
end
