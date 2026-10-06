require "spec_helper"

# Cross-checks Hamster::Multiset against an independent reference model built
# on a plain Ruby Hash of value => count, plus persistence (structural
# sharing) and hash-collision behavior.
describe Hamster::Multiset do
  # Reference model: every operation is reimplemented here using only a plain
  # Ruby Hash, so a bug in the Multiset implementation cannot be mirrored by
  # the oracle.
  class MultisetOracle
    attr_reader :counts

    def initialize(counts = {})
      @counts = counts.reject { |_, count| count.zero? }
    end

    def add(item, n)
      self.class.new(counts.merge(item => count_of(item) + n))
    end

    def remove(item, n)
      self.class.new(counts.merge(item => [count_of(item) - n, 0].max))
    end

    def sum(other)
      merge_with(other) { |a, b| a + b }
    end

    def union(other)
      merge_with(other) { |a, b| [a, b].max }
    end

    def intersection(other)
      kept = {}
      counts.each do |item, count|
        shared = [count, other.count_of(item)].min
        kept[item] = shared if shared > 0
      end
      self.class.new(kept)
    end

    def difference(other)
      merge_with(other) { |a, b| [a - b, 0].max }
    end

    def count_of(item)
      counts.fetch(item, 0)
    end

    private

    def merge_with(other)
      merged = counts.dup
      other.counts.each do |item, count|
        merged[item] = yield(count_of(item), count)
      end
      self.class.new(merged)
    end
  end

  def expect_matches_oracle(multiset, oracle)
    expect(multiset.to_hash).to eq(oracle.counts)
    expect(multiset.size).to eq(oracle.counts.values.sum)
    expect(multiset.distinct_count).to eq(oracle.counts.size)
    oracle.counts.each do |item, count|
      expect(multiset.multiplicity(item)).to eq(count)
    end
  end

  describe "against a plain count-hash oracle" do
    it "matches after a long random sequence of operations" do
      rng = Random.new(20261006)
      keys = (:a..:h).to_a
      multiset = MS.empty
      oracle = MultisetOracle.new

      500.times do
        key = keys[rng.rand(keys.size)]
        case rng.rand(6)
        when 0
          n = rng.rand(1..6)
          multiset = multiset.add(key, n)
          oracle = oracle.add(key, n)
        when 1
          n = rng.rand(1..8)
          multiset = multiset.remove(key, n)
          oracle = oracle.remove(key, n)
        when 2
          other_ms = MS.new(Array.new(rng.rand(0..5)) { keys[rng.rand(keys.size)] })
          other_oracle = MultisetOracle.new(other_ms.to_hash)
          multiset = multiset + other_ms
          oracle = oracle.sum(other_oracle)
        when 3
          other_ms = MS.new(Array.new(rng.rand(0..5)) { keys[rng.rand(keys.size)] })
          other_oracle = MultisetOracle.new(other_ms.to_hash)
          multiset = multiset | other_ms
          oracle = oracle.union(other_oracle)
        when 4
          other_ms = MS.new(Array.new(rng.rand(0..5)) { keys[rng.rand(keys.size)] })
          other_oracle = MultisetOracle.new(other_ms.to_hash)
          multiset = multiset & other_ms
          oracle = oracle.intersection(other_oracle)
        when 5
          other_ms = MS.new(Array.new(rng.rand(0..5)) { keys[rng.rand(keys.size)] })
          other_oracle = MultisetOracle.new(other_ms.to_hash)
          multiset = multiset - other_ms
          oracle = oracle.difference(other_oracle)
        end

        expect_matches_oracle(multiset, oracle)
      end
    end

    it "never stores zero or negative counts internally" do
      multiset = MS[:a, :a, :b].remove(:a, 2).remove(:b, 99)
      expect(multiset.to_hash).to eq({})
      expect(multiset.each_pair.to_a).to eq([])
      expect(multiset.empty?).to eq(true)
    end
  end

  describe "with colliding hash keys" do
    let(:collision_a) { DeterministicHash.new("a", 1) }
    let(:collision_b) { DeterministicHash.new("b", 1) }
    let(:collision_c) { DeterministicHash.new("c", 1) }

    it "keeps colliding keys independent" do
      multiset = MS.empty.add(collision_a, 2).add(collision_b, 3).add(collision_c, 1)
      expect(multiset.multiplicity(collision_a)).to eq(2)
      expect(multiset.multiplicity(collision_b)).to eq(3)
      expect(multiset.multiplicity(collision_c)).to eq(1)
      expect(multiset.distinct_count).to eq(3)
      expect(multiset.size).to eq(6)
    end

    it "removes only the targeted colliding key" do
      multiset = MS.empty.add(collision_a, 2).add(collision_b, 3)
      result = multiset.remove(collision_a, 2)
      expect(result).not_to include(collision_a)
      expect(result.multiplicity(collision_b)).to eq(3)
      expect(result.to_hash).to eq(collision_b => 3)
    end

    it "performs bulk operations correctly across collisions" do
      left = MS.empty.add(collision_a, 5).add(collision_b, 1)
      right = MS.empty.add(collision_a, 2).add(collision_c, 4)
      expect((left & right).to_hash).to eq(collision_a => 2)
      expect((left | right).to_hash).to eq(collision_a => 5, collision_b => 1, collision_c => 4)
      expect((left - right).to_hash).to eq(collision_a => 3, collision_b => 1)
      expect((left + right).to_hash).to eq(collision_a => 7, collision_b => 1, collision_c => 4)
    end
  end

  describe "structural sharing between versions" do
    it "keeps every derived version intact" do
      versions = []
      oracles = []
      multiset = MS.empty
      oracle = MultisetOracle.new

      [[:a, 3], [:b, 2], [:a, 1], [:c, 5], [:b, 1]].each do |key, n|
        multiset = multiset.add(key, n)
        oracle = oracle.add(key, n)
        versions << multiset
        oracles << oracle
      end

      removal = multiset.remove(:a, 2)
      removal_oracle = oracle.remove(:a, 2)
      versions << removal
      oracles << removal_oracle

      difference = multiset - MS[:a, :c, :c]
      difference_oracle = oracle.difference(MultisetOracle.new(a: 1, c: 2))
      versions << difference
      oracles << difference_oracle

      versions.zip(oracles).each do |version, expected|
        expect_matches_oracle(version, expected)
      end
    end

    it "does not let operations on one version affect another" do
      base = MS[:a, :a, :b]
      grown = base.add(:a, 10)
      shrunk = base.remove(:b)
      merged = base + MS[:c, :c]

      expect(base.to_hash).to eq(a: 2, b: 1)
      expect(grown.to_hash).to eq(a: 12, b: 1)
      expect(shrunk.to_hash).to eq(a: 2)
      expect(merged.to_hash).to eq(a: 2, b: 1, c: 2)
    end
  end
end
