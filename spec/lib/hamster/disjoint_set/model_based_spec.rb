require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  # A simple mutable union-find, used as a reference model.
  class ReferenceDisjointSet
    def initialize
      @parent = {}
      @size = {}
    end

    def add(item)
      unless @parent.key?(item)
        @parent[item] = item
        @size[item] = 1
      end
    end

    def find(item)
      root = item
      root = @parent[root] until @parent[root] == root
      root
    end

    def union(item, other)
      add(item)
      add(other)
      root_item, root_other = find(item), find(other)
      return if root_item == root_other
      @parent[root_other] = root_item
      @size[root_item] += @size[root_other]
    end

    def member?(item)
      @parent.key?(item)
    end

    def partition_size(item)
      @parent.key?(item) ? @size[find(item)] : 0
    end

    def partitions
      groups = Hash.new { |hash, key| hash[key] = [] }
      @parent.each_key { |item| groups[find(item)] << item }
      groups.values.map(&:sort).sort
    end
  end

  describe "model-based comparison with a mutable union-find" do
    it "matches the reference on random short operation sequences" do
      rng = Random.new(20261008)
      pool = (0...12).to_a

      30.times do
        ds = DS.empty
        ref = ReferenceDisjointSet.new
        versions = []

        60.times do
          case rng.rand(4)
          when 0
            item = pool.sample(random: rng)
            ds = ds.add(item)
            ref.add(item)
          when 1, 2
            item, other = pool.sample(2, random: rng)
            ds = ds.union(item, other)
            ref.union(item, other)
          when 3
            item = pool.sample(random: rng)
            ds = ds.compress(item)
          end

          expect(ds.partitions.map { |members| members.to_a.sort }.sort).to eq(ref.partitions)
          expect(ds.partition_count).to eq(ref.partitions.size)
          pool.each do |item|
            expect(ds.include?(item)).to eq(ref.member?(item))
            expect(ds.partition_size(item)).to eq(ref.partition_size(item))
          end
          versions << ds
        end

        # Later operations must not have corrupted any of the versions
        # captured along the way: structural sharing is read-only.
        versions.each do |version|
          expect(version.partition_count).to eq(version.partitions.size)
        end
      end
    end

    it "keeps every intermediate version intact after later operations" do
      rng = Random.new(42)
      pool = (0...10).to_a
      ds = DS.empty
      ref = ReferenceDisjointSet.new
      snapshots = []

      40.times do
        if rng.rand(2).zero?
          item = pool.sample(random: rng)
          ds = ds.add(item)
          ref.add(item)
        else
          item, other = pool.sample(2, random: rng)
          ds = ds.union(item, other)
          ref.union(item, other)
        end
        snapshots << [ds, ref.partitions]
      end

      snapshots.each do |version, expected|
        expect(version.partitions.map { |members| members.to_a.sort }.sort).to eq(expected)
      end
    end
  end
end
