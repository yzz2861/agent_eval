require "spec_helper"
require "hamster/disjoint_set"

describe Hamster::DisjointSet do
  describe "persistence across branched versions" do
    it "keeps independent branches isolated from each other" do
      base    = DS.new([:a, :b, :c, :d, :e, :f])
      branch1 = base.union(:a, :b).union(:b, :c)
      branch2 = base.union(:d, :e)
      branch3 = branch1.union(:c, :d)

      expect(base.partition_count).to eq(6)
      expect(base.connected?(:a, :b)).to be(false)

      expect(branch1.connected?(:a, :c)).to be(true)
      expect(branch1.connected?(:a, :d)).to be(false)
      expect(branch1.partition_count).to eq(4)

      expect(branch2.connected?(:d, :e)).to be(true)
      expect(branch2.connected?(:a, :b)).to be(false)
      expect(branch2.partition_count).to eq(5)

      expect(branch3.connected?(:a, :d)).to be(true)
      expect(branch3.connected?(:d, :e)).to be(false)
      expect(branch3.connected?(:e, :f)).to be(false)
      expect(branch3.partition_count).to eq(3)
    end

    it "lets later versions share structure without corrupting earlier ones" do
      versions = []
      ds = DS.empty
      100.times do |i|
        ds = ds.add(i)
        versions << ds
      end
      merged = ds
      (0...100).step(2) { |i| merged = merged.union(i, i + 1) }

      expect(merged.partition_count).to eq(50)
      versions.each_with_index do |version, i|
        expect(version.size).to eq(i + 1)
        expect(version.partition_count).to eq(i + 1)
        expect(version.connected?(0, 1)).to be(false)
      end
    end

    it "allows querying and extending an old version after newer ones exist" do
      v1 = DS[:a, :b, :c]
      v2 = v1.union(:a, :b)
      v3 = v2.union(:b, :c)

      forked = v1.union(:b, :c)
      expect(forked.connected?(:b, :c)).to be(true)
      expect(forked.connected?(:a, :b)).to be(false)

      expect(v3.connected?(:a, :c)).to be(true)
      expect(v2.partition_count).to eq(2)
      expect(v1.partition_count).to eq(3)
    end

    it "keeps branches intact even when a sibling compresses its paths" do
      base = DS.empty
      8.times { |i| base = base.add(i) }
      base = base.union(0, 1).union(2, 3).union(4, 5).union(6, 7)
      base = base.union(0, 2).union(4, 6).union(0, 4)

      snapshot = base.partitions.map { |members| members.to_a.sort }.sort
      parents_before = base.instance_variable_get(:@parents)

      compressed_branch = base.compress(7).compress(3).compress(5)
      merged_branch = compressed_branch.union(8, 9).union(0, 8)

      expect(base.instance_variable_get(:@parents)).to equal(parents_before)
      expect(base.partitions.map { |members| members.to_a.sort }.sort).to eq(snapshot)
      expect(merged_branch.connected?(7, 9)).to be(true)
      expect(base.include?(8)).to be(false)
    end
  end
end
