require 'spec_helper'

RSpec.describe Flipper::Variants do
  let(:salt) { "exp-42" }
  let(:feature_name) { :new_checkout }

  # Buckets are crc32("#{salt}:#{feature}:#{actor_id}") % 100_000. These
  # vectors are fixed so any change to the hashing scheme fails loudly.
  HASH_VECTORS = {
    "actor-1" => 63_174,
    "actor-2" => 69_436,
    "actor-3" => 9_514,
    "actor-4" => 9_481,
    "actor-5" => 92_863,
    "actor-6" => 68_773,
    "actor-7" => 21_075,
    "actor-8" => 6_498,
  }.freeze

  # Actor ids whose buckets sit exactly on interval boundaries for a
  # 25/25/25 control/A/B split (canonical order: A, B, control):
  # A [0, 25000), B [25000, 50000), control [50000, 75000), gap [75000, 100000).
  EDGE_VECTORS = {
    "edge-33234" => 0,
    "edge-173287" => 1,
    "edge-147727" => 24_999,
    "edge-85380" => 25_000,
    "edge-131238" => 50_000,
    "edge-147068" => 74_999,
    "edge-68819" => 75_000,
    "edge-413384" => 99_999,
  }.freeze

  def config(variants, version: "v1", salt: self.salt)
    Flipper::Variants::Configuration.new(
      variants: variants,
      salt: salt,
      version: version,
    )
  end

  def evaluate(actor_id, configuration)
    described_class.evaluate(feature_name, actor_id, configuration)
  end

  describe ".bucket_for" do
    it "matches fixed hash vectors" do
      HASH_VECTORS.each do |actor_id, bucket|
        expect(described_class.bucket_for(salt, feature_name, actor_id)).to eq(bucket)
      end
    end

    it "is stable across repeated calls" do
      first = described_class.bucket_for(salt, feature_name, "actor-1")
      expect(described_class.bucket_for(salt, feature_name, "actor-1")).to eq(first)
    end

    it "changes with the salt" do
      expect(described_class.bucket_for("other-salt", feature_name, "actor-1")).to eq(50_138)
    end

    it "changes with the feature name" do
      expect(described_class.bucket_for(salt, "other_feature", "actor-1")).to eq(60_138)
    end
  end

  describe ".evaluate" do
    let(:configuration) do
      config([["control", 25], ["A", 25], ["B", 25]])
    end

    it "assigns actors to variants per fixed vectors" do
      expect(evaluate("actor-8", configuration).variant).to eq("A")   # bucket 6_498
      expect(evaluate("actor-3", configuration).variant).to eq("A")   # bucket 9_514
      expect(evaluate("actor-4", configuration).variant).to eq("A")   # bucket 9_481
      expect(evaluate("actor-7", configuration).variant).to eq("A")   # bucket 21_075
      expect(evaluate("actor-1", configuration).variant).to eq("control") # bucket 63_174
      expect(evaluate("actor-2", configuration).variant).to eq("control") # bucket 69_436
      expect(evaluate("actor-6", configuration).variant).to eq("control") # bucket 68_773
    end

    it "assigns no variant when the actor lands in the gap" do
      result = evaluate("actor-5", configuration) # bucket 92_863, gap is [75_000, 100_000)
      expect(result.variant).to be_nil
      expect(result.assigned?).to be(false)
    end

    it "respects interval boundaries" do
      expectations = {
        "edge-33234" => "A",   # bucket 0, first bucket of A
        "edge-173287" => "A",  # bucket 1
        "edge-147727" => "A",  # bucket 24_999, last bucket of A
        "edge-85380" => "B",   # bucket 25_000, first bucket of B
        "edge-131238" => "control", # bucket 50_000, first bucket of control
        "edge-147068" => "control", # bucket 74_999, last bucket of control
        "edge-68819" => nil,   # bucket 75_000, first bucket of the gap
        "edge-413384" => nil,  # bucket 99_999, last bucket
      }
      expectations.each do |actor_id, variant|
        expect(evaluate(actor_id, configuration).variant).to eq(variant),
          "expected #{actor_id} to map to #{variant.inspect}"
      end
    end

    it "carries the configuration version for tracking" do
      result = evaluate("actor-1", configuration)
      expect(result.version).to eq("v1")
      expect(result.feature_name).to eq("new_checkout")
      expect(result.actor_id).to eq("actor-1")
      expect(result.bucket).to eq(63_174)
    end

    it "answers variant? and assigned?" do
      result = evaluate("actor-1", configuration)
      expect(result.variant?("control")).to be(true)
      expect(result.variant?(:control)).to be(true)
      expect(result.variant?("A")).to be(false)
      expect(result.assigned?).to be(true)
    end

    it "does not depend on the order variants are declared in" do
      reordered = config([["B", 25], ["control", 25], ["A", 25]])
      (HASH_VECTORS.keys + EDGE_VECTORS.keys).each do |actor_id|
        expect(evaluate(actor_id, reordered).variant)
          .to eq(evaluate(actor_id, configuration).variant),
          "expected #{actor_id} to keep its variant when config order changes"
      end
    end

    it "assigns every actor when weights sum to 100" do
      full = config([["control", 34], ["A", 33], ["B", 33]])
      (HASH_VECTORS.keys + EDGE_VECTORS.keys).each do |actor_id|
        expect(evaluate(actor_id, full).assigned?).to be(true),
          "expected #{actor_id} to be assigned when there is no gap"
      end
    end
  end

  describe "weight adjustment" do
    let(:v1) { config([["control", 25], ["A", 25], ["B", 25]], version: "v1") }
    let(:v2) { config([["control", 25], ["A", 40], ["B", 25]], version: "v2") }

    # Growing A from 25 to 40 shifts the intervals to:
    # A [0, 40000), B [40000, 65000), control [65000, 90000), gap [90000, 100000).
    # Only three bucket ranges may change hands:
    #   [25000, 40000)  B -> A
    #   [50000, 65000)  control -> B
    #   [75000, 90000)  gap -> control
    it "only reassigns actors in the shifted intervals" do
      changed = {
        "user-10" => ["B", "A"],        # bucket 27_382
        "user-1" => ["B", "A"],         # bucket 36_884
        "user-21" => ["control", "B"],  # bucket 53_123
        "actor-1" => ["control", "B"],  # bucket 63_174
        "user-15" => ["control", "B"],  # bucket 64_665
        "user-4" => [nil, "control"],   # bucket 77_563
      }
      unchanged = %w[actor-7 actor-8 actor-3 actor-4 actor-2 actor-6 actor-5]

      changed.each do |actor_id, (before, after)|
        expect(evaluate(actor_id, v1).variant).to eq(before),
          "expected #{actor_id} to start as #{before.inspect}"
        expect(evaluate(actor_id, v2).variant).to eq(after),
          "expected #{actor_id} to become #{after.inspect}"
      end

      unchanged.each do |actor_id|
        expect(evaluate(actor_id, v2).variant)
          .to eq(evaluate(actor_id, v1).variant),
          "expected #{actor_id} to keep its variant"
      end
    end

    it "keeps buckets stable and bumps the reported version" do
      result_v1 = evaluate("actor-1", v1)
      result_v2 = evaluate("actor-1", v2)
      expect(result_v2.bucket).to eq(result_v1.bucket)
      expect(result_v1.version).to eq("v1")
      expect(result_v2.version).to eq("v2")
    end
  end

  describe Flipper::Variants::Configuration do
    it "rejects weights summing to more than 100" do
      expect {
        config([["control", 50], ["A", 30], ["B", 30]])
      }.to raise_error(ArgumentError, /sum to at most 100/)
    end

    it "accepts weights summing to exactly 100" do
      configuration = config([["control", 34], ["A", 33], ["B", 33]])
      expect(configuration.gap).to eq(0)
    end

    it "exposes the unallocated gap" do
      configuration = config([["control", 25], ["A", 25], ["B", 25]])
      expect(configuration.gap).to eq(25)
    end

    it "rejects negative weights" do
      expect {
        config([["control", 60], ["A", -10], ["B", 25]])
      }.to raise_error(ArgumentError, /between 0 and 100/)
    end

    it "rejects weights above 100" do
      expect {
        config([["control", 101]])
      }.to raise_error(ArgumentError, /between 0 and 100/)
    end

    it "rejects duplicate variant names" do
      expect {
        config([["A", 25], ["A", 25]])
      }.to raise_error(ArgumentError, /duplicate variant names: A/)
    end

    it "rejects an empty variant list" do
      expect {
        config([])
      }.to raise_error(ArgumentError, /variants must not be empty/)
    end

    it "rejects an empty salt" do
      expect {
        config([["A", 50]], salt: "")
      }.to raise_error(ArgumentError, /salt must not be empty/)
    end

    it "rejects a missing version" do
      expect {
        config([["A", 50]], version: nil)
      }.to raise_error(ArgumentError, /version must be present/)
    end

    it "rejects an empty variant name" do
      expect {
        config([["", 50]])
      }.to raise_error(ArgumentError, /name must not be empty/)
    end

    it "accepts Variant instances and symbol names" do
      configuration = described_class.new(
        variants: [Flipper::Variants::Variant.new(:control, 50)],
        salt: :exp_42,
        version: 7,
      )
      expect(configuration.variants.first.name).to eq("control")
      expect(configuration.salt).to eq("exp_42")
      expect(configuration.version).to eq("7")
    end
  end
end
