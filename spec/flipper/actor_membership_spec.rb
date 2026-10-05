RSpec.describe Flipper::ActorMembership do
  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:flipper) { Flipper.new(adapter) }
  let(:feature) { flipper[:whitelist] }
  let(:feature_key) { feature.key }

  # Authoritative set version, bumped on every actor enable/disable.
  let(:versions) { Hash.new(0) }
  let(:stats) { Hash.new(0) }
  let(:index) { Flipper::ActorIndex::Bloom.new(size: 1024, hashes: 4) }

  subject(:checker) do
    described_class.new(
      index: index,
      loader: ->(key) { Flipper::GateValues.new(adapter.get(feature)).actors },
      versioner: ->(key) { versions[key] },
      stats: stats,
    )
  end

  def enable_actor(actor)
    feature.enable_actor(Flipper::Actor.new(actor))
    versions[feature_key] += 1
    index.track_add(feature_key, actor, versions[feature_key])
  end

  def disable_actor(actor)
    feature.disable_actor(Flipper::Actor.new(actor))
    versions[feature_key] += 1
    index.track_remove(feature_key, actor, versions[feature_key])
  end

  context "with an actor in the set" do
    it "enables after an exact query and counts it" do
      enable_actor("user;1")
      expect(checker.enabled?(feature_key, "user;1")).to be(true)
      expect(stats[:index_maybe]).to eq(1)
      expect(stats[:exact_queries]).to eq(1)
    end
  end

  context "with an actor definitely not in the set" do
    it "disables without any exact query" do
      enable_actor("user;1")
      expect(checker.enabled?(feature_key, "user;absent")).to be(false)
      expect(stats[:index_absent]).to eq(1)
      expect(stats[:exact_queries]).to eq(0)
    end
  end

  context "with a forced Bloom filter false positive" do
    # A 1-bit filter reports :maybe for every value, so every non-member
    # lookup is a false positive by construction.
    let(:index) { Flipper::ActorIndex::Bloom.new(size: 1, hashes: 1) }

    it "still disables non-members because a hit never enables directly" do
      enable_actor("user;1")
      expect(index.check(feature_key, "user;impostor", set_version: versions[feature_key])).to eq(:maybe)
      expect(checker.enabled?(feature_key, "user;impostor")).to be(false)
      expect(stats[:index_maybe]).to eq(1)
      expect(stats[:exact_queries]).to eq(1)
    end

    it "still enables real members" do
      enable_actor("user;1")
      expect(checker.enabled?(feature_key, "user;1")).to be(true)
    end
  end

  context "with a stub index that always lies about membership" do
    let(:always_maybe) do
      Class.new do
        def check(*, **) = :maybe
        def sync(*) = true
      end.new
    end

    it "the exact set remains the final authority" do
      lying = described_class.new(
        index: always_maybe,
        loader: ->(key) { Flipper::GateValues.new(adapter.get(feature)).actors },
        versioner: ->(key) { versions[key] },
        stats: stats,
      )
      enable_actor("user;1")
      expect(lying.enabled?(feature_key, "user;1")).to be(true)
      expect(lying.enabled?(feature_key, "user;2")).to be(false)
      expect(stats[:exact_queries]).to eq(2)
    end
  end

  context "when the index version lags behind the set version" do
    it "falls back to an exact query and re-syncs the index" do
      enable_actor("user;1")
      versions[feature_key] += 1 # set changed without notifying the index

      expect(checker.enabled?(feature_key, "user;1")).to be(true)
      expect(stats[:index_stale]).to eq(1)
      expect(stats[:exact_queries]).to eq(1)
      expect(stats[:syncs]).to eq(1)

      # After the fallback sync, non-members are cheap again.
      expect(checker.enabled?(feature_key, "user;absent")).to be(false)
      expect(stats[:index_absent]).to eq(1)
      expect(stats[:exact_queries]).to eq(1)
    end
  end

  context "additions" do
    it "newly added actors are enabled via the index plus exact query" do
      enable_actor("user;1")
      enable_actor("user;2")
      expect(checker.enabled?(feature_key, "user;2")).to be(true)
      expect(stats[:exact_queries]).to eq(1)
    end
  end

  context "removals" do
    it "removed actors are disabled, with one fallback exact query" do
      enable_actor("user;1")
      enable_actor("user;2")
      disable_actor("user;1")

      # Removal invalidates the index: first check falls back, exact set
      # (which no longer contains user;1) decides.
      expect(checker.enabled?(feature_key, "user;1")).to be(false)
      expect(stats[:index_stale]).to eq(1)
      expect(stats[:syncs]).to eq(1)

      # The rebuilt index reflects the removal.
      expect(checker.enabled?(feature_key, "user;1")).to be(false)
      expect(stats[:index_absent]).to eq(1)
      expect(stats[:exact_queries]).to eq(1)

      # Survivors are still enabled.
      expect(checker.enabled?(feature_key, "user;2")).to be(true)
    end
  end
end
