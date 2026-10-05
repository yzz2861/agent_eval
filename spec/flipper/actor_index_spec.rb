RSpec.describe Flipper::ActorIndex::Bloom do
  let(:index) { described_class.new(size: 1024, hashes: 4) }

  describe ".optimal" do
    it "derives size and hashes from expected members and target fpr" do
      index = described_class.optimal(expected_members: 1_000_000, fpr: 0.01)
      expect(index.size).to eq(9_585_059)
      expect(index.hashes).to eq(7)
      expect(index.bytes_per_feature).to eq(1_198_133) # ~1.14 MB
    end

    it "rejects an invalid fpr" do
      expect { described_class.optimal(expected_members: 10, fpr: 1.5) }
        .to raise_error(ArgumentError)
    end
  end

  describe "check" do
    it "returns :stale when the feature was never indexed" do
      expect(index.check("feature", "actor;1", set_version: 0)).to eq(:stale)
    end

    it "returns :stale when the set version moved on without the index" do
      index.sync("feature", ["actor;1"], 1)
      expect(index.check("feature", "actor;1", set_version: 2)).to eq(:stale)
    end

    it "returns :maybe for a synced member at the matching version" do
      index.sync("feature", ["actor;1"], 1)
      expect(index.check("feature", "actor;1", set_version: 1)).to eq(:maybe)
    end

    it "returns :absent for a value that was never added" do
      index.sync("feature", ["actor;1"], 1)
      expect(index.check("feature", "actor;absent", set_version: 1)).to eq(:absent)
    end
  end

  describe "track_add" do
    it "makes the added actor a :maybe at the new version" do
      index.track_add("feature", "actor;1", 1)
      expect(index.check("feature", "actor;1", set_version: 1)).to eq(:maybe)
      expect(index.version_for("feature")).to eq(1)
    end

    it "chains onto a filter built at the previous version" do
      index.sync("feature", ["actor;1"], 1)
      index.track_add("feature", "actor;2", 2)
      expect(index.check("feature", "actor;1", set_version: 2)).to eq(:maybe)
      expect(index.check("feature", "actor;2", set_version: 2)).to eq(:maybe)
    end
  end

  describe "track_remove" do
    it "invalidates the feature so the next check is :stale" do
      index.sync("feature", ["actor;1"], 1)
      index.track_remove("feature", "actor;1", 2)
      expect(index.check("feature", "actor;1", set_version: 2)).to eq(:stale)
      expect(index.version_for("feature")).to be_nil
    end
  end

  describe "sync" do
    it "rebuilds the filter from the authoritative members" do
      index.sync("feature", ["actor;1", "actor;2"], 7)
      expect(index.check("feature", "actor;1", set_version: 7)).to eq(:maybe)
      expect(index.check("feature", "actor;2", set_version: 7)).to eq(:maybe)
      expect(index.check("feature", "actor;3", set_version: 7)).to eq(:absent)
    end
  end

  describe "false positives" do
    it "can be forced with a tiny filter, and are reported as :maybe not :absent" do
      tiny = described_class.new(size: 1, hashes: 1)
      tiny.sync("feature", ["actor;1"], 1)
      # Every value maps to the single bit, so this is a guaranteed false
      # positive for non-members.
      expect(tiny.check("feature", "actor;not-a-member", set_version: 1)).to eq(:maybe)
    end
  end
end
