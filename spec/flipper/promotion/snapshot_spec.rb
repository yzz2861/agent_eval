require "set"
require "flipper/adapters/memory"

RSpec.describe Flipper::PromotionPlan::Snapshot do
  def build(source)
    described_class.new(source)
  end

  describe "normalization" do
    it "converts array gate values to sets of strings and symbol keys to symbols" do
      snapshot = build("search" => { "actors" => [1, 2], "groups" => ["staff"] })

      expect(snapshot["search"][:actors]).to eq(Set["1", "2"])
      expect(snapshot["search"][:groups]).to eq(Set["staff"])
    end
  end

  describe "#version" do
    it "is stable for equal configurations regardless of key/set order" do
      raw_a = {
        "zebra" => { actors: Set["2", "1"], boolean: "true" },
        "alpha" => { "groups" => ["staff"] },
      }
      raw_b = {
        "alpha" => { groups: Set["staff"] },
        "zebra" => { boolean: "true", actors: Set["1", "2"] },
      }

      expect(build(raw_a).version).to eq(build(raw_b).version)
    end

    it "changes when a gate value changes" do
      before = build("search" => { actors: Set["1"] })
      after = build("search" => { actors: Set["1", "2"] })

      expect(before.version).not_to eq(after.version)
    end

    it "treats nil and 0 percentages as the same version" do
      with_nil = build("search" => { percentage_of_actors: nil })
      with_zero = build("search" => { percentage_of_actors: "0" })

      expect(with_nil.version).to eq(with_zero.version)
    end

    it "reads through an adapter via get_all" do
      adapter = Flipper::Adapters::Memory.new
      Flipper.new(adapter, memoize: false).enable_actor(:search, Flipper::Actor.new("7"))

      snapshot = build(adapter)

      expect(snapshot["search"][:actors]).to eq(Set["7"])
      expect(snapshot.version).to eq(described_class.new(adapter.get_all).version)
    end

    it "accepts a DSL instance and a raw hash" do
      adapter = Flipper::Adapters::Memory.new
      flipper = Flipper.new(adapter, memoize: false)
      flipper.enable_group(:search, :staff)

      from_dsl = build(flipper)
      from_hash = build("search" => { groups: Set["staff"] })

      expect(from_dsl.version).to eq(from_hash.version)
    end

    it "accepts an Flipper::Export" do
      adapter = Flipper::Adapters::Memory.new
      Flipper.new(adapter, memoize: false).enable(:search)
      export = adapter.export

      expect(build(export).version).to eq(build(adapter.get_all).version)
    end
  end
end
