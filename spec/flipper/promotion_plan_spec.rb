require "set"

RSpec.describe Flipper::PromotionPlan do
  let(:baseline) do
    {
      "search" => {
        actors: Set["actor-1", "actor-2"],
        groups: Set["staff"],
        percentage_of_time: "10",
      },
      "removed" => { actors: Set["actor-9"] },
      "unchanged" => { groups: Set["staff"] },
    }
  end

  let(:source) do
    {
      "search" => {
        actors: Set["actor-1", "actor-3"],
        groups: Set["staff", "beta"],
        percentage_of_time: "20",
      },
      "new" => { boolean: "true" },
      "unchanged" => { groups: Set["staff"] },
    }
  end

  let(:target_adapter) do
    Flipper::Adapters::Memory.new({
      "search" => {
        actors: Set["actor-1", "actor-2", "actor-4"],
        groups: Set["staff"],
        percentage_of_time: "30",
      },
      "target_only" => { actors: Set["actor-8"] },
      "unchanged" => { groups: Set["staff"] }
    })
  end

  it "builds viewable feature and gate changes without overwriting target sets" do
    plan = described_class.new(baseline, source, target_adapter)
    search = plan.changes.fetch("search")
    actors = search.gates.fetch(:actors)
    groups = search.gates.fetch(:groups)

    expect(actors.added).to eq(Set["actor-3"])
    expect(actors.removed).to eq(Set["actor-2"])
    expect(actors.desired).to eq(Set["actor-1", "actor-3", "actor-4"])
    expect(groups.added).to eq(Set["beta"])
    expect(groups.removed).to be_empty
    expect(groups.desired).to eq(Set["staff", "beta"])
    expect(plan.changes["new"].action).to eq(:add)
    expect(plan.changes["removed"].action).to eq(:remove)
    expect(plan.changes).not_to have_key("unchanged")
    expect(plan.changes["target_only"].action).to be_nil
    expect(plan.conflicts.map(&:path)).to eq([["search", :percentage_of_time]])
  end

  it "applies resolved changes to a memory adapter and preserves target-only data" do
    plan = described_class.new(baseline, source, target_adapter)
    plan.resolve!("search", :percentage_of_time, resolution: :source)
    plan.apply

    expect(target_adapter.get_all).to eq(
      "search" => {
        boolean: nil,
        groups: Set["staff", "beta"],
        actors: Set["actor-1", "actor-3", "actor-4"],
        expression: nil,
        percentage_of_actors: nil,
        percentage_of_time: "20",
      },
      "target_only" => {
        boolean: nil,
        groups: Set.new,
        actors: Set["actor-8"],
        expression: nil,
        percentage_of_actors: nil,
        percentage_of_time: nil,
      },
      "new" => {
        boolean: "true",
        groups: Set.new,
        actors: Set.new,
        expression: nil,
        percentage_of_actors: nil,
        percentage_of_time: nil,
      },
      "unchanged" => {
        boolean: nil,
        groups: Set["staff"],
        actors: Set.new,
        expression: nil,
        percentage_of_actors: nil,
        percentage_of_time: nil,
      }
    )
  end

  it "requires target recalculation after the target version changes" do
    plan = described_class.new(baseline, source, target_adapter)
    plan.resolve!("search", :percentage_of_time, resolution: :source)
    target_adapter.enable(
      Flipper::Feature.new("target_only", target_adapter),
      Flipper::Gates::Boolean.new,
      Flipper::Types::Boolean.new(true)
    )

    expect { plan.apply }.to raise_error(
      described_class::StaleTarget,
      /Recalculate the plan/
    )
  end

  it "combines actor or group additions and deletions independently" do
    conflicting_baseline = { "feature" => { actors: Set["a", "b"] } }
    conflicting_source = { "feature" => { actors: Set["a", "c"] } }
    conflicting_target = { "feature" => { actors: Set["a", "b", "c"] } }
    plan = described_class.new(conflicting_baseline, conflicting_source, conflicting_target)

    expect(plan.conflicts).to be_empty
    expect(plan.result.fetch("feature").fetch(:actors)).to eq(Set["a", "c"])
    gate_change = plan.changes.fetch("feature").gates.fetch(:actors)
    expect(gate_change.added).to eq(Set["c"])
    expect(gate_change.removed).to eq(Set["b"])
    expect(gate_change.target_added).to eq(Set["c"])
  end

  it "supports custom scalar conflict resolution" do
    plan = described_class.new(baseline, source, target_adapter)
    plan.resolve!("search", :percentage_of_time, "40")

    expect(plan.result.fetch("search").fetch(:percentage_of_time)).to eq("40")
    expect(plan.conflicts.first.resolution).to eq(:custom)
  end

  it "exposes a serializable plan summary and stable target version" do
    plan = described_class.new(baseline, source, target_adapter)
    summary = plan.to_h

    expect(summary[:target_version]).to eq(plan.target_version)
    expect(summary[:resolved]).to eq(false)
    expect(summary[:changes].keys).to include("search", "new", "removed")
    expect(summary[:conflicts].first).to include(
      feature: "search",
      gate: :percentage_of_time,
      source: 20,
      target: 30
    )
    expect(described_class.version_for(target_adapter)).to eq(plan.target_version)
  end

  it "does not apply until conflicts are explicitly resolved" do
    plan = described_class.new(baseline, source, target_adapter)

    expect { plan.apply }.to raise_error(described_class::UnresolvedConflict)
    expect(target_adapter.get_all.keys).to eq(["search", "target_only", "unchanged"])
  end

  it "works with hashes, exports, and DSL adapters without a remote service" do
    export_adapter = Flipper::Adapters::Memory.new(baseline)
    export = export_adapter.export
    source_adapter = Flipper::Adapters::Memory.new(source)

    source_dsl = Flipper.new(source_adapter)
    target_dsl = Flipper.new(target_adapter)
    target_dsl.preload_all
    plan = Flipper::Promotion.plan(export, source_dsl, target_dsl)
    plan.resolve!("search", :percentage_of_time, resolution: :target)
    plan.apply_to(target_dsl)

    expect(target_adapter.get_all.fetch("search").fetch(:percentage_of_time)).to eq("30")
    expect(target_dsl.preload(["search"]).first.gate_values.percentage_of_time).to eq(30)
  end

  it "applies source removal when the target still matches the baseline" do
    target_with_removed_feature = Flipper::Adapters::Memory.new({
      "removed" => { actors: Set["actor-9"] }
    })
    plan = described_class.new(
      { "removed" => { actors: Set["actor-9"] } },
      {},
      target_with_removed_feature
    )

    expect(plan.conflicts).to be_empty
    expect(plan.changes.fetch("removed").action).to eq(:remove)
    plan.apply

    expect(target_with_removed_feature.features).not_to include("removed")
  end

  it "conflicts when source removes a feature that target temporarily modified" do
    target_modified = Flipper::Adapters::Memory.new({
      "removed" => { actors: Set["actor-10"] }
    })
    plan = described_class.new(
      { "removed" => { actors: Set["actor-9"] } },
      {},
      target_modified
    )

    expect(plan.conflicts.map(&:path)).to eq([["removed"]])
    expect { plan.apply }.to raise_error(described_class::UnresolvedConflict)

    plan.resolve!("removed", resolution: :source)
    plan.apply
    expect(target_modified.features).not_to include("removed")
  end

  it "conflicts when both sides add the same feature with different gates" do
    target_adapter = Flipper::Adapters::Memory.new({
      "added" => { percentage_of_time: "10" }
    })
    plan = described_class.new(
      {},
      { "added" => { percentage_of_time: "20" } },
      target_adapter
    )

    expect(plan.conflicts.map(&:path)).to eq([["added"]])
    expect(plan.changes.fetch("added").action).to be_nil

    plan.resolve!("added", resolution: :source)
    expect(plan.changes.fetch("added").action).to eq(:update)
    plan.apply(target_adapter)

    expect(target_adapter.get_all.fetch("added").fetch(:percentage_of_time)).to eq("20")
  end
end
