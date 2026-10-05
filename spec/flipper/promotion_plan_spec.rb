require "set"
require "flipper/adapters/memory"

RSpec.describe Flipper::PromotionPlan do
  def config(gates = {})
    Flipper::Adapters::Memory.default_config.merge(gates)
  end

  def adapter(features)
    raw = features.transform_values { |gates| config(gates) }
    Flipper::Adapters::Memory.new(raw)
  end

  let(:base) do
    adapter(
      "search" => { actors: Set["1"], groups: Set["staff"], percentage_of_actors: "10" },
      "old" => { boolean: "true" },
      "expr" => { expression: { "Equal" => [{ "Property" => "plan" }, "pro"] } },
    )
  end

  let(:source) do
    adapter(
      "search" => { actors: Set["1", "2"], groups: Set.new, percentage_of_actors: "50" },
      "brand_new" => { boolean: "true" },
      "expr" => { expression: { "Equal" => [{ "Property" => "plan" }, "enterprise"] } },
    )
  end

  let(:target) do
    adapter(
      "search" => { actors: Set["1", "9"], groups: Set["staff"], percentage_of_actors: "25" },
      "old" => { boolean: "true" },
      "expr" => { expression: { "Equal" => [{ "Property" => "plan" }, "trial"] } },
      "target_only" => { boolean: "true" },
    )
  end

  subject(:plan) { described_class.build(base, source, target) }

  describe "DSL entry point" do
    it "builds and applies a plan against a Flipper DSL target" do
      base_flipper = Flipper.new(base, memoize: false)
      source_flipper = Flipper.new(source, memoize: false)
      target_flipper = Flipper.new(Flipper::Adapters::Memory.new(target.get_all), memoize: false)

      dsl_plan = target_flipper.promotion_plan(base_flipper, source_flipper)
      dsl_plan.resolve!("search", :source, gate: :percentage_of_actors)
      dsl_plan.resolve!("expr", :source, gate: :expression)
      dsl_plan.apply

      expect(target_flipper.feature(:search).actors_value).to eq(Set["1", "2", "9"])
      expect(target_flipper.exist?(:brand_new)).to be(true)
    end
  end

  describe "three-way merge" do
    it "computes set gate additions and deletions independently without overwriting target" do
      search = plan.feature_plans.find { |feature| feature.feature == "search" }
      actors = search.gate_changes.find { |change| change.gate == :actors }
      groups = search.gate_changes.find { |change| change.gate == :groups }

      expect(actors.added).to eq(Set["2"])
      expect(actors.removed).to be_empty
      expect(actors.merged_value).to eq(Set["1", "2", "9"])

      expect(groups.added).to be_empty
      expect(groups.removed).to eq(Set["staff"])
    end

    it "never re-adds a member the target removed independently" do
      local_target = adapter("search" => { actors: Set["2"] })
      local_base = adapter("search" => { actors: Set["1", "2"] })
      local_source = adapter("search" => { actors: Set["1", "2"], groups: Set["admins"] })

      feature = described_class.build(local_base, local_source, local_target)
                   .feature_plans.find { |f| f.feature == "search" }
      actors = feature.gate_changes.find { |change| change.gate == :actors }

      expect(actors.merged_value).to eq(Set["2"])
      expect(actors.added).to be_empty
    end

    it "adds new source features and removes source-deleted features" do
      by_feature = plan.changes.map { |feature| [feature.feature, feature.action] }.to_h

      expect(by_feature["brand_new"]).to eq(:add)
      expect(by_feature["old"]).to eq(:remove)
      expect(by_feature).not_to have_key("target_only")
    end

    it "leaves target-only features untouched" do
      expect(plan.changes.map(&:feature)).not_to include("target_only")
    end

    it "merges gate values for a feature independently added on both sides" do
      local_base = adapter({})
      local_source = adapter("newish" => { actors: Set["1"], groups: Set["staff"] })
      local_target = adapter("newish" => { actors: Set["2"] })

      feature = described_class.build(local_base, local_source, local_target)
                   .feature_plans.find { |f| f.feature == "newish" }
      actors = feature.gate_changes.find { |change| change.gate == :actors }

      expect(feature.action).to eq(:modify)
      expect(actors.merged_value).to eq(Set["1", "2"])
    end

    it "adopts a source boolean enable cleanly when target leaves the baseline" do
      local_base = adapter("switch" => { actors: Set["1"] })
      local_source = adapter("switch" => { boolean: "true", actors: Set["1"] })
      local_target = adapter("switch" => { actors: Set["1", "9"] })

      feature = described_class.build(local_base, local_source, local_target)
                   .feature_plans.find { |f| f.feature == "switch" }
      boolean_change = feature.gate_changes.find { |change| change.gate == :boolean }

      expect(boolean_change).not_to be_conflict
      expect(boolean_change.merged_value).to eq("true")
      # Target's temporary actor survives: promotion writes the merged gates.
      expect(feature.merged_config[:actors]).to eq(Set["1", "9"])
    end

    it "cleans a remove when the target is unchanged relative to the baseline" do
      flipper_target = Flipper.new(target, memoize: false)
      expect(flipper_target.exist?(:old)).to be(true)
      old = plan.feature_plans.find { |f| f.feature == "old" }
      expect(old.action).to eq(:remove)
      expect(old.conflicts).to be_empty
    end
  end

  describe "conflicts" do
    it "reports a scalar gate changed on both sides as an unresolved conflict" do
      percentage = plan.unresolved_conflicts.find { |conflict| conflict.gate == :percentage_of_actors }
      expect(percentage).to have_attributes(
        feature: "search",
        kind: :gate_value,
        source_value: "50",
        target_value: "25",
        base_value: "10",
      )
    end

    it "reports expression changes on both sides as conflicts" do
      expression_conflict = plan.unresolved_conflicts.find { |conflict| conflict.gate == :expression }
      expect(expression_conflict).to have_attributes(feature: "expr", kind: :gate_value)
    end

    it "does not conflict when one side leaves the baseline value alone" do
      local_target = adapter("search" => { percentage_of_actors: "10" })
      local_base = adapter("search" => { percentage_of_actors: "10" })
      local_source = adapter("search" => { percentage_of_actors: "50" })

      feature = described_class.build(local_base, local_source, local_target)
                   .feature_plans.find { |f| f.feature == "search" }

      expect(feature.conflicts).to be_empty
      expect(feature.merged_config[:percentage_of_actors]).to eq("50")
    end

    it "flags presence when source deletes a feature the target modified" do
      local_base = adapter("temp" => { actors: Set["1"] })
      local_source = adapter({})
      local_target = adapter("temp" => { actors: Set["1", "9"] })

      feature = described_class.build(local_base, local_source, local_target)
                   .feature_plans.find { |f| f.feature == "temp" }

      expect(feature.conflict).to have_attributes(kind: :presence)
    end

    it "flags presence when target deletes a feature the source keeps" do
      local_base = adapter("temp" => { actors: Set["1"] })
      local_source = adapter("temp" => { actors: Set["1"] })
      local_target = adapter({})

      feature = described_class.build(local_base, local_source, local_target)
                   .feature_plans.find { |f| f.feature == "temp" }

      expect(feature.conflict).to have_attributes(kind: :presence)
    end

    it "flags presence even when the surviving source config equals the baseline" do
      local_base = adapter("temp" => { actors: Set["1"] })
      local_source = adapter("temp" => { actors: Set["1"] })
      local_target = adapter({})

      local_plan = described_class.build(local_base, local_source, local_target)
      expect(local_plan.unresolved_conflicts.map(&:kind)).to eq([:presence])

      # :source re-adds the feature
      local_plan.resolve!("temp", :source)
      local_plan.apply(local_target)
      expect(local_target.get_all["temp"][:actors]).to eq(Set["1"])
    end

    it "resolves scalar conflicts with :source or :target" do
      plan.resolve!("search", :source, gate: :percentage_of_actors)
      plan.resolve!("expr", :source, gate: :expression)

      search = plan.feature_plans.find { |feature| feature.feature == "search" }
      expect(search.merged_config[:percentage_of_actors]).to eq("50")
      expect(plan).to be_resolved
    end

    it "resolves presence conflicts with :target keeping the feature" do
      local_base = adapter("temp" => { actors: Set["1"] })
      local_source = adapter({})
      local_target = adapter("temp" => { actors: Set["1", "9"] })

      local_plan = described_class.build(local_base, local_source, local_target)
      local_plan.resolve!("temp", :target)

      expect(local_plan.changes.map(&:feature)).not_to include("temp")
      local_plan.apply(local_target)
      expect(local_target.get_all).to have_key("temp")
    end

    it "resolves presence conflicts with :source removing the feature" do
      local_base = adapter("temp" => { actors: Set["1"] })
      local_source = adapter({})
      local_target = adapter("temp" => { actors: Set["1", "9"] })
      flipper_target = Flipper.new(local_target, memoize: false)

      local_plan = described_class.build(local_base, local_source, local_target)
      local_plan.resolve!("temp", :source)
      local_plan.apply

      expect(local_target.get_all).not_to have_key("temp")
      expect(flipper_target.exist?(:temp)).to be(false)
    end

    it "raises for an invalid resolution choice" do
      expect do
        plan.resolve!("search", :baseline, gate: :percentage_of_actors)
      end.to raise_error(described_class::InvalidResolution)
    end

    it "raises when resolving a nonexistent conflict" do
      expect { plan.resolve!("nope", :source) }.to raise_error(described_class::ConflictNotFound)
    end
  end

  describe "#apply" do
    before do
      plan.resolve!("search", :source, gate: :percentage_of_actors)
      plan.resolve!("expr", :source, gate: :expression)
    end

    it "applies the merged configuration to the memory target atomically" do
      plan.apply

      search = target.get_all["search"]
      expect(search[:actors]).to eq(Set["1", "2", "9"])
      expect(search[:groups]).to be_empty
      expect(search[:percentage_of_actors]).to eq("50")
      expect(target.get_all["brand_new"][:boolean]).to eq("true")
      expect(target.get_all).not_to have_key("old")
      expect(target.get_all).to have_key("target_only")
    end

    it "refuses to apply while conflicts are unresolved" do
      local_plan = described_class.build(base, source, target)
      expect { local_plan.apply }.to raise_error(described_class::UnresolvedConflicts)
      expect(target.get_all["search"][:percentage_of_actors]).to eq("25")
    end

    it "raises TargetVersionMismatch and applies nothing when the target changed" do
      Flipper.new(target, memoize: false).enable_actor(:search, Flipper::Actor.new("42"))

      expect { plan.apply }.to raise_error(described_class::TargetVersionMismatch)
      expect(target.get_all["search"][:actors]).to eq(Set["1", "9", "42"])
      expect(target.get_all).to have_key("old")
    end

    it "can only be applied once" do
      plan.apply
      expect { plan.apply }.to raise_error(Flipper::Error)
    end

    it "applies through a Flipper DSL (memoizable wrapper) and clears memoization" do
      flipper = Flipper.new(target)
      flipper.enabled?(:search)
      plan.apply(flipper)

      expect(flipper.feature(:search).actors_value).to eq(Set["1", "2", "9"])
    end

    it "falls back to non-atomic Feature API writes for adapters without override" do
      backend = Flipper::Adapters::Memory.new(target.get_all)
      fallback_class = Class.new do
        include Flipper::Adapter

        def initialize(backend)
          @backend = backend
        end

        def method_missing(name, *args, **kwargs, &block)
          @backend.send(name, *args, **kwargs, &block)
        end

        def respond_to_missing?(name, include_private = false)
          super || @backend.respond_to?(name, include_private)
        end
      end
      fallback = fallback_class.new(backend)
      fallback_plan = described_class.build(base, source, fallback)
      fallback_plan.resolve!("search", :source, gate: :percentage_of_actors)
      fallback_plan.resolve!("expr", :source, gate: :expression)

      fallback_plan.apply

      expect(backend.get_all["search"][:actors]).to eq(Set["1", "2", "9"])
      expect(backend.get_all["search"][:groups]).to be_empty
      expect(backend.get_all).not_to have_key("old")
    end

    it "applies every operation under the memory adapter lock atomically" do
      lock = target.instance_variable_get(:@lock)
      entered = Mutex.new
      entered_condition = ConditionVariable.new
      entered_flag = false
      release_mutex = Mutex.new
      release_condition = ConditionVariable.new
      released = false

      holder = Thread.new do
        lock.synchronize do
          entered.synchronize do
            entered_flag = true
            entered_condition.signal
          end
          release_mutex.synchronize do
            release_condition.wait(release_mutex) until released
          end
        end
      end
      entered.synchronize do
        entered_condition.wait(entered) until entered_flag
      end

      applier = Thread.new do
        begin
          plan.apply
        rescue described_class::TargetVersionMismatch
          :mismatch
        end
      end

      sleep 0.05
      expect(applier).to be_alive
      release_mutex.synchronize do
        released = true
        release_condition.broadcast
      end
      expect(applier.value).to eq(true)
      expect(target.get_all["search"][:actors]).to eq(Set["1", "2", "9"])
    ensure
      holder.join
    end
  end

  describe "#to_h" do
    it "is reviewable and serializable with feature, gate, adds, removes and conflicts" do
      hash = plan.to_h

      expect(hash).to include(:target_version, :changes, :conflicts)
      expect { JSON.generate(hash) }.not_to raise_error

      search = hash[:changes].find { |change| change[:feature] == "search" }
      actors = search[:gate_changes].find { |change| change[:gate] == :actors }
      expect(actors[:added]).to eq(["2"])
    end
  end
end
