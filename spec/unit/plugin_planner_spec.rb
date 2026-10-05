# frozen_string_literal: true

RSpec.describe Dry::System::PluginPlanner do
  subject(:planner) { described_class.new(candidates: candidates) }

  def descriptor(name, version, dependencies: {}, optional_dependencies: {}, metadata: nil)
    described_class::Descriptor.new(
      name: name,
      version: version,
      dependencies: dependencies,
      optional_dependencies: optional_dependencies,
      metadata: metadata
    )
  end

  describe "#plan" do
    context "with a single plugin" do
      let(:candidates) {
        [
          descriptor(:foo, "1.0.0"),
          descriptor(:foo, "1.5.0"),
          descriptor(:foo, "2.0.0")
        ]
      }

      it "selects the highest version satisfying the application range" do
        plan = planner.plan(foo: "~> 1.0")

        expect(plan.version_of(:foo)).to eq(Gem::Version.new("1.5.0"))
      end

      it "never selects a version outside the application range" do
        plan = planner.plan(foo: "< 2.0")

        expect(plan.version_of(:foo)).to eq(Gem::Version.new("1.5.0"))
      end

      it "accepts an array of names, allowing any version" do
        plan = planner.plan([:foo])

        expect(plan.version_of(:foo)).to eq(Gem::Version.new("2.0.0"))
      end

      it "accepts combined requirements" do
        plan = planner.plan(foo: [">= 1.2", "< 2.0"])

        expect(plan.version_of(:foo)).to eq(Gem::Version.new("1.5.0"))
      end
    end

    context "with required dependencies" do
      let(:candidates) {
        [
          descriptor(:foo, "1.0.0", dependencies: {bar: ">= 1.0"}),
          descriptor(:bar, "1.0.0", dependencies: {baz: "~> 1.2"}),
          descriptor(:bar, "2.0.0", dependencies: {baz: "~> 1.2"}),
          descriptor(:baz, "1.2.0"),
          descriptor(:baz, "1.3.0"),
          descriptor(:baz, "2.0.0")
        ]
      }

      it "pulls required dependencies into the plan transitively" do
        plan = planner.plan(foo: ">= 1.0")

        expect(plan.to_h).to eq(
          foo: Gem::Version.new("1.0.0"),
          bar: Gem::Version.new("2.0.0"),
          baz: Gem::Version.new("1.3.0")
        )
      end

      it "constrains dependency versions declared by dependents" do
        candidates = [
          descriptor(:foo, "1.0.0", dependencies: {bar: "< 2.0"}),
          descriptor(:bar, "1.0.0"),
          descriptor(:bar, "2.0.0")
        ]
        planner = described_class.new(candidates: candidates)

        expect(planner.plan(foo: ">= 1.0").version_of(:bar)).to eq(Gem::Version.new("1.0.0"))
      end
    end

    context "when backtracking is required" do
      let(:candidates) {
        [
          descriptor(:a, "2.0.0", dependencies: {c: ">= 2.0"}),
          descriptor(:a, "1.0.0", dependencies: {c: "< 2.0"}),
          descriptor(:c, "1.5.0"),
          descriptor(:c, "2.0.0")
        ]
      }

      it "selects a lower version of a plugin when its highest version conflicts" do
        plan = planner.plan(a: ">= 1.0", c: "< 2.0")

        expect(plan.to_h).to eq(
          a: Gem::Version.new("1.0.0"),
          c: Gem::Version.new("1.5.0")
        )
      end
    end

    context "with optional dependencies" do
      it "does not pull optional dependencies into the plan" do
        candidates = [
          descriptor(:foo, "1.0.0", optional_dependencies: {bar: ">= 1.0"}),
          descriptor(:bar, "1.0.0")
        ]
        planner = described_class.new(candidates: candidates)

        plan = planner.plan(foo: ">= 1.0")

        expect(plan).to include(:foo)
        expect(plan).not_to include(:bar)
      end

      it "constrains an optional dependency when it is selected anyway" do
        candidates = [
          descriptor(:foo, "1.0.0", optional_dependencies: {bar: "< 2.0"}),
          descriptor(:bar, "1.0.0"),
          descriptor(:bar, "2.0.0")
        ]
        planner = described_class.new(candidates: candidates)

        plan = planner.plan(foo: ">= 1.0", bar: ">= 1.0")

        expect(plan.version_of(:bar)).to eq(Gem::Version.new("1.0.0"))
      end

      it "fails when a selected optional dependency cannot satisfy the constraint" do
        candidates = [
          descriptor(:foo, "1.0.0", optional_dependencies: {bar: "< 2.0"}),
          descriptor(:bar, "2.0.0")
        ]
        planner = described_class.new(candidates: candidates)

        expect { planner.plan(foo: ">= 1.0", bar: ">= 1.0") }
          .to raise_error(Dry::System::PluginPlanUnresolvableError, /bar/)
      end
    end

    context "when no solution exists" do
      let(:candidates) {
        [
          descriptor(:foo, "1.0.0"),
          descriptor(:foo, "1.5.0"),
          descriptor(:bar, "1.3.0", dependencies: {foo: "< 2.0"})
        ]
      }

      it "raises an error describing the minimal conflict chain" do
        expect { planner.plan(foo: ">= 2.0", bar: "~> 1.3") }
          .to raise_error(Dry::System::PluginPlanUnresolvableError) { |error|
            expect(error.message).to include("no version of `foo` satisfies all constraints:")
            expect(error.message).to include("application requires foo >= 2.0")
            expect(error.message).to include("bar (1.3.0) requires foo < 2.0")
            expect(error.message).to include("bar (1.3.0) selected to satisfy: application requires bar ~> 1.3")
            expect(error.message).to include("available versions of `foo`: 1.5.0, 1.0.0")
          }
      end

      it "does not silently downgrade to an out-of-range version" do
        expect { planner.plan(foo: ">= 2.0") }
          .to raise_error(Dry::System::PluginPlanUnresolvableError, /foo/)
      end
    end

    context "when a required dependency has no candidates" do
      let(:candidates) {
        [descriptor(:foo, "1.0.0", dependencies: {bar: ">= 1.0"})]
      }

      it "raises an error pointing at the missing plugin" do
        expect { planner.plan(foo: ">= 1.0") }
          .to raise_error(Dry::System::PluginPlanUnresolvableError, /no candidate versions of `bar`/)
      end
    end

    context "determinism" do
      let(:candidates) {
        [
          descriptor(:foo, "1.0.0", dependencies: {bar: ">= 1.0"}),
          descriptor(:foo, "1.1.0"),
          descriptor(:bar, "1.0.0"),
          descriptor(:bar, "1.2.0")
        ]
      }

      it "returns the same plan regardless of candidate order" do
        requirements = {foo: ">= 1.0"}
        first = described_class.new(candidates: candidates).plan(requirements)
        shuffled = described_class.new(candidates: candidates.reverse.shuffle).plan(requirements)

        expect(shuffled.selections).to eq(first.selections)
      end
    end
  end

  describe "solving does not execute plugin code" do
    it "only reads descriptor attributes while planning" do
      probe = Object.new
      def probe.call(*) = raise("plugin code must not run during planning")

      candidates = [
        descriptor(:foo, "1.0.0", dependencies: {bar: ">= 1.0"}, metadata: probe),
        descriptor(:bar, "1.0.0", metadata: probe)
      ]
      planner = described_class.new(candidates: candidates)

      expect { planner.plan(foo: ">= 1.0") }.not_to raise_error
    end
  end

  describe "Plan#load!" do
    let(:candidates) {
      [
        descriptor(:foo, "1.0.0", dependencies: {bar: ">= 1.0"}),
        descriptor(:bar, "1.0.0", dependencies: {baz: ">= 1.0"}),
        descriptor(:baz, "1.0.0")
      ]
    }

    it "loads plugins in dependency order via the given loader" do
      loaded = []

      planner.plan(foo: ">= 1.0").load! { |descriptor| loaded << descriptor.name }

      expect(loaded).to eq(%i[baz bar foo])
    end

    it "accepts a callable loader" do
      loader = ->(descriptor) { (@loaded ||= []) << descriptor.name }
      planner.plan(foo: ">= 1.0").load!(loader)

      expect(@loaded).to eq(%i[baz bar foo])
    end

    it "requires a loader" do
      expect { planner.plan(foo: ">= 1.0").load! }
        .to raise_error(ArgumentError, /loader/)
    end
  end

  describe "#load" do
    it "plans and loads in one step" do
      candidates = [descriptor(:foo, "1.0.0")]
      planner = described_class.new(candidates: candidates)
      loaded = []

      planner.load({foo: ">= 1.0"}) { |descriptor| loaded << descriptor.name }

      expect(loaded).to eq(%i[foo])
    end
  end

  describe ".plan" do
    it "plans in one step" do
      candidates = [descriptor(:foo, "1.0.0")]

      plan = described_class.plan(candidates: candidates, requirements: {foo: ">= 1.0"})

      expect(plan.version_of(:foo)).to eq(Gem::Version.new("1.0.0"))
    end
  end
end
