# frozen_string_literal: true

RSpec.describe Dry::System::Plugins::Planner do
  Plugin = Struct.new(
    :name, :version, :dependencies, :optional_dependencies,
    keyword_init: true
  ) do
    def self.loaded
      @loaded ||= []
    end

    def self.reset!
      @loaded = []
    end

    def load
      self.class.loaded << [name, version]
    end
  end

  let(:candidates) do
    [
      Plugin.new(
        name: :monitoring,
        version: "2.0.0",
        dependencies: {notifications: "~> 2.0"},
        optional_dependencies: {logging: ">= 2.0"}
      ),
      Plugin.new(
        name: :monitoring,
        version: "1.1.0",
        dependencies: {notifications: "~> 1.0"},
        optional_dependencies: {logging: ">= 1.0"}
      ),
      Plugin.new(name: :notifications, version: "2.0.0"),
      Plugin.new(name: :notifications, version: "1.0.0"),
      Plugin.new(name: :logging, version: "2.0.0"),
      Plugin.new(name: :logging, version: "1.0.0"),
      Plugin.new(
        name: :legacy,
        version: "1.0.0",
        dependencies: {notifications: "~> 1.0"},
        optional_dependencies: {logging: ">= 2.0"}
      )
    ]
  end

  let(:allowed) do
    {
      monitoring: ">= 1.0",
      notifications: ">= 1.0",
      logging: ">= 1.0"
    }
  end

  let(:planner) { described_class.new(candidates, allowed: allowed) }

  before { Plugin.reset! }

  describe "#plan" do
    it "selects the highest allowed plugins and their required dependencies" do
      plan = planner.plan(:monitoring)

      expect(plan.to_a.map { |plugin| [plugin.name, plugin.version] }).to contain_exactly(
        [:monitoring, "2.0.0"],
        [:notifications, "2.0.0"]
      )
    end

    it "does not select an optional dependency that was not requested" do
      plan = planner.plan(:monitoring)

      expect(plan.names).not_to include("logging")
    end

    it "constrains an optional dependency only when it is also selected" do
      plan = planner.plan(:monitoring, :logging)

      expect(plan.candidates.fetch("logging").version.to_s).to eq("2.0.0")
      expect(plan.names).to eq(%w[logging notifications monitoring])
    end

    it "keeps optional dependencies out of the required closure" do
      plan = planner.plan(:legacy)

      expect(plan.names).to eq(%w[notifications legacy])
    end

    it "backtracks when a higher candidate cannot satisfy its required dependencies" do
      backtrack_candidates = [
        Plugin.new(name: :app, version: "2.0.0", dependencies: {shared: ">= 2.0"}),
        Plugin.new(name: :app, version: "1.0.0", dependencies: {shared: ">= 1.0"}),
        Plugin.new(name: :shared, version: "1.0.0")
      ]

      plan = described_class.new(backtrack_candidates).plan(:app)

      expect(plan.to_a.map { |plugin| [plugin.name, plugin.version] }).to eq(
        [[:shared, "1.0.0"], [:app, "1.0.0"]]
      )
    end

    it "backtracks when an already selected optional dependency is incompatible" do
      backtrack_candidates = [
        Plugin.new(
          name: :app,
          version: "2.0.0",
          dependencies: {},
          optional_dependencies: {extra: ">= 2.0"}
        ),
        Plugin.new(
          name: :app,
          version: "1.0.0",
          dependencies: {},
          optional_dependencies: {extra: ">= 1.0"}
        ),
        Plugin.new(name: :extra, version: "1.0.0")
      ]

      plan = described_class.new(backtrack_candidates).plan(:app, :extra)

      expect(plan.to_a.map { |plugin| [plugin.name, plugin.version] }).to eq(
        [[:app, "1.0.0"], [:extra, "1.0.0"]]
      )
    end

    it "never selects a version outside the application's allowed range" do
      plan = planner.plan(
        :monitoring,
        allowed: {
          monitoring: "~> 1.0",
          notifications: "~> 1.0",
          logging: ">= 1.0"
        }
      )

      expect(plan.candidates.fetch("monitoring").version.to_s).to eq("1.1.0")
      expect(plan.candidates.fetch("notifications").version.to_s).to eq("1.0.0")
    end

    it "raises a conflict chain without silently using an out-of-range version" do
      expect {
        planner.plan(:monitoring, allowed: allowed.merge(notifications: "~> 3.0"))
      }.to raise_error(
        Dry::System::PluginResolutionError,
        a_string_including(":monitoring -> :notifications", "~> 3.0", "required by the application")
      )
    end

    it "reports the chain for a missing transitive dependency" do
      candidates << Plugin.new(
        name: :dashboard,
        version: "1.0.0",
        dependencies: {missing: ">= 1.0"}
      )

      expect { planner.plan(:dashboard) }.to raise_error(
        Dry::System::PluginResolutionError,
        "plugin :missing has no candidates (:dashboard -> :missing)"
      )
    end

    it "reports incompatible selected optional dependencies with the dependency chain" do
      expect {
        planner.plan(:legacy, :logging, allowed: allowed.merge(logging: "~> 1.0"))
      }.to raise_error(
        Dry::System::PluginResolutionError,
        a_string_including(":legacy -> :logging", ">= 2.0", "optional constraint from :legacy")
      )
    end

    it "applies optional constraints when the optional plugin is selected first" do
      ordered_candidates = [
        Plugin.new(
          name: :app,
          version: "2.0.0",
          dependencies: {},
          optional_dependencies: {extra: ">= 2.0"}
        ),
        Plugin.new(name: :extra, version: "1.0.0")
      ]

      expect {
        described_class.new(ordered_candidates).plan(:app, :extra)
      }.to raise_error(
        Dry::System::PluginResolutionError,
        a_string_including(":app -> :extra", ">= 2.0", "optional constraint from :app")
      )
    end

    it "reports circular dependencies" do
      candidates << Plugin.new(name: :alpha, version: "1.0.0", dependencies: {beta: ">= 1.0"})
      candidates << Plugin.new(name: :beta, version: "1.0.0", dependencies: {alpha: ">= 1.0"})

      expect { planner.plan(:alpha) }.to raise_error(
        Dry::System::PluginResolutionError,
        "circular plugin dependency: :alpha -> :beta -> :alpha"
      )
    end

    it "backtracks when only a higher candidate forms a circular dependency" do
      backtrack_candidates = [
        Plugin.new(name: :alpha, version: "2.0.0", dependencies: {beta: ">= 1.0"}),
        Plugin.new(name: :alpha, version: "1.0.0", dependencies: {}),
        Plugin.new(name: :beta, version: "1.0.0", dependencies: {alpha: ">= 2.0"})
      ]

      plan = described_class.new(backtrack_candidates).plan(:alpha)

      expect(plan.to_a.map { |plugin| [plugin.name, plugin.version] }).to eq(
        [[:alpha, "1.0.0"]]
      )
    end

    it "does not execute plugin code while solving" do
      plan = planner.plan(:monitoring, :logging)

      expect(Plugin.loaded).to be_empty
      expect(plan).to be_an_instance_of(described_class::Plan)
    end

    it "accepts hash-shaped plugin descriptors" do
      hash_candidates = [
        {
          name: :web,
          version: "1.0.0",
          dependencies: {core: "~> 1.0"},
          optional_dependencies: {debug: ">= 1.0"}
        },
        {name: :core, version: "1.2.0"},
        {name: :debug, version: "1.5.0"}
      ]
      loaded_plugins = []

      described_class.new(hash_candidates).plan(:web, :debug).load do |plugin|
        loaded_plugins << plugin[:name]
      end

      expect(loaded_plugins).to eq(%i[core debug web])
    end

    it "accepts dependency names without version constraints" do
      array_candidates = [
        {name: :web, version: "1.0.0", dependencies: [:core], optional_dependencies: [:debug]},
        {name: :core, version: "1.0.0"},
        {name: :debug, version: "1.0.0"}
      ]

      plan = described_class.new(array_candidates).plan(:web, :debug)

      expect(plan.names).to eq(%w[core debug web])
    end
  end

  describe "#load" do
    it "loads the planned dependencies before their dependents" do
      loaded_plugins = []
      planner.load(:monitoring, :logging) { |plugin| loaded_plugins << plugin.name }

      expect(loaded_plugins).to eq(%i[logging notifications monitoring])
    end

    it "uses the descriptor's load method when no loader is given" do
      planner.load(:monitoring, :logging)

      expect(Plugin.loaded).to eq(
        [
          [:logging, "2.0.0"],
          [:notifications, "2.0.0"],
          [:monitoring, "2.0.0"]
        ]
      )
    end
  end
end
