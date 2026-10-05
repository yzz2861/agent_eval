# frozen_string_literal: true

RSpec.describe "Provider dependencies (depends_on)" do
  subject(:system) { Test::Container }

  let(:log) { [] }

  before do
    class Test::Container < Dry::System::Container
      configure do |config|
        config.root = SPEC_ROOT.join("fixtures")
      end
    end
  end

  def define_provider(name, deps: [], fail_on_start: false, fail_on_stop: false)
    log = self.log

    system.register_provider(name) do
      depends_on(*deps)

      prepare do
        log << [:prepare, name]
      end

      start do
        log << [:start, name]
        raise "start failed for #{name}" if fail_on_start

        register(name, name)
      end

      stop do
        log << [:stop, name]
        raise "stop failed for #{name}" if fail_on_stop
      end
    end
  end

  describe "starting" do
    it "prepares and starts dependencies before their dependents" do
      define_provider(:db)
      define_provider(:client, deps: [:db])
      define_provider(:api, deps: [:client])

      system.start(:api)

      expect(log).to eq [
        [:prepare, :db], [:start, :db],
        [:prepare, :client], [:start, :client],
        [:prepare, :api], [:start, :api]
      ]
    end

    it "starts transitive dependencies" do
      define_provider(:db)
      define_provider(:client, deps: [:db])
      define_provider(:api, deps: [:client])

      system.start(:api)

      expect(system.providers[:db]).to be_started
      expect(system.providers[:client]).to be_started
      expect(system.providers[:api]).to be_started
    end

    it "prepares dependencies without starting them when preparing" do
      define_provider(:db)
      define_provider(:client, deps: [:db])

      system.prepare(:client)

      expect(log).to eq [[:prepare, :db], [:prepare, :client]]
    end

    it "starts all providers in dependency order on finalize!, regardless of registration order" do
      define_provider(:api, deps: [:client])
      define_provider(:db)
      define_provider(:client, deps: [:db])

      system.finalize!

      expect(log).to eq [
        [:prepare, :db], [:start, :db],
        [:prepare, :client], [:start, :client],
        [:prepare, :api], [:start, :api]
      ]
    end
  end

  describe "plan" do
    it "is inspectable and produced without side effects" do
      define_provider(:db)
      define_provider(:client, deps: [:db])
      define_provider(:api, deps: [:client])

      plan = system.providers.plan(:api)

      expect(plan).to be_a(Dry::System::ProviderPlan)
      expect(plan.names).to eq %i[db client api]
      expect(plan.providers.map(&:name)).to eq %i[db client api]
      expect(log).to be_empty
    end

    it "includes all providers when no names are given" do
      define_provider(:db)
      define_provider(:client, deps: [:db])

      expect(system.providers.plan.names).to eq %i[db client]
    end

    it "records the full execution order in events, including repeated start and shutdown" do
      define_provider(:db)
      define_provider(:client, deps: [:db])

      plan = system.providers.plan(:client)

      plan.start
      plan.start
      plan.shutdown

      expect(plan.events).to eq [
        [:start, :db], [:start, :client],
        [:start, :db], [:start, :client],
        [:stop, :client], [:stop, :db]
      ]
    end
  end

  describe "shutdown" do
    it "stops providers in reverse dependency order" do
      define_provider(:db)
      define_provider(:client, deps: [:db])
      define_provider(:api, deps: [:client])

      system.start(:api)
      log.clear

      system.shutdown!

      expect(log).to eq [[:stop, :api], [:stop, :client], [:stop, :db]]
    end

    it "continues stopping other providers when one fails and aggregates the errors" do
      define_provider(:db, fail_on_stop: true)
      define_provider(:client, deps: [:db])
      define_provider(:api, deps: [:client])

      system.start(:api)
      log.clear

      expect { system.shutdown! }.to raise_error(Dry::System::ProviderStopError) { |error|
        expect(error.errors.keys).to eq %i[db]
        expect(error.errors[:db].message).to eq "stop failed for db"
        expect(error.message).to include(":db")
      }

      expect(log).to eq [[:stop, :api], [:stop, :client], [:stop, :db]]
      expect(system.providers[:api]).to be_stopped
      expect(system.providers[:client]).to be_stopped
    end
  end

  describe "dependency errors" do
    it "raises on missing providers before any side effects" do
      define_provider(:api, deps: [:missing])

      expect { system.start(:api) }.to raise_error(
        Dry::System::ProviderDependencyNotFoundError,
        /Provider :api depends on :missing/
      )

      expect(log).to be_empty
    end

    it "raises on dependency cycles before any side effects" do
      define_provider(:a, deps: [:b])
      define_provider(:b, deps: [:a])

      expect { system.start(:a) }.to raise_error(
        Dry::System::ProviderDependencyCycleError,
        /:a => :b => :a/
      )

      expect(log).to be_empty
    end

    it "raises on self-dependencies" do
      define_provider(:a, deps: [:a])

      expect { system.start(:a) }.to raise_error(Dry::System::ProviderDependencyCycleError)

      expect(log).to be_empty
    end
  end

  describe "start failure" do
    it "stops only the providers started by the failed run, in reverse order" do
      define_provider(:db)
      define_provider(:client, deps: [:db])
      define_provider(:api, deps: [:client], fail_on_start: true)

      system.start(:db)
      log.clear

      expect { system.start(:api) }.to raise_error(RuntimeError, "start failed for api")

      expect(log).to eq [
        [:prepare, :client], [:start, :client],
        [:prepare, :api], [:start, :api],
        [:stop, :client]
      ]

      expect(system.providers[:db]).to be_started
      expect(system.providers[:db]).not_to be_stopped
      expect(system.providers[:client]).to be_stopped
    end

    it "raises an aggregated error when rollback stops also fail" do
      define_provider(:client, fail_on_stop: true)
      define_provider(:api, deps: [:client], fail_on_start: true)

      expect { system.start(:api) }.to raise_error(Dry::System::ProviderStopError) { |error|
        expect(error.errors.keys).to eq %i[client]
        expect(error.cause).to be_a(RuntimeError)
        expect(error.cause.message).to eq "start failed for api"
      }
    end
  end
end
