# frozen_string_literal: true

require "ostruct"

RSpec.describe "Providers / Explicit dependencies" do
  subject(:container) { container_class }

  let(:log) { [] }

  let(:container_class) do
    log = self.log

    Class.new(Dry::System::Container) do
      register_provider(:logger) do
        prepare { log << "logger.prepare" }
        start { log << "logger.start"; register(:logger, :logger_started) }
        stop { log << "logger.stop" }
      end

      register_provider(:db) do
        depends_on :logger

        prepare { log << "db.prepare" }
        start { log << "db.start"; register(:db, :db_started) }
        stop { log << "db.stop" }
      end

      register_provider(:client) do
        depends_on :db

        prepare { log << "client.prepare" }
        start { log << "client.start"; register(:client, :client_started) }
        stop { log << "client.stop" }
      end
    end
  end

  describe "provider plan" do
    it "is viewable before any side effects" do
      plan = container.provider_plan(:client)

      expect(plan.start_order).to eq %i[logger db client]
      expect(plan.stop_order).to eq %i[client db logger]
      expect(plan.roots).to eq [:client]
      expect(plan.names).to eq %i[logger db client]
      expect(plan.to_s).to eq "logger -> db -> client"
      expect(log).to eq []
    end

    it "plans all providers when no names are given" do
      expect(container.provider_plan.start_order).to eq %i[logger db client]
    end

    it "accepts multiple root names and merges their dependencies" do
      plan = container.provider_plan(:client, :logger)

      expect(plan.start_order).to eq %i[logger db client]
    end

    it "is enumerable over providers in start order" do
      expect(container.provider_plan(:client).map(&:name)).to eq %i[logger db client]
    end
  end

  describe "ordered lifecycle" do
    it "prepares dependencies in order" do
      container.prepare(:client)

      expect(log).to eq ["logger.prepare", "db.prepare", "client.prepare"]
    end

    it "prepares and starts dependencies in order" do
      container.start(:client)

      expect(log).to eq [
        "logger.prepare", "logger.start",
        "db.prepare", "db.start",
        "client.prepare", "client.start"
      ]
    end

    it "stops in reverse dependency order on shutdown" do
      container.start(:client)
      container.shutdown!

      expect(log).to eq [
        "logger.prepare", "logger.start",
        "db.prepare", "db.start",
        "client.prepare", "client.start",
        "client.stop", "db.stop", "logger.stop"
      ]
    end

    it "does not stop providers that were only prepared" do
      container.prepare(:client)
      container.shutdown!

      expect(log).to eq ["logger.prepare", "db.prepare", "client.prepare"]
    end
  end

  describe "validation before side effects" do
    it "raises before side effects when a dependency is missing" do
      missing_container = Class.new(Dry::System::Container) do
        register_provider(:db) do
          depends_on :ghost

          prepare { raise "must not run" }
        end
      end

      expect { missing_container.start(:db) }.to raise_error(
        Dry::System::ProviderDependencyNotFoundError, /:ghost/
      )
      expect { missing_container.provider_plan(:db) }.to raise_error(
        Dry::System::ProviderDependencyNotFoundError, /:ghost/
      )
    end

    it "raises ProviderNotFoundError when the named provider does not exist" do
      expect { container.start(:nope) }.to raise_error(
        Dry::System::ProviderNotFoundError, /:nope/
      )
      expect(log).to eq []
    end

    it "detects a dependency cycle before side effects" do
      cycle_log = []
      cycle_container = Class.new(Dry::System::Container) do
        register_provider(:a) do
          depends_on :b
          prepare { cycle_log << :a }
        end
        register_provider(:b) do
          depends_on :a
        end
      end

      expect { cycle_container.provider_plan(:a) }.to raise_error(
        Dry::System::ProviderDependencyCycleError, /a -> b -> a/
      )
      expect { cycle_container.start(:a) }.to raise_error(
        Dry::System::ProviderDependencyCycleError
      )
      expect(cycle_log).to eq []
    end

    it "detects a longer dependency cycle before side effects" do
      cycle_container = Class.new(Dry::System::Container) do
        register_provider(:a) { depends_on :b }
        register_provider(:b) { depends_on :c }
        register_provider(:c) { depends_on :a }
      end

      expect { cycle_container.start(:a) }.to raise_error(
        Dry::System::ProviderDependencyCycleError, /a -> b -> c -> a/
      )
    end
  end

  describe "rollback on start failure" do
    let(:failing_container) do
      log = self.log

      Class.new(Dry::System::Container) do
        register_provider(:a) do
          start { log << "a.start" }
          stop { log << "a.stop" }
        end
        register_provider(:b) do
          depends_on :a
          start { log << "b.start"; raise "boom" }
          stop { log << "b.stop" }
        end
        register_provider(:c) do
          depends_on :b
          start { log << "c.start" }
        end
      end
    end

    it "stops only the providers started in the failed round, in reverse" do
      expect { failing_container.start(:c) }.to raise_error(RuntimeError, "boom")

      # :c never started, :b failed, :a started successfully and is rolled back
      expect(log).to eq ["a.start", "b.start", "a.stop"]
    end

    it "does not stop providers already running before the failed start" do
      failing_container.start(:a)
      log.clear

      expect { failing_container.start(:c) }.to raise_error(RuntimeError, "boom")

      expect(log).to eq ["b.start"]
      expect(failing_container.providers[:a]).to be_started
    end

    it "continues rollback even when a stop fails and re-raises the start error" do
      flaky = Class.new(Dry::System::Container) do
        register_provider(:a) do
          start {}
          stop { raise "stop boom" }
        end
        register_provider(:b) do
          depends_on :a
          start { raise "start boom" }
        end
      end

      expect { flaky.start(:b) }.to raise_error(RuntimeError, "start boom")

      events = flaky.lifecycle_events
      expect(events).to include(
        an_object_having_attributes(action: :rollback, provider: :a, status: :failed)
      )
    end
  end

  describe "shutdown failure aggregation" do
    it "continues stopping other providers and raises an aggregated error" do
      log = self.log
      flaky = Class.new(Dry::System::Container) do
        register_provider(:a) do
          start {}
          stop { raise "stop a" }
        end
        register_provider(:b) do
          depends_on :a
          start {}
          stop { raise "stop b" }
        end
        register_provider(:c) do
          depends_on :b
          start { log << "c.start" }
          stop { log << "c.stop" }
        end
      end

      flaky.start(:c)

      expect { flaky.shutdown! }.to raise_error(Dry::System::ProviderStopError) { |error|
        expect(error.failures.keys).to eq %i[b a]
      }

      # :c was still stopped even though :b and :a failed afterwards
      expect(log).to eq ["c.start", "c.stop"]
    end
  end

  describe "single provider stop" do
    it "re-raises a failing stop and records the failed event" do
      flaky = Class.new(Dry::System::Container) do
        register_provider(:a) do
          start {}
          stop { raise "stop a" }
        end
      end

      flaky.start(:a)

      expect { flaky.stop(:a) }.to raise_error(RuntimeError, "stop a")
      expect(flaky.lifecycle_events.last).to be_failed
    end
  end

  describe "lifecycle events" do
    it "records the complete execution order, including repeated starts" do
      container.start(:client)
      container.start(:db)

      events = container.lifecycle_events

      expect(events.map { |event| [event.action, event.provider, event.status] }).to eq [
        [:prepare, :logger, :run], [:start, :logger, :run],
        [:prepare, :db, :run], [:start, :db, :run],
        [:prepare, :client, :run], [:start, :client, :run],
        [:prepare, :logger, :skipped], [:start, :logger, :skipped],
        [:prepare, :db, :skipped], [:start, :db, :skipped]
      ]
    end

    it "records repeated shutdowns" do
      container.start(:db)
      container.shutdown!
      container.shutdown!

      shutdowns = container.lifecycle_events.select { |event| event.action == :shutdown }
      expect(shutdowns.map(&:status)).to eq %i[run run]

      stops = container.lifecycle_events.select { |event| event.action == :stop }
      expect(stops.map(&:provider)).to eq %i[client db logger client db logger]
      expect(stops.map(&:status)).to eq %i[skipped run run skipped skipped skipped]
    end
  end

  describe "finalization" do
    it "starts all providers in dependency order" do
      container.finalize!

      expect(log).to eq [
        "logger.prepare", "logger.start",
        "db.prepare", "db.start",
        "client.prepare", "client.start"
      ]
    end
  end

  describe "depends_on declaration styles" do
    it "accepts dependencies as a register_provider option" do
      styled = Class.new(Dry::System::Container) do
        register_provider(:a) do
          start {}
        end
        register_provider(:b, depends_on: :a) do
          start {}
        end
      end

      expect(styled.provider_plan(:b).start_order).to eq %i[a b]
      expect(styled.providers[:b].depends_on).to eq [:a]
    end

    it "accumulates multiple and repeated dependency declarations" do
      styled = Class.new(Dry::System::Container) do
        register_provider(:a) do; end
        register_provider(:b) do
          depends_on :a
          depends_on :a, :a
        end
      end

      expect(styled.providers[:b].depends_on).to eq [:a]
    end

    it "merges option dependencies with source block dependencies" do
      styled = Class.new(Dry::System::Container) do
        register_provider(:a) do; end
        register_provider(:b) do; end
        register_provider(:c, depends_on: :b) do
          depends_on :a
        end
      end

      expect(styled.provider_plan(:c).start_order).to eq %i[a b c]
    end
  end
end
