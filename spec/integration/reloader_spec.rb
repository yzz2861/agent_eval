# frozen_string_literal: true

RSpec.describe "Reloader / Generation scopes" do
  # Builds a reloader whose providers and components report their lifecycle and the
  # dependency edges they observe.
  #
  # Graph:
  #
  #   logger (provider)
  #     ^
  #   db (provider) -> logger
  #     ^
  #   users.create (component) -> db, logger
  def build_reloader
    events = []
    start_counts = Hash.new(0)
    stop_counts = Hash.new(0)

    # Each provider registration returns the *current* start block, which labels every
    # object it creates with the generation in which the provider is rebuilt. The block
    # closes over `db_version`, which the spec changes on reload.
    db_version = "v1"

    reloader = Dry::System::Reloader.new
    reloader.provider :logger do
      start do
        start_counts[:logger] += 1
        events << [:logger_start, target.generation_number]
        register("logger", {name: :logger})
      end

      stop do
        stop_counts[:logger] += 1
        events << [:logger_stop, target.generation_number]
      end
    end

    reloader.provider :db do
      start do
        start_counts[:db] += 1
        events << [:db_start, target.generation_number, db_version]
        register("db", {name: :db, version: db_version, logger: target["logger"]})
      end

      stop do
        stop_counts[:db] += 1
        events << [:db_stop, target.generation_number, db_version]
      end
    end

    reloader.component "users.create" do |generation|
      db = generation["db"]
      {
        db: db,
        logger: generation["logger"],
        # Capture the db version so specs can assert which generation built this object.
        db_version: db[:version]
      }
    end

    # A component that only depends on the logger, which must be carried across a
    # db-only reload without rebuilding.
    reloader.component "stats.summarize" do |generation|
      {logger: generation["logger"]}
    end

    {reloader: reloader, events: events, start_counts: start_counts,
     stop_counts: stop_counts, set_db_version: ->(value) { db_version = value }}
  end

  describe "generation pinning" do
    it "resolves from the generation current when the scope opened, across a reload" do
      setup = build_reloader
      reloader = setup[:reloader]

      in_flight = nil
      entered = Thread::Queue.new
      release = Thread::Queue.new

      # First controlled thread: an in-flight request opens generation 1 and blocks in
      # the middle of its work while a reload happens.
      old_thread = Thread.new do
        reloader.with_generation do |scope|
          service = scope["users.create"]
          in_flight = service
          entered << true
          release.pop
          service
        end
      end

      entered.pop

      expect(in_flight.fetch(:db_version)).to eq("v1")
      expect(reloader.generation_number).to eq(1)

      setup[:set_db_version].call("v2")
      reloader.reload(changed: "db")

      expect(reloader.generation_number).to eq(2)
      setup[:stop_counts].values.each { |count| expect(count).to be_zero }

      # Second controlled thread: new work uses generation 2 and its rebuilt db.
      new_service = nil
      new_thread = Thread.new do
        reloader.with_generation do |scope|
          expect(scope.generation_number).to eq(2)
          new_service = scope["users.create"]
        end
      end
      new_thread.join

      expect(new_service.fetch(:db_version)).to eq("v2")
      expect(new_service.fetch(:db)).not_to be(in_flight.fetch(:db))
      expect(new_service.fetch(:logger)).to be(in_flight.fetch(:logger))

      # The in-flight request still resolves additional dependencies from generation 1.
      expect(old_thread.status).to eq("sleep")

      release << true
      old_result = old_thread.value

      expect(old_result).to be(in_flight)
      expect(old_result.fetch(:db_version)).to eq("v1")
    end

    it "never lets one object mix two generations of dependencies" do
      setup = build_reloader
      reloader = setup[:reloader]

      v1_service = reloader.with_generation { |scope| scope["users.create"] }

      setup[:set_db_version].call("v2")
      reloader.reload(changed: "db")

      v2_service = reloader.with_generation { |scope| scope["users.create"] }

      expect(v1_service.fetch(:db_version)).to eq("v1")
      expect(v2_service.fetch(:db_version)).to eq("v2")
      expect(v1_service.fetch(:db)).not_to be(v2_service.fetch(:db))
      # The db itself captured its logger when its provider started; the v2 db must
      # hold the logger from generation 2's graph (here shared with generation 1).
      expect(v2_service.fetch(:db).fetch(:logger)).to be(v2_service.fetch(:logger))
      expect(v1_service.fetch(:db).fetch(:logger)).to be(v1_service.fetch(:logger))
    end
  end

  describe "dependency-directed rebuilds" do
    it "rebuilds the changed provider and its actual dependents, carrying over the rest" do
      setup = build_reloader
      reloader = setup[:reloader]

      reloader.with_generation do |scope|
        scope["users.create"]
        scope["stats.summarize"]
      end

      logger = reloader["logger"]
      stats = reloader["stats.summarize"]

      setup[:set_db_version].call("v2")
      reloader.reload(changed: "db")

      expect(reloader["logger"]).to be(logger)
      # stats.summarize only depends on logger, so its registration is carried over
      # unchanged and is the exact same object.
      expect(reloader["stats.summarize"]).to be(stats)
      expect(reloader["users.create"].fetch(:db_version)).to eq("v2")

      expect(setup[:start_counts]).to eq(logger: 1, db: 2)
    end

    it "restarts providers that depend on a changed component" do
      setup = build_reloader
      reloader = setup[:reloader]

      reloaded = false

      reloader.with_generation { |scope| scope["db"] }

      # Change the logger definition; db starts after resolving logger, so db depends on
      # it and must restart. Replace the provider blocks through the reload DSL.
      reloader.reload do
        provider :logger do
          start do
            setup[:start_counts][:logger] += 1
            register("logger", {name: :logger, fresh: true})
          end

          stop { setup[:stop_counts][:logger] += 1 }
        end

        provider :db do
          start do
            setup[:start_counts][:db] += 1
            register("db", {name: :db, logger: target["logger"]})
          end

          stop { setup[:stop_counts][:db] += 1 }
        end
        reloaded = true
      end

      expect(reloaded).to be(true)
      expect(reloader["db"].fetch(:logger)).to eq(name: :logger, fresh: true)
      expect(setup[:start_counts]).to eq(logger: 2, db: 2)
    end
  end

  describe "failure recovery" do
    it "keeps the previous generation when a provider fails to start" do
      setup = build_reloader
      reloader = setup[:reloader]

      service = reloader.with_generation { |scope| scope["users.create"] }

      expect {
        reloader.reload do
          provider :db do
            start { raise "cannot start db" }
            stop { }
          end
        end
      }.to raise_error(Dry::System::ReloadFailedError, /cannot start db/)

      expect(reloader.generation_number).to eq(1)
      expect(reloader["users.create"]).to be(service)
      expect(setup[:start_counts]).to eq(logger: 1, db: 1)
      expect(setup[:stop_counts].values).to all(eq(0))
    end

    it "keeps the previous generation when a component fails to build" do
      setup = build_reloader
      reloader = setup[:reloader]

      reloader.with_generation { |scope| scope["users.create"] }

      expect {
        reloader.reload do
          component("users.create") { |_| raise "cannot build users.create" }
        end
      }.to raise_error(Dry::System::ReloadFailedError, /cannot build users.create/)

      expect(reloader.generation_number).to eq(1)
      expect(reloader["users.create"].fetch(:db_version)).to eq("v1")
      expect(setup[:stop_counts].values).to all(eq(0))
    end

    it "supports a successful reload after a failed one" do
      setup = build_reloader
      reloader = setup[:reloader]

      reloader.with_generation { |scope| scope["users.create"] }

      expect {
        reloader.reload do
          provider :db do
            start { raise "temporary failure" }
            stop { }
          end
        end
      }.to raise_error(Dry::System::ReloadFailedError)

      setup[:set_db_version].call("v2")
      number = reloader.reload(changed: "db")

      expect(number).to eq(2)
      expect(reloader["users.create"].fetch(:db_version)).to eq("v2")
    end
  end

  describe "provider shutdown" do
    it "stops a superseded provider only after its last generation's scope closes" do
      setup = build_reloader
      reloader = setup[:reloader]

      old_scope = reloader.open_generation
      old_scope["users.create"]

      setup[:set_db_version].call("v2")
      reloader.reload(changed: "db")

      expect(setup[:stop_counts][:db]).to eq(0)

      old_scope.close!

      expect(setup[:stop_counts][:db]).to eq(1)
      # The logger was carried into generation 2 and is still running.
      expect(setup[:stop_counts][:logger]).to eq(0)

      reloader.shutdown!

      expect(setup[:stop_counts][:logger]).to eq(1)
    end

    it "stops every distinct provider instance exactly once over several reloads" do
      setup = build_reloader
      reloader = setup[:reloader]

      scope = reloader.open_generation
      scope["users.create"]

      setup[:set_db_version].call("v2")
      reloader.reload(changed: "db")
      scope.close!

      setup[:set_db_version].call("v3")
      reloader.reload(changed: "db")
      reloader.shutdown!

      # Three db generations (v1, v2, v3), each stopped once; the logger was shared by
      # all generations and stopped once.
      expect(setup[:stop_counts]).to eq(logger: 1, db: 3)
    end

    it "stops a generation with no open scopes as soon as it is superseded" do
      setup = build_reloader
      reloader = setup[:reloader]

      # Resolve, then let the scope close: subsequent generations have no open scopes
      # when they are themselves superseded and must be released immediately.
      reloader.with_generation { |scope| scope["users.create"] }

      setup[:set_db_version].call("v2")
      reloader.reload(changed: "db")
      expect(setup[:stop_counts][:db]).to eq(1)

      setup[:set_db_version].call("v3")
      reloader.reload(changed: "db")
      expect(setup[:stop_counts][:db]).to eq(2)

      reloader.shutdown!
      expect(setup[:stop_counts][:db]).to eq(3)
      expect(setup[:stop_counts][:logger]).to eq(1)
    end

    it "stops providers started by a discarded (failed) reload" do
      setup = build_reloader
      reloader = setup[:reloader]

      reloader.with_generation { |scope| scope["users.create"] }

      expect {
        reloader.reload do
          provider :db do
            start do
              register("db", {logger: target["logger"], cache: target["cache"]})
            end

            stop { }
          end

          provider :cache do
            start { register("cache", Object.new) }
            stop { setup[:stop_counts][:cache] += 1 }
          end

          component("users.create") do |generation|
            generation["cache"]
            raise "fail after cache started"
          end
        end
      }.to raise_error(Dry::System::ReloadFailedError)

      expect(setup[:stop_counts][:cache]).to eq(1)
      expect(reloader.generation_number).to eq(1)
    end
  end

  describe "scopes" do
    it "raises when resolving from a closed scope" do
      reloader = Dry::System::Reloader.new
      reloader.component("thing") { :thing }

      scope = reloader.open_generation
      expect(scope["thing"]).to eq(:thing)
      scope.close!

      expect(scope).to be_closed
      expect { scope["thing"] }.to raise_error(Dry::System::ScopeClosedError)
    end

    it "closes the scope even when the wrapped block raises" do
      reloader = Dry::System::Reloader.new
      reloader.component("thing") { :thing }

      scope = nil
      expect {
        reloader.with_generation do |opened|
          scope = opened
          raise "boom"
        end
      }.to raise_error(RuntimeError, "boom")

      expect(scope).to be_closed
    end

    it "is safe under concurrent scopes and reloads" do
      setup = build_reloader
      reloader = setup[:reloader]

      errors = Thread::Queue.new
      running = true

      workers = Array.new(4) do |worker_index|
        Thread.new do
          while running
            reloader.with_generation do |scope|
              service = scope["users.create"]
              logger = scope["logger"]
              # Within one generation the db and the service share the logger the
              # scope resolved: no mixing of generations.
              unless service.fetch(:logger).equal?(logger) &&
                  service.fetch(:db).fetch(:logger).equal?(logger)
                errors << "worker #{worker_index}: mixed generations"
              end
              sleep(rand * 0.002)
              # The pinned generation must not change underfoot.
              unless scope["users.create"].fetch(:db_version) == service.fetch(:db_version)
                errors << "worker #{worker_index}: generation changed mid-request"
              end
            rescue StandardError => error
              errors << "#{error.class}: #{error.message}"
            end
          end
        end
      end

      reloader_thread = Thread.new do
        versions = ("v2".."v7").to_a
        loop do
          version = versions.shift or break
          setup[:set_db_version].call(version)
          reloader.reload(changed: "db")
          sleep(rand * 0.002)
        end
      end

      reloader_thread.join
      running = false
      workers.each(&:join)

      expect(Array.new(errors.size) { errors.pop }).to be_empty

      reloader.shutdown!

      # Seven db builds (v1..v7), each stopped exactly once; the shared logger once.
      expect(setup[:stop_counts][:db]).to eq(7)
      expect(setup[:stop_counts][:logger]).to eq(1)
    end
  end
end
