# frozen_string_literal: true

RSpec.describe "Lifecycles" do
  let(:container) {
    Class.new(Dry::System::Container) do
      register("counter", lifecycle: :singleton) { Object.new }
      register("request", lifecycle: :scoped) { Object.new }
      register("per_call", lifecycle: :transient) { Object.new }
    end
  }

  describe "singleton" do
    it "resolves a single shared instance" do
      expect(container["counter"]).to be container["counter"]
    end

    it "is built lazily, on first resolution" do
      builds = 0
      container.register("lazy_singleton", lifecycle: :singleton) { builds += 1 }

      expect(builds).to eq 0
      container["lazy_singleton"]
      container["lazy_singleton"]
      expect(builds).to eq 1
    end

    it "accepts the lifecycle as a string" do
      container.register("string_singleton", lifecycle: "singleton") { Object.new }
      expect(container["string_singleton"]).to be container["string_singleton"]
    end

    it "raises for an invalid lifecycle" do
      expect {
        container.register("bad", lifecycle: :nope) { Object.new }
      }.to raise_error(Dry::System::InvalidLifecycleError)
    end

    it "keeps working after finalization" do
      container.finalize!
      expect(container["counter"]).to be container["counter"]
    end
  end

  describe "transient" do
    it "builds a new instance on every resolution" do
      expect(container["per_call"]).not_to be container["per_call"]
    end
  end

  describe "scoped" do
    it "cannot be resolved outside of a scope" do
      expect { container["request"] }.to raise_error(
        Dry::System::ScopedComponentWithoutScopeError, /"request"/
      )
    end

    it "shares a single instance within a scope" do
      first = second = nil
      container.scope do
        first = container["request"]
        second = container["request"]
      end
      expect(first).to be second
    end

    it "creates a fresh instance for each independent scope" do
      first = container.scope { container["request"] }
      second = container.scope { container["request"] }
      expect(first).not_to be second
    end

    it "returns the block's return value" do
      expect(container.scope { :done }).to eq :done
    end

    it "yields a scope with depth and root? metadata" do
      container.scope do |outer|
        expect(outer).to be_root
        expect(outer.depth).to eq 0

        container.scope do |inner|
          expect(inner).not_to be_root
          expect(inner.depth).to eq 1
        end
      end
    end

    describe "nested scopes" do
      it "reuses an instance created by an enclosing scope" do
        container.scope do
          outer_instance = container["request"]

          container.scope do
            expect(container["request"]).to be outer_instance
          end

          expect(container["request"]).to be outer_instance
        end
      end

      it "gives the inner scope ownership when no enclosing scope created one" do
        released = []
        container.register("inner_owned", lifecycle: :scoped,
                          release: ->(inst) { released << inst }) { Object.new }

        inner_instance = nil
        outer_instance = nil

        container.scope do
          container.scope do
            inner_instance = container["inner_owned"]
          end
          # The inner scope owned and released it; the outer scope gets a fresh one
          outer_instance = container["inner_owned"]
        end

        expect(inner_instance).not_to be outer_instance
        expect(released).to eq [inner_instance, outer_instance]
      end
    end

    describe "isolation" do
      it "does not share instances across threads" do
      seen = Queue.new

      container.scope do
        parent_instance = container["request"]

        thread = Thread.new {
          begin
            container["request"]
          rescue Dry::System::ScopedComponentWithoutScopeError => e
            seen << e
          end
        }

        error = seen.pop
        thread.join

        expect(error).to be_a(Dry::System::ScopedComponentWithoutScopeError)
        expect(parent_instance).to be container["request"]
      end
    end

      it "does not share instances across fibers" do
        seen = nil

        container.scope do
          Fiber.new {
            begin
              container["request"]
            rescue Dry::System::ScopedComponentWithoutScopeError => e
              seen = e
            end
          }.resume
        end

        expect(seen).to be_a(Dry::System::ScopedComponentWithoutScopeError)
      end

      it "carries an explicit scope into a fiber with Scope#activate" do
        inside = nil
        outer_instance = nil

        container.scope do |scope|
          outer_instance = container["request"]

          Fiber.new {
            scope.activate {
              inside = container["request"]
            }
          }.resume
        end

        expect(inside).to be outer_instance
      end
    end

    describe "release" do
      it "releases owned components in the reverse order of creation" do
      order = []
      container.register("first", lifecycle: :scoped,
                        release: ->(inst) { order << [:first, inst] }) { Object.new }
      container.register("second", lifecycle: :scoped,
                        release: ->(inst) { order << [:second, inst] }) { Object.new }

      container.scope do
        container["first"]
        container["second"]
        expect(order).to be_empty
      end

      expect(order.map(&:first)).to eq %i[second first]
    end

      it "calls #close when no release hook is configured" do
      released = []
      closable = Class.new {
        define_method(:close) { released << self }
      }
      container.register("closable", lifecycle: :scoped) { closable.new }

      instance = container.scope { container["closable"] }
      expect(released).to eq [instance]
    end

      it "releases even when the scope block raises, and re-raises the error" do
      released = false
      container.register("boom_scoped", lifecycle: :scoped,
                        release: ->(_) { released = true }) { Object.new }

      expect {
        container.scope do
          container["boom_scoped"]
          raise "scope failure"
        end
      }.to raise_error(RuntimeError, "scope failure")

      expect(released).to be true
    end

      it "only releases instances owned by the closing scope" do
      releases = []
      container.register("owned", lifecycle: :scoped,
                        release: ->(inst) { releases << inst }) { Object.new }

      outer_instance = nil
      container.scope do
        outer_instance = container["owned"]
        container.scope do
          # reuses the outer instance; the inner scope owns nothing
          container["owned"]
        end
        expect(releases).to be_empty
      end
      expect(releases).to eq [outer_instance]
    end

      it "runs release callbacks registered with on_release" do
      events = []
      container.scope do |scope|
        scope.on_release { events << :callback }
        events << :body
      end
      expect(events).to eq %i[body callback]
    end

      it "attempts every release even when one raises, raising the first error" do
      container.register("bad_release", lifecycle: :scoped,
                        release: ->(_) { raise "first failure" }) { Object.new }
      container.register("good_release", lifecycle: :scoped,
                        release: ->(_) {}) { Object.new }

      expect {
        container.scope do
          container["good_release"]
          container["bad_release"]
        end
      }.to raise_error(RuntimeError, "first failure")
    end
    end
  end

  describe "captive dependencies" do
    it "rejects a singleton capturing a scoped dependency, with the chain" do
      inject = container.injector
      service_class = Class.new {
        include inject["request"]
      }
      container.register("service", lifecycle: :singleton) { service_class.new }

      expect { container["service"] }.to raise_error(
        Dry::System::CaptiveDependencyError
      ) { |error|
        expect(error.message).to include "service (singleton)"
        expect(error.message).to include "request (scoped)"
        expect(error.message).to include "service (singleton) -> request (scoped)"
      }
    end

    it "rejects a singleton capturing a transient dependency" do
      inject = container.injector
      service_class = Class.new {
        include inject["per_call"]
      }
      container.register("service", lifecycle: :singleton) { service_class.new }

      expect { container["service"] }.to raise_error(Dry::System::CaptiveDependencyError)
    end

    it "rejects a scoped component capturing a transient dependency" do
      inject = container.injector
      service_class = Class.new {
        include inject["per_call"]
      }
      container.register("service", lifecycle: :scoped) { service_class.new }

      expect {
        container.scope { container["service"] }
      }.to raise_error(Dry::System::CaptiveDependencyError)
    end

    it "allows a scoped component to depend on a singleton" do
      inject = container.injector
      service_class = Class.new {
        include inject["counter"]
      }
      container.register("service", lifecycle: :scoped) { service_class.new }

      expect(container.scope { container["service"] }).to be_an_instance_of(service_class)
    end

    it "allows a transient to depend on anything available in the scope" do
      inject = container.injector
      service_class = Class.new {
        include inject["request", "counter"]
      }
      container.register("service", lifecycle: :transient) { service_class.new }

      instance = container.scope { container["service"] }
      expect(instance).to be_an_instance_of(service_class)
    end

    it "reports the dependency chain at the point the rule is broken" do
      inject = container.injector
      level3_class = Class.new {
        include inject["request"]
      }
      container.register("level3", lifecycle: :transient) { level3_class.new }
      level2_class = Class.new {
        include inject["level3"]
      }
      container.register("level2", lifecycle: :scoped) { level2_class.new }
      level1_class = Class.new {
        include inject["level2"]
      }
      container.register("level1", lifecycle: :singleton) { level1_class.new }

      expect { container["level1"] }.to raise_error(
        Dry::System::CaptiveDependencyError
      ) { |error|
        expect(error.message).to include(
          "level1 (singleton) -> level2 (scoped)"
        )
      }
    end

    it "reports the chain through valid intermediate dependencies" do
      inject = container.injector
      leaf_class = Class.new {
        include inject["request"]
      }
      container.register("leaf", lifecycle: :singleton) { leaf_class.new }
      mid_class = Class.new {
        include inject["leaf"]
      }
      container.register("mid", lifecycle: :singleton) { mid_class.new }
      owner_class = Class.new {
        include inject["mid"]
      }
      container.register("owner", lifecycle: :singleton) { owner_class.new }

      expect { container["owner"] }.to raise_error(
        Dry::System::CaptiveDependencyError
      ) { |error|
        expect(error.message).to include(
          "leaf (singleton) -> request (scoped)"
        )
      }
    end
  end

  describe "manual registrations" do
    it "treats a plain registration as a singleton value" do
      object = Object.new
      container.register("plain", object)
      expect(container["plain"]).to be object
    end

    it "supports a release symbol naming a method to call" do
      released = []
      closable = Class.new {
        define_method(:disconnect) { released << self }
      }
      container.register("conn", lifecycle: :scoped, release: :disconnect) {
        closable.new
      }
      instance = container.scope { container["conn"] }
      expect(released).to eq [instance]
    end

    it "releases singletons on shutdown, in reverse creation order" do
      events = []
      container.register("s1", lifecycle: :singleton,
                        release: ->(_) { events << :s1 }) { Object.new }
      container.register("s2", lifecycle: :singleton,
                        release: ->(_) { events << :s2 }) { Object.new }
      container["s1"]
      container["s2"]

      container.shutdown!
      expect(events).to eq %i[s2 s1]
    end
  end

  describe "legacy memoize option" do
    it "is still supported as a singleton lifecycle" do
      legacy = Class.new(Dry::System::Container) {
        register("old", memoize: true) { Object.new }
      }
      expect(legacy["old"]).to be legacy["old"]
    end
  end
end
