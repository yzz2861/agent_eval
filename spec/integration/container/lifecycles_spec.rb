# frozen_string_literal: true

RSpec.describe "Container / Component lifecycles" do
  subject(:container) {
    Class.new(Dry::System::Container) do
      configure do |config|
        config.name = :test
      end
    end
  }

  describe "singleton lifecycle" do
    it "resolves the same instance on every resolution" do
      container.register("app", lifecycle: :singleton) { Object.new }

      expect(container["app"]).to be container["app"]
    end

    it "shares the instance across scopes" do
      container.register("app", lifecycle: :singleton) { Object.new }

      instance = container["app"]

      container.scoped do
        expect(container["app"]).to be instance
      end
    end

    it "is equivalent to memoize: true" do
      container.register("app", lifecycle: :singleton) { Object.new }

      expect(container._container["app"].options[:memoize]).to be true
    end
  end

  describe "transient lifecycle" do
    it "resolves a new instance on every resolution" do
      container.register("operation", lifecycle: :transient) { Object.new }

      expect(container["operation"]).not_to be container["operation"]
    end

    it "resolves a new instance even within a scope" do
      container.register("operation", lifecycle: :transient) { Object.new }

      container.scoped do
        expect(container["operation"]).not_to be container["operation"]
      end
    end
  end

  describe "scoped lifecycle" do
    it "resolves the same instance within a scope" do
      container.register("request_store", lifecycle: :scoped) { Object.new }

      container.scoped do
        expect(container["request_store"]).to be container["request_store"]
      end
    end

    it "resolves different instances in different scopes" do
      container.register("request_store", lifecycle: :scoped) { Object.new }

      first = container.scoped { container["request_store"] }
      second = container.scoped { container["request_store"] }

      expect(first).not_to be second
    end

    it "raises NoActiveScopeError when resolved without an active scope" do
      container.register("request_store", lifecycle: :scoped) { Object.new }

      expect { container["request_store"] }.to raise_error(
        Dry::System::NoActiveScopeError,
        /request_store.*no scope is active.*MyContainer.scoped/
      )
    end

    it "accepts the lifecycle given as a string" do
      container.register("request_store", lifecycle: "scoped") { Object.new }

      container.scoped do
        expect(container["request_store"]).to be container["request_store"]
      end
    end
  end

  describe "lifecycle option validation" do
    it "raises InvalidLifecycleError for an unknown lifecycle" do
      expect {
        container.register("app", lifecycle: :eternal) { Object.new }
      }.to raise_error(
        Dry::System::InvalidLifecycleError,
        /Invalid lifecycle :eternal for "app"/,
      )
    end

    it "raises ArgumentError when registering a scoped component with a pre-built value" do
      expect {
        container.register("request_store", Object.new, lifecycle: :scoped)
      }.to raise_error(ArgumentError, /must be registered with a block/)
    end

    it "raises ArgumentError when registering a transient component with a pre-built value" do
      expect {
        container.register("operation", Object.new, lifecycle: :transient)
      }.to raise_error(ArgumentError, /must be registered with a block/)
    end

    it "allows registering a singleton component with a pre-built value" do
      container.register("app", Object.new, lifecycle: :singleton)

      expect(container["app"]).to be container["app"]
    end

    it "raises ArgumentError for conflicting lifecycle and memoize options" do
      expect {
        container.register("app", lifecycle: :singleton, memoize: false) { Object.new }
      }.to raise_error(ArgumentError, /Conflicting options/)

      expect {
        container.register("op", lifecycle: :transient, memoize: true) { Object.new }
      }.to raise_error(ArgumentError, /Conflicting options/)
    end
  end

  describe "default lifecycles" do
    it "treats memoized components as singletons" do
      container.register("app", memoize: true) { Object.new }

      expect(container["app"]).to be container["app"]
    end

    it "treats plain block registrations as transient" do
      container.register("operation") { Object.new }

      expect(container["operation"]).not_to be container["operation"]
    end
  end

  describe "scoped components registered via providers" do
    it "resolves one instance per scope" do
      container = Class.new(Dry::System::Container) do
        register_provider :request_store do
          start do
            register "request_store", lifecycle: :scoped do
              Object.new
            end
          end
        end
      end

      container.start :request_store

      first = container.scoped { container["request_store"] }
      second = container.scoped { container["request_store"] }

      expect(first).not_to be second
    end
  end
end
