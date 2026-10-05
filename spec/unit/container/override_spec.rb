# frozen_string_literal: true

require "dry/system/container"

RSpec.describe Dry::System::Container, ".override" do
  subject(:container) { Test::Container }

  let(:substitute) { Object.new }

  before do
    Test::Client = Class.new

    Test::Container = Class.new(Dry::System::Container) do
      register "client", memoize: true do
        Test::Client.new
      end

      register "metrics", memoize: true do
        Object.new
      end
    end

    Test::Inject = Test::Container.injector

    Test::Service = Class.new do
      include Test::Inject["client"]
    end

    Test::Container.register "service", memoize: true do
      Test::Service.new
    end
  end

  it "requires a block" do
    expect { container.override("client", substitute) }.to raise_error(ArgumentError, /block/)
  end

  it "requires a substitute when a single key is given" do
    expect { container.override("client") {} }.to raise_error(ArgumentError, /substitute/)
  end

  it "returns the block's return value" do
    expect(container.override("client", substitute) { :result }).to be :result
  end

  it "rebuilds already-memoized dependent components on top of the substitute" do
    # Build (and memoize) the upper-level component before the override begins
    client_before = container["client"]
    service_before = container["service"]

    expect(service_before.client).to be client_before

    container.override("client", substitute) do
      expect(container["client"]).to be substitute

      scoped_service = container["service"]
      expect(scoped_service).not_to be service_before
      expect(scoped_service.client).to be substitute

      # Rebuilt components are memoized for the rest of the scope
      expect(container["service"]).to be scoped_service
    end

    # The container's own memoized components are left untouched
    expect(container["client"]).to be client_before
    expect(container["service"]).to be service_before
  end

  it "does not populate the container's own memoized cache" do
    scoped_service = nil

    container.override("client", substitute) do
      scoped_service = container["service"]
    end

    expect(container["service"]).not_to be scoped_service
    expect(container["service"].client).to be_a Test::Client
  end

  it "applies only within the current thread" do
    client_before = container["client"]

    container.override("client", substitute) do
      expect(Thread.new { container["client"] }.value).to be client_before
      expect(container["client"]).to be substitute
    end
  end

  it "restores the enclosing scope's graph when a nested override exits" do
    outer_substitute = Object.new
    inner_substitute = Object.new

    container.override("client", outer_substitute) do
      outer_service = container["service"]
      expect(outer_service.client).to be outer_substitute

      container.override("client", inner_substitute) do
        expect(container["client"]).to be inner_substitute
        expect(container["service"].client).to be inner_substitute
      end

      expect(container["client"]).to be outer_substitute
      expect(container["service"]).to be outer_service
    end
  end

  it "discards only the scope's own state when building a component fails" do
    Test::Container.register "failing", memoize: true do
      raise "boom"
    end

    service_before = container["service"]

    expect {
      container.override("client", substitute) do
        container["service"]
        container["failing"]
      end
    }.to raise_error(RuntimeError, "boom")

    # The container's own graph is untouched by the failed scope
    expect(container["service"]).to be service_before

    # A later scope starts from a clean slate
    container.override("client", substitute) do
      expect(container["service"].client).to be substitute
    end
  end

  it "accepts nil and false as substitutes" do
    container.override("client", nil) do
      expect(container["client"]).to be_nil
      expect(container["service"].client).to be_nil
    end

    container.override("client", false) do
      expect(container["client"]).to be false
      expect(container["service"].client).to be false
    end

    expect(container["client"]).to be_a Test::Client
  end

  it "accepts a hash of keys to substitutes" do
    metrics_substitute = Object.new

    container.override("client" => substitute, "metrics" => metrics_substitute) do
      expect(container["client"]).to be substitute
      expect(container["metrics"]).to be metrics_substitute
      expect(container["service"].client).to be substitute
    end
  end

  it "raises a KeyError for unknown keys within the scope" do
    container.override("client", substitute) do
      expect { container["unknown"] }.to raise_error(Dry::Core::Container::KeyError, /unknown/)
    end
  end
end

RSpec.describe Dry::System::Container, ".override with auto-registered components" do
  subject(:container) { Test::Container }

  let(:substitute) { Object.new }

  before do
    Test::Container = Class.new(Dry::System::Container) do
      configure do |config|
        config.root = SPEC_ROOT.join("fixtures/scoped_override").realpath
        config.component_dirs.add "lib" do |dir|
          dir.memoize = true
        end
      end
    end

    Test::Inject = Test::Container.injector
  end

  it "rebuilds components already memoized before the override" do
    service_before = container["test.service"]
    expect(service_before.client).to be_a Test::Client

    container.override("test.client", substitute) do
      expect(container["test.client"]).to be substitute

      scoped_service = container["test.service"]
      expect(scoped_service).not_to be service_before
      expect(scoped_service.client).to be substitute
    end

    expect(container["test.service"]).to be service_before
  end

  it "lazy-loads components within the scope without memoizing them in the container" do
    container.override("test.client", substitute) do
      expect(container["test.service"].client).to be substitute
    end

    expect(container["test.service"].client).to be_a Test::Client
  end
end
