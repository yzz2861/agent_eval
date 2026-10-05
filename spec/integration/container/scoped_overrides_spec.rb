# frozen_string_literal: true

require "dry/system/container"

RSpec.describe "Container / scoped overrides" do
  let(:container) do
    Class.new(Dry::System::Container) do
      register("test.client", memoize: true) { Test::Client.new }
      register("test.service", memoize: true) { Test::Service.new }
      register("test.failing_service", memoize: true) { Test::FailingService.new }
    end
  end

  before do
    module Test
      class Client
      end

      class Service
        attr_reader :client

        def initialize(client:)
          @client = client
        end
      end

      class FailingService
        def initialize(client:)
          raise RuntimeError, "boom"
        end
      end
    end

    Test::Import = container.injector
    Test::Service.include(Test::Import["test.client"])
    Test::FailingService.include(Test::Import["test.client"])
  end

  it "rebuilds already resolved dependent components using the scoped replacement" do
    container.finalize!

    original_client = container["test.client"]
    original_service = container["test.service"]
    replacement_client = Object.new

    expect(original_service.client).to be(original_client)

    container.override("test.client", replacement_client) do
      expect(container["test.client"]).to be(replacement_client)
      expect(container["test.service"]).not_to be(original_service)
      expect(container["test.service"].client).to be(replacement_client)
    end

    expect(container["test.client"]).to be(original_client)
    expect(container["test.service"]).to be(original_service)
    expect(container["test.service"].client).to be(original_client)
  end

  it "restores the parent scope when a nested override exits" do
    original_service = container["test.service"]
    middle_client = Object.new
    inner_service = Object.new

    container.override("test.client", middle_client) do
      middle_service = container["test.service"]

      expect(middle_service.client).to be(middle_client)

      container.override("test.service", inner_service) do
        expect(container["test.service"]).to be(inner_service)
      end

      expect(container["test.service"]).to be(middle_service)
      expect(container["test.service"].client).to be(middle_client)
    end

    expect(container["test.service"]).to be(original_service)
  end

  it "accepts nil and false as replacement values" do
    container.override(nil_component: nil, false_component: false) do
      expect(container[:nil_component]).to be(nil)
      expect(container[:false_component]).to be(false)
    end
  end

  it "does not allow finalization while overrides are active" do
    expect {
      container.override("test.client", Object.new) do
        container.finalize!
      end
    }.to raise_error(
      Dry::System::ScopedOverridesFinalizationError,
      "cannot finalize a container while scoped overrides are active"
    )

    expect(container.finalized?).to be(false)
  end

  it "does not retain components created by a failed construction" do
    original_service = container["test.service"]
    replacement_client = Object.new

    expect {
      container.override("test.client", replacement_client) do
        container["test.failing_service"]
      end
    }.to raise_error(RuntimeError, "boom")

    expect(container["test.service"]).to be(original_service)

    container.override("test.client", replacement_client) do
      expect(container["test.service"].client).to be(replacement_client)
    end
  end

  it "rolls back nested failures to the enclosing scope" do
    replacement_client = Object.new

    container.override("test.client", replacement_client) do
      rebuilt_service = container["test.service"]

      expect {
        container.override("test.client", Object.new) do
          container["test.failing_service"]
        end
      }.to raise_error(RuntimeError, "boom")

      expect(container["test.service"]).to be(rebuilt_service)
    end
  end

  it "stops providers that were started only inside the scope" do
    lifecycle = []

    container.register_provider(:lifecycle) do
      start { lifecycle << :start }
      stop { lifecycle << :stop }
    end

    container.override("test.client", Object.new) do
      container.start(:lifecycle)
      expect(lifecycle).to eq(%i[start])
    end

    expect(lifecycle).to eq(%i[start stop])
    expect(container.providers[:lifecycle]).not_to be_started
  end

  it "keeps the original graph visible outside the current thread" do
    original_client = container["test.client"]
    client_seen_outside_scope = nil

    container.override("test.client", Object.new) do
      thread = Thread.new do
        client_seen_outside_scope = container["test.client"]
      end

      thread.join

      expect(client_seen_outside_scope).to be(original_client)
    end
  end
end
