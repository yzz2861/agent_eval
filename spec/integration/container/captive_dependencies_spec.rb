# frozen_string_literal: true

RSpec.describe "Container / Captive dependencies" do
  subject(:container) {
    Class.new(Dry::System::Container) do
      configure do |config|
        config.name = :test
      end
    end
  }

  it "prevents a singleton from depending on a scoped component" do
    container.register("request_store", lifecycle: :scoped) { Object.new }
    container.register("app", lifecycle: :singleton) { container["request_store"] }

    expect { container["app"] }.to raise_error(
      Dry::System::CaptiveDependencyError,
      /singleton component cannot capture a shorter-lived scoped dependency/,
    )
  end

  it "prevents a singleton from depending on a transient component" do
    container.register("operation", lifecycle: :transient) { Object.new }
    container.register("app", lifecycle: :singleton) { container["operation"] }

    expect { container["app"] }.to raise_error(
      Dry::System::CaptiveDependencyError,
      /singleton component cannot capture a shorter-lived transient dependency/,
    )
  end

  it "prevents a scoped component from depending on a transient component" do
    container.register("operation", lifecycle: :transient) { Object.new }
    container.register("worker", lifecycle: :scoped) { container["operation"] }

    expect {
      container.scoped { container["worker"] }
    }.to raise_error(
      Dry::System::CaptiveDependencyError,
      /scoped component cannot capture a shorter-lived transient dependency/,
    )
  end

  it "reports the full dependency chain in the error" do
    container.register("request_store", lifecycle: :scoped) { Object.new }
    container.register("repository", lifecycle: :singleton) { container["request_store"] }
    container.register("app", lifecycle: :singleton) { container["repository"] }

    container.scoped do
      expect { container["app"] }.to raise_error(
        Dry::System::CaptiveDependencyError,
        /app \(singleton\) -> repository \(singleton\) -> request_store \(scoped\)/,
      )
    end
  end

  it "exposes the chain on the error" do
    container.register("request_store", lifecycle: :scoped) { Object.new }
    container.register("app", lifecycle: :singleton) { container["request_store"] }

    container.scoped do
      expect { container["app"] }.to raise_error(
        Dry::System::CaptiveDependencyError,
      ) { |e|
        expect(e.chain.map(&:key)).to eq %w[app request_store]
        expect(e.chain.map(&:lifecycle)).to eq %i[singleton scoped]
      }
    end
  end

  it "allows a singleton to depend on other singletons" do
    container.register("config", lifecycle: :singleton) { Object.new }
    container.register("app", lifecycle: :singleton) { container["config"] }

    expect(container["app"]).to be container["config"]
  end

  it "allows a scoped component to depend on singletons and other scoped components" do
    container.register("config", lifecycle: :singleton) { Object.new }
    container.register("request_store", lifecycle: :scoped) { Object.new }
    container.register("worker", lifecycle: :scoped) {
      [container["config"], container["request_store"]]
    }

    container.scoped do
      config, request_store = container["worker"]

      expect(config).to be container["config"]
      expect(request_store).to be container["request_store"]
    end
  end

  it "allows a transient component to depend on shorter-lived components" do
    container.register("request_store", lifecycle: :scoped) { Object.new }
    container.register("operation", lifecycle: :transient) { container["request_store"] }

    container.scoped do
      expect(container["operation"]).to be container["request_store"]
    end
  end

  it "treats memoized components as singletons and plain blocks as transient" do
    container.register("operation") { Object.new }
    container.register("app", memoize: true) { container["operation"] }

    expect { container["app"] }.to raise_error(
      Dry::System::CaptiveDependencyError,
      /singleton component cannot capture a shorter-lived transient dependency/,
    )
  end

  it "does not check dependencies resolved outside of component builds" do
    container.register("request_store", lifecycle: :scoped) { Object.new }

    container.scoped do
      expect { container["request_store"] }.not_to raise_error
    end
  end
end
