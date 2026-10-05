# frozen_string_literal: true

RSpec.describe "Container / Imports / Borrowed components" do
  # A simple resource whose lifecycle can be observed from the outside
  let(:connection_class) {
    Class.new do
      attr_reader :open

      def initialize
        @open = true
      end

      def close
        @open = false
      end
    end
  }

  let(:base_container) {
    connection_class = self.connection_class

    Class.new(Dry::System::Container) do
      configure do |config|
        config.name = :base
        config.exports = %w[db.connection db.pool]
      end

      register("internal", Object.new)

      register_provider(:db) do
        start do
          register("db.connection", connection_class.new)
          register("db.pool", Object.new)
        end

        stop do
          target["db.connection"].close
        end
      end
    end
  }

  describe "resolving borrowed components" do
    let(:app_container) {
      base_container = self.base_container

      Class.new(Dry::System::Container) do
        configure { |config| config.name = :app }

        import from: base_container, as: :base, keys: %w[db.connection], borrow: true
      end
    }

    it "fails when the source container has not been started" do
      expect { app_container["base.db.connection"] }
        .to raise_error(
          Dry::System::BorrowSourceNotStartedError,
          /source container :base has not been started/
        )
    end

    it "resolves the very same object that the source container serves" do
      base_container.finalize!

      expect(app_container["base.db.connection"])
        .to be(base_container["db.connection"])
    end

    it "fails when the source container has been shut down" do
      base_container.finalize!
      connection = app_container["base.db.connection"]
      base_container.shutdown!

      expect { app_container["base.db.connection"] }
        .to raise_error(Dry::System::BorrowSourceShutdownError, /has been shut down/)
      expect(connection.open).to be false
    end
  end

  describe "lifecycle ownership" do
    let(:app_a) {
      base_container = self.base_container

      Class.new(Dry::System::Container) do
        configure { |config| config.name = :app_a }

        register_provider(:app_cache) do
          start { register("app_cache", Object.new) }
          stop { }
        end

        import from: base_container, as: :base, keys: %w[db.connection], borrow: true
      end
    }

    let(:app_b) {
      base_container = self.base_container

      Class.new(Dry::System::Container) do
        configure { |config| config.name = :app_b }
        import from: base_container, as: :base, keys: %w[db.connection], borrow: true
      end
    }

    it "shares one base resource across both targets for the complete lifecycle" do
      base_container.finalize!
      app_a.finalize!
      app_b.finalize!

      # Both targets borrow the same live object from the base
      connection = base_container["db.connection"]
      expect(app_a["base.db.connection"]).to be(connection)
      expect(app_b["base.db.connection"]).to be(connection)
      expect(connection.open).to be true

      # The target's own components still shut down, but the base is untouched
      app_a["app_cache"]
      app_a.shutdown!
      app_b.shutdown!

      expect(app_a.providers[:app_cache]).to be_stopped
      expect(app_a.shutdown?).to be true
      expect(app_b.shutdown?).to be true
      expect(connection.open).to be true
      expect(base_container.started?).to be true
      expect(base_container.shutdown?).to be false
      expect(base_container.providers[:db]).to be_started

      # Borrowed references remain resolvable while the source lives on
      expect(app_a["base.db.connection"]).to be(connection)
      expect(app_b["base.db.connection"]).to be(connection)

      # Only the lifecycle owner (the base) can finally close the resource
      base_container.shutdown!
      expect(connection.open).to be false
      expect { app_a["base.db.connection"] }
        .to raise_error(Dry::System::BorrowSourceShutdownError)
      expect { app_b["base.db.connection"] }
        .to raise_error(Dry::System::BorrowSourceShutdownError)
    end
  end

  describe "export restrictions" do
    it "cannot borrow a key that the source does not export" do
      base_container = self.base_container

      expect {
        Class.new(Dry::System::Container) do
          import from: base_container, as: :base, keys: %w[internal], borrow: true
        end
      }.to raise_error(
        Dry::System::BorrowNotExportedError,
        /Cannot borrow key "internal" from :base: it is not included in the source container's exports/
      )
    end

    it "cannot borrow from a source that configures no exports" do
      source = Class.new(Dry::System::Container) do
        configure { |config| config.name = :open_source }
        register("anything", Object.new)
      end

      expect {
        Class.new(Dry::System::Container) do
          import from: source, as: :src, keys: %w[anything], borrow: true
        end
      }.to raise_error(
        Dry::System::BorrowNotExportedError,
        /does not configure any exports/
      )
    end

    it "cannot resolve an arbitrary source key by bypassing the borrowed keys" do
      base_container.finalize!

      base = base_container
      app = Class.new(Dry::System::Container) {
        import from: base, as: :base, keys: %w[db.connection], borrow: true
      }

      # The private key and the non-borrowed exported key are not registered
      expect(app.registered?("base.internal")).to be false
      expect(app.registered?("base.db.pool")).to be false

      # Triggering the lazy import path must not copy the restricted keys either
      expect(app.key?("base.internal")).to be false
      expect(app.key?("base.db.pool")).to be false
    end
  end

  describe "namespace conflicts" do
    it "is detected at configuration time" do
      base_container = self.base_container

      expect {
        Class.new(Dry::System::Container) do
          import from: base_container, as: :base, keys: %w[db.connection], borrow: true
          import from: base_container, as: :base, keys: %w[db.connection], borrow: true
        end
      }.to raise_error(
        Dry::System::ImportNamespaceConflictError,
        /Import namespace :base has already been registered/
      )
    end
  end
end
