# frozen_string_literal: true

require "ostruct"

RSpec.describe "Container / Imports / Borrowed components" do
  subject(:base_container) { base_container_class }

  let(:base_container_class) do
    Class.new(Dry::System::Container) do
      configure do |config|
        config.name = :base
        config.exports = %w[db.client]
      end

      register("static_component", "static from base")

      register_provider(:db) do
        start do
          register("db.client", Object.new)
        end
      end
    end
  end

  let(:target_a) do
    base = base_container

    Class.new(Dry::System::Container) do
      configure { |config| config.name = :app_a }

      register("local_component", "local to a")

      import from: base, as: :core, borrow: true
    end
  end

  let(:target_b) do
    base = base_container

    Class.new(Dry::System::Container) do
      configure { |config| config.name = :app_b }

      import from: base, as: :core, borrow: true
    end
  end

  describe "configuration" do
    it "registers only explicit borrowed references in the target" do
      expect(target_a.registered?("core.db.client")).to be true
      expect(target_a.registered?("core.static_component")).to be false
    end

    it "does not resolve arbitrary source keys through the target namespace" do
      expect(target_a.key?("core.db.client")).to be true
      expect(target_a.key?("core.static_component")).to be false
      expect(target_a.key?("core.anything_else")).to be false
    end

    it "raises when borrowing a key not declared in the source exports" do
      base = base_container

      expect {
        Class.new(Dry::System::Container) do
          import from: base, as: :core, borrow: true, keys: %w[not.exported]
        end
      }.to raise_error(
        Dry::System::ComponentNotExportedError,
        /not included in the exports of source container base/
      )
    end

    it "raises when the source declares no exports at all" do
      source = Class.new(Dry::System::Container) do
        configure { |config| config.name = :closed }
        register("thing", Object.new)
      end

      expect {
        Class.new(Dry::System::Container) do
          import from: source, as: :core, borrow: true
        end
      }.to raise_error(ArgumentError, /declares no `config.exports`/)
    end

    it "raises when the import namespace conflicts with a registered local component" do
      base = base_container

      expect {
        Class.new(Dry::System::Container) do
          register("core", "local")
          import from: base, as: :core, borrow: true
        end
      }.to raise_error(Dry::System::ImportNamespaceConflictError, /"core" conflicts/)
    end

    it "raises when the import namespace conflicts with a nested registered key" do
      base = base_container

      expect {
        Class.new(Dry::System::Container) do
          register("core.thing", "local")
          import from: base, as: :core, borrow: true
        end
      }.to raise_error(Dry::System::ImportNamespaceConflictError)
    end

    it "raises when the same import namespace is registered twice" do
      base = base_container

      expect {
        Class.new(Dry::System::Container) do
          import from: base, as: :core, borrow: true
          import from: base, as: :core, borrow: true
        end
      }.to raise_error(Dry::System::ImportNamespaceConflictError)
    end

    it "raises when borrowing into a nil namespace" do
      base = base_container

      expect {
        Class.new(Dry::System::Container) do
          import from: base, as: nil, borrow: true
        end
      }.to raise_error(ArgumentError, /non-nil `as:` namespace/)
    end
  end

  describe "resolution and lifecycle" do
    it "fails to resolve when the source has not been started" do
      expect(base_container.lifecycle_status).to eq(:not_started)

      expect {
        target_a["core.db.client"]
      }.to raise_error(
        Dry::System::BorrowedComponentNotAvailableError,
        /has not been started or finalized/
      )
    end

    context "source started" do
      before do
        base_container.start(:db)
      end

      it "shares a single source-owned component across both targets" do
        from_a = target_a["core.db.client"]
        from_b = target_b["core.db.client"]

        expect(from_a).to be(base_container["db.client"])
        expect(from_b).to be(from_a)
      end

      it "supports resolving borrowed components through an injector" do
        import_module = target_a.injector
        klass = Class.new do
          include import_module["core.db.client"]
        end

        expect(klass.new.client).to be(base_container["db.client"])
      end

      it "does not start the source just by finalizing a target" do
        fresh_base = Class.new(Dry::System::Container) do
          configure { |config| config.name = :fresh_base; config.exports = %w[db.client] }
          register_provider(:db) do
            start { register("db.client", Object.new) }
          end
        end

        fresh_target = Class.new(Dry::System::Container) do
          import from: fresh_base, as: :core, borrow: true
        end

        fresh_target.finalize!

        expect(fresh_target).to be_finalized
        expect(fresh_base).not_to be_finalized
        expect(fresh_base.lifecycle_status).to eq(:not_started)
      end

      it "keeps the source resource alive when a target shuts down" do
        connection = target_a["core.db.client"]

        target_a.shutdown!

        expect(base_container["db.client"]).to be(connection)
        expect(target_b["core.db.client"]).to be(connection)
      end

      it "still shuts down the target's own providers on shutdown" do
        base = base_container

        local_target = Class.new(Dry::System::Container) do
          configure { |config| config.name = :local_app }

          register_provider(:local) do
            start { register("local.resource", OpenStruct.new(active: true)) }
            stop { container["local.resource"].active = false }
          end

          import from: base, as: :core, borrow: true
        end

        resource = local_target["local.resource"]

        local_target.shutdown!

        expect(resource.active).to be false
      end

      it "fails to resolve after the source has shut down" do
        target_a["core.db.client"]

        base_container.shutdown!

        expect(base_container.lifecycle_status).to eq(:shutdown)

        expect {
          target_a["core.db.client"]
        }.to raise_error(
          Dry::System::BorrowedComponentNotAvailableError,
          /has been shut down/
        )
      end
    end

    context "source finalized" do
      before do
        base_container.finalize!
      end

      it "resolves borrowed components and treats the source as running" do
        expect(base_container.lifecycle_status).to eq(:running)
        expect(target_a["core.db.client"]).to be(base_container["db.client"])
      end
    end
  end

  describe "complete lifecycle shared by two targets" do
    it "serves both targets for the source's lifetime and fails only after source shutdown" do
      target_a
      target_b

      expect { target_a["core.db.client"] }.to raise_error(
        Dry::System::BorrowedComponentNotAvailableError
      )

      base_container.start(:db)

      shared = base_container["db.client"]
      expect(target_a["core.db.client"]).to be(shared)
      expect(target_b["core.db.client"]).to be(shared)

      target_a.shutdown!
      expect(target_b["core.db.client"]).to be(shared)

      target_b.shutdown!
      expect(base_container["db.client"]).to be(shared)

      base_container.shutdown!
      expect { target_a["core.db.client"] }.to raise_error(
        Dry::System::BorrowedComponentNotAvailableError, /shut down/
      )
      expect { target_b["core.db.client"] }.to raise_error(
        Dry::System::BorrowedComponentNotAvailableError, /shut down/
      )
    end
  end
end
