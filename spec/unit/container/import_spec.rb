# frozen_string_literal: true

require "dry/system/container"

RSpec.describe Dry::System::Container, ".import" do
  subject(:app) { Class.new(Dry::System::Container) }

  let(:db) do
    Class.new(Dry::System::Container) do
      register(:users, %w[jane joe])
    end
  end

  it "imports one container into another" do
    app.import(from: db, as: :persistence)

    expect(app.registered?("persistence.users")).to be(false)

    app.finalize!

    expect(app["persistence.users"]).to eql(%w[jane joe])
  end

  context "when container has been finalized" do
    it "raises an error" do
      app.finalize!

      expect do
        app.import(from: db, as: :persistence)
      end.to raise_error(Dry::System::ContainerAlreadyFinalizedError)
    end
  end

  describe "borrow: true" do
    let(:source) do
      Class.new(Dry::System::Container) do
        configure do |config|
          config.name = :source
          config.exports = %w[users]
        end

        register(:users, %w[jane joe])
      end
    end

    it "registers an explicit borrowed reference at configuration time" do
      app.import(from: source, as: :core, borrow: true)

      expect(app.registered?("core.users")).to be true
    end

    it "rejects borrowing keys not declared in the source exports" do
      expect {
        app.import(from: source, as: :core, borrow: true, keys: %w[secrets])
      }.to raise_error(Dry::System::ComponentNotExportedError)
    end

    it "rejects a namespace that conflicts with an existing registration" do
      app.register("core", "local")

      expect {
        app.import(from: source, as: :core, borrow: true)
      }.to raise_error(Dry::System::ImportNamespaceConflictError)
    end

    it "requires a non-nil namespace" do
      expect {
        app.import(from: source, as: nil, borrow: true)
      }.to raise_error(ArgumentError, /non-nil `as:` namespace/)
    end

    it "resolves the shared source component once the source is running" do
      app.import(from: source, as: :core, borrow: true)

      expect { app["core.users"] }.to raise_error(
        Dry::System::BorrowedComponentNotAvailableError
      )

      source.finalize!

      expect(app["core.users"]).to be(source["users"])
    end
  end

  describe "import module" do
    it "loads system when it was not loaded in the imported container yet" do
      class Test::Other < Dry::System::Container
        configure do |config|
          config.root = SPEC_ROOT.join("fixtures/import_test").realpath
          config.component_dirs.add "lib"
        end
      end

      class Test::Container < Dry::System::Container
        configure do |config|
          config.root = SPEC_ROOT.join("fixtures/test").realpath
          config.component_dirs.add "lib"
        end

        import from: Test::Other, as: :other
      end

      module Test
        Import = Container.injector
      end

      class Test::Foo
        include Test::Import["other.test.bar"]
      end

      expect(Test::Foo.new.bar).to be_instance_of(Test::Bar)
    end
  end
end
