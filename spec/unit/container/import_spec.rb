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

  context "borrow" do
    let(:source) do
      Class.new(Dry::System::Container) do
        configure do |config|
          config.name = :source
          config.exports = %w[users]
        end

        register("users", %w[jane joe])
        register("secret", :hidden)
      end
    end

    it "raises when a borrowed key is not exported" do
      expect {
        app.import(from: source, as: :src, keys: %w[secret], borrow: true)
      }.to raise_error(
        Dry::System::BorrowNotExportedError,
        /Cannot borrow key "secret" from :source/
      )
    end

    it "raises on a duplicate import namespace at configuration time" do
      app.import(from: source, as: :src, keys: %w[users], borrow: true)

      expect {
        app.import(from: source, as: :src, keys: %w[users], borrow: true)
      }.to raise_error(Dry::System::ImportNamespaceConflictError, /:src has already been registered/)
    end

    it "raises when the source has not been started" do
      app.import(from: source, as: :src, keys: %w[users], borrow: true)

      expect { app["src.users"] }
        .to raise_error(Dry::System::BorrowSourceNotStartedError, /has not been started/)
    end

    it "serves the live object from the started source" do
      app.import(from: source, as: :src, keys: %w[users], borrow: true)
      source.finalize!

      expect(app["src.users"]).to be(source["users"])
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
