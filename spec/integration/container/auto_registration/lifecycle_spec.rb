# frozen_string_literal: true

RSpec.describe "Auto-registration / Component lifecycles" do
  before do
    class Test::Container < Dry::System::Container
      configure do |config|
        config.root = SPEC_ROOT.join("fixtures").realpath

        config.component_dirs.add "lifecycle_components" do |dir|
          dir.namespaces.add "test", key: nil
        end
      end
    end
  end

  shared_examples "lifecycle components" do
    it "registers components with lifecycle: singleton as singletons" do
      expect(Test::Container["singleton_service"]).to be Test::Container["singleton_service"]
    end

    it "registers components with lifecycle: transient as transient" do
      expect(Test::Container["transient_service"]).not_to be Test::Container["transient_service"]
    end

    it "registers components with lifecycle: scoped as scoped" do
      Test::Container.scoped do
        expect(Test::Container["scoped_service"]).to be Test::Container["scoped_service"]
      end

      first = Test::Container.scoped { Test::Container["scoped_service"] }
      second = Test::Container.scoped { Test::Container["scoped_service"] }

      expect(first).not_to be second
    end

    it "raises NoActiveScopeError when resolving a scoped component without a scope" do
      expect { Test::Container["scoped_service"] }.to raise_error(
        Dry::System::NoActiveScopeError,
      )
    end
  end

  context "Finalized container" do
    before do
      Test::Container.finalize!
    end

    include_examples "lifecycle components"
  end

  context "Non-finalized container" do
    include_examples "lifecycle components"
  end
end
