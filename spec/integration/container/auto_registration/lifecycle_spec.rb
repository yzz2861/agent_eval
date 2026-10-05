# frozen_string_literal: true

RSpec.describe "Auto-registration / Lifecycles" do
  let(:cleanable_modules) { %i[LifecycleTest] }

  subject(:container) {
    policy = lifecycle_policy
    Class.new(Dry::System::Container) {
      configure do |config|
        config.root = SPEC_ROOT.join("fixtures/component_lifecycles").realpath

        config.component_dirs.add "lib" do |dir|
          dir.lifecycle = policy
          dir.namespaces.add "lifecycle_test", key: nil
        end
      end
    }
  }

  context "with a static dir lifecycle" do
    let(:lifecycle_policy) { :singleton }

    it "builds all components as singletons" do
      expect(container["ephemeral_service"]).to be container["ephemeral_service"]
    end
  end

  context "with a per-component proc policy" do
    let(:lifecycle_policy) {
      proc { |component|
        case component.key
        when "global_cache" then :singleton
        when "request_context" then :scoped
        else :transient
        end
      }
    }

    it "applies the singleton policy" do
      expect(container["global_cache"]).to be container["global_cache"]
    end

    it "applies the scoped policy and releases the component" do
      first = container.scope { container["request_context"] }
      second = container.scope { container["request_context"] }

      expect(first).not_to be second
      expect(first).to be_closed
      expect(second).to be_closed
    end

    it "applies the transient policy" do
      expect(container["ephemeral_service"]).not_to be container["ephemeral_service"]
    end
  end

  context "with a lifecycle magic comment" do
    let(:lifecycle_policy) { :transient }

    it "the magic comment overrides the dir policy" do
      expect { container["request_context"] }.to raise_error(
        Dry::System::ScopedComponentWithoutScopeError
      )

      instance = container.scope { container["request_context"] }
      expect(container.scope { container["request_context"] }).not_to be instance
    end
  end

  context "with no lifecycle policy" do
    let(:lifecycle_policy) { nil }

    it "defaults to the memoize policy (transient here)" do
      expect(container["ephemeral_service"]).not_to be container["ephemeral_service"]
    end
  end

  context "with an invalid lifecycle policy" do
    let(:lifecycle_policy) { :nope }

    it "raises an InvalidLifecycleError when a component is resolved" do
      expect { container["ephemeral_service"] }.to raise_error(
        Dry::System::InvalidLifecycleError, /:nope/
      )
    end
  end
end
