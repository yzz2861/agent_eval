# frozen_string_literal: true

RSpec.describe Dry::Container do
  let(:klass) { Dry::Container }
  let(:container) { klass.new }

  it_behaves_like "a container"

  describe "inheritance" do
    it "sets up a container for a child class" do
      parent = Class.new { extend Dry::Container::Mixin }
      child = Class.new(parent)

      parent.register(:foo, Object.new)
      child.register(:foo, Object.new)

      expect(parent[:foo]).to_not be(child[:foo])
    end

    it "inherits tagged bindings with their priority and registration order" do
      parent = Class.new { extend Dry::Container::Mixin }
      parent.register(:sms, tags: :notifier) { :sms }
      parent.register(:push, tags: :notifier, priority: -1) { :push }
      child = Class.new(parent)
      child.register(:email, tags: :notifier) { :email }

      expect(child.resolve_all(:notifier)).to eq(%i[push sms email])
      expect(child.tagged_keys(:notifier)).to eq(%w[push sms email])
      expect(parent.resolve_all(:notifier)).to eq(%i[push sms])
    end
  end
end
