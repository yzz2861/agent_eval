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

    it "keeps tagged multi-bindings and their order in child classes" do
      parent = Class.new { extend Dry::Container::Mixin }

      parent.register("notifiers.sms", tags: %i[notifier], order: 2) { :sms }
      parent.register("notifiers.email", tags: %i[notifier], order: 1) { :email }

      child = Class.new(parent)
      child.register("notifiers.push", tags: %i[notifier]) { :push }

      expect(parent.resolve_all(:notifier)).to eq(%i[email sms])
      expect(child.resolve_all(:notifier)).to eq(%i[push email sms])
    end
  end
end
