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

    it "does not share aliases between parent and child" do
      parent = Class.new { extend Dry::Container::Mixin }
      parent.register_alias("mailer", "notifications.delivery")

      child = Class.new(parent)
      child.register_alias("legacy_mailer", "notifications.delivery")

      expect(child.key?("mailer")).to be(true)
      expect(parent.key?("legacy_mailer")).to be(false)
    end
  end
end
