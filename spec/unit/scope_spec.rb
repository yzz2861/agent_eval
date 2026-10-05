# frozen_string_literal: true

RSpec.describe Dry::System::Scope do
  subject(:scope) { described_class.new(container: container) }

  let(:container) { Class.new(Dry::System::Container) }

  describe "#depth and #root?" do
    it "is a root scope at depth 0" do
      expect(scope).to be_root
      expect(scope.depth).to eq 0
    end

    it "tracks nesting depth" do
      inner = described_class.new(container: container, parent: scope)
      deepest = described_class.new(container: container, parent: inner)

      expect(inner).not_to be_root
      expect(inner.depth).to eq 1
      expect(deepest.depth).to eq 2
    end
  end

  describe "#find" do
    it "searches outwards through parents" do
      inner = described_class.new(container: container, parent: scope)
      scope.store("shared", :outer, nil)

      expect(inner.find("shared")).to eq :outer
      expect(scope.find("missing")).to be_nil
    end
  end

  describe "#release!" do
    it "releases owned components in reverse order" do
      events = []
      scope.store("a", :a, ->(v) { events << v })
      scope.store("b", :b, ->(v) { events << v })

      scope.release!

      expect(events).to eq %i[b a]
      expect(scope.find("a")).to be_nil
    end

    it "calls #close by default" do
      closable = Object.new
      closed = false
      closable.define_singleton_method(:close) { closed = true }

      scope.store("c", closable, nil)
      scope.release!

      expect(closed).to be true
    end

    it "supports a symbol naming the release method" do
      released = false
      object = Object.new
      object.define_singleton_method(:disconnect) { released = true }

      scope.store("c", object, :disconnect)
      scope.release!

      expect(released).to be true
    end

    it "runs on_release callbacks and still releases components if one raises" do
      events = []
      scope.store("ok", :ok, ->(v) { events << v })
      scope.store("bad", :bad, ->(_) { raise "release failed" })
      scope.on_release { events << :callback }

      expect { scope.release! }.to raise_error(RuntimeError, "release failed")
      expect(events).to eq %i[ok callback]
    end
  end
end
