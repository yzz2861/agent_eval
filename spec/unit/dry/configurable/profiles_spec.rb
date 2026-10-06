# frozen_string_literal: true

RSpec.describe Dry::Configurable::Profiles do
  subject(:profiles) { described_class.new }

  def add_profile(name, parents = [])
    profiles << Dry::Configurable::Profile.new(
      name, parents: parents, block: ->(_config) {}
    )
  end

  describe "#linearize" do
    it "returns the profile itself when it has no parents" do
      add_profile(:base)

      expect(profiles.linearize(:base)).to eql(%i[base])
    end

    it "orders a single inheritance chain from most to least specific" do
      add_profile(:base)
      add_profile(:middleware, %i[base])
      add_profile(:app, %i[middleware])

      expect(profiles.linearize(:app)).to eql(%i[app middleware base])
    end

    it "preserves the declared order of multiple parents" do
      add_profile(:common)
      add_profile(:left, %i[common])
      add_profile(:right, %i[common])
      add_profile(:app, %i[left right])

      expect(profiles.linearize(:app)).to eql(%i[app left right common])
    end

    it "places a shared ancestor in a diamond exactly once, after all its descendants" do
      add_profile(:base)
      add_profile(:development, %i[base])
      add_profile(:test, %i[base])
      add_profile(:ci, %i[development test])

      order = profiles.linearize(:ci)

      expect(order).to eql(%i[ci development test base])
      expect(order.count(:base)).to be(1)
    end

    it "accepts string names" do
      add_profile(:base)

      expect(profiles.linearize("base")).to eql(%i[base])
    end

    it "memoizes the resolved order" do
      add_profile(:base)
      add_profile(:app, %i[base])

      expect(profiles.linearize(:app)).to be(profiles.linearize(:app))
    end

    it "raises UnknownProfileError for an undefined profile" do
      expect { profiles.linearize(:missing) }.to raise_error(
        Dry::Configurable::UnknownProfileError,
        "+missing+ is not a defined profile"
      )
    end

    it "raises UnknownProfileError for an undefined parent" do
      add_profile(:app, %i[missing])

      expect { profiles.linearize(:app) }.to raise_error(
        Dry::Configurable::UnknownProfileError,
        "+missing+ is not a defined profile"
      )
    end

    it "raises CyclicProfileInheritanceError for a direct cycle" do
      add_profile(:a, %i[b])
      add_profile(:b, %i[a])

      expect { profiles.linearize(:a) }.to raise_error(
        Dry::Configurable::CyclicProfileInheritanceError,
        "cyclic profile inheritance: a -> b -> a"
      )
    end

    it "raises CyclicProfileInheritanceError for self-inheritance" do
      add_profile(:a, %i[a])

      expect { profiles.linearize(:a) }.to raise_error(
        Dry::Configurable::CyclicProfileInheritanceError,
        "cyclic profile inheritance: a -> a"
      )
    end

    it "raises ProfileLinearizationError for contradictory precedence constraints" do
      add_profile(:x)
      add_profile(:y)
      add_profile(:a, %i[x y])
      add_profile(:b, %i[y x])
      add_profile(:c, %i[a b])

      expect { profiles.linearize(:c) }.to raise_error(
        Dry::Configurable::ProfileLinearizationError,
        /contradictory precedence constraints/
      )
    end
  end

  describe "registry behavior" do
    it "stores profiles by name and enumerates them" do
      add_profile(:base)
      add_profile(:app, %i[base])

      expect(profiles.keys).to eql(%i[base app])
      expect(profiles[:base].name).to be(:base)
      expect(profiles.key?(:app)).to be(true)
      expect(profiles.map(&:name)).to eql(%i[base app])
    end

    it "invalidates memoized linearizations when a profile is added" do
      add_profile(:app, %i[base])

      expect { profiles.linearize(:app) }.to raise_error(
        Dry::Configurable::UnknownProfileError
      )

      add_profile(:base)

      expect(profiles.linearize(:app)).to eql(%i[app base])
    end

    it "duplicates independently of the original registry" do
      add_profile(:base)
      copy = profiles.dup
      add_profile(:app, %i[base])

      expect(copy.keys).to eql(%i[base])
      expect(profiles.keys).to eql(%i[base app])
    end
  end
end
