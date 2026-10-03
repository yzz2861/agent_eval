# frozen_string_literal: true

RSpec.describe Dry::Types::Schema::KeyGroup do
  subject(:group) { described_class.new(:exactly_one, [:a, :b]) }

  describe "#initialize" do
    it "accepts single keys as members" do
      group = described_class.new(:exactly_one, [:a, :b])

      expect(group.members).to eql([[[:a]], [[:b]]])
    end

    it "accepts fixed nested paths as members" do
      group = described_class.new(:exactly_one, [[[:creds, :token]], [[:creds, :password]]])

      expect(group.members).to eql([[[:creds, :token]], [[:creds, :password]]])
    end

    it "accepts bundles of paths as members" do
      group = described_class.new(:exactly_one, [:token, [:username, :password]])

      expect(group.members).to eql([[[:token]], [[:username], [:password]]])
    end

    it "rejects unknown kinds" do
      expect { described_class.new(:either, [:a]) }.to raise_error(
        ArgumentError, /unknown group kind :either/
      )
    end

    it "rejects unknown check moments" do
      expect { described_class.new(:exactly_one, [:a], check: :later) }.to raise_error(
        ArgumentError, /unknown check moment :later/
      )
    end

    it "rejects empty member lists" do
      expect { described_class.new(:exactly_one, []) }.to raise_error(
        ArgumentError, /at least one member/
      )
    end

    it "rejects empty members" do
      expect { described_class.new(:exactly_one, [[]]) }.to raise_error(
        ArgumentError, /must not be empty/
      )
    end

    it "rejects invalid path segments" do
      expect { described_class.new(:exactly_one, [[:a, "b"]]) }.to raise_error(
        ArgumentError, /symbols, paths or bundles of paths/
      )
    end
  end

  describe "#paths" do
    it "returns flattened unique paths" do
      group = described_class.new(
        :all_or_none, [[:a, :b], [:a, [:b, :c]]]
      )

      expect(group.paths).to eql([[:a], [:b], [:b, :c]])
    end
  end

  describe ".coerce" do
    it "coerces a hash" do
      group = described_class.coerce(
        kind: :at_least_one, members: [:a, :b], check: :after_defaults
      )

      expect(group).to eql(described_class.new(:at_least_one, [:a, :b], check: :after_defaults))
    end

    it "defaults to checking before defaults" do
      expect(described_class.coerce(kind: :exactly_one, members: [:a]).check).to be(:before_defaults)
    end

    it "returns groups unchanged" do
      expect(described_class.coerce(group)).to be(group)
    end
  end

  describe "#to_ast" do
    it "serializes the group" do
      expect(group.to_ast).to eql(
        [:exactly_one, [[[:a]], [[:b]]], :before_defaults]
      )
    end
  end
end
