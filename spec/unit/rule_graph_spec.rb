# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::RuleGraph do
  def rule(keys: [:x], name: nil, depends_on: nil)
    Dry::Validation::Rule.new(
      keys: keys,
      name: name,
      depends_on: depends_on,
      block: proc {}
    )
  end

  describe "#call" do
    it "returns rules in definition order when there are no dependencies" do
      a = rule(name: :a)
      b = rule(name: :b)

      expect(described_class.new([a, b]).call).to eql([a, b])
    end

    it "orders prerequisites before dependent rules" do
      a = rule(name: :a)
      b = rule(name: :b, depends_on: :a)
      c = rule(name: :c, depends_on: :b)

      expect(described_class.new([c, b, a]).call).to eql([a, b, c])
    end

    it "keeps unrelated rules in their relative definition order" do
      a = rule(name: :a)
      b = rule(name: :b)
      c = rule(name: :c, depends_on: :a)

      expect(described_class.new([a, b, c]).call).to eql([a, b, c])
    end
  end

  describe "initialization" do
    it "raises when a dependency is not defined" do
      a = rule(name: :a, depends_on: :missing)

      expect { described_class.new([a]) }.to raise_error(
        Dry::Validation::MissingRuleError,
        /:a depends on :missing.*no rule named :missing/
      )
    end

    it "reports unnamed dependent rules in the missing-rule message" do
      a = rule(depends_on: :missing)

      expect { described_class.new([a]) }.to raise_error(
        Dry::Validation::MissingRuleError,
        /rule\(:x\) depends on :missing/
      )
    end

    it "raises when rules form a cycle" do
      a = rule(name: :a, depends_on: :b)
      b = rule(name: :b, depends_on: :a)

      expect { described_class.new([a, b]) }.to raise_error(
        Dry::Validation::CircularDependencyError,
        /:a -> :b -> :a|:b -> :a -> :b/
      )
    end

    it "raises when a rule depends on itself" do
      a = rule(name: :a, depends_on: :a)

      expect { described_class.new([a]) }.to raise_error(
        Dry::Validation::CircularDependencyError,
        /:a -> :a/
      )
    end

    it "raises when a name is registered twice" do
      a = rule(keys: [:x], name: :dup)
      b = rule(keys: [:y], name: :dup)

      expect { described_class.new([a, b]) }.to raise_error(
        Dry::Validation::DuplicateRuleNameError,
        /:dup is used by both rule\(:x\) and rule\(:y\)/
      )
    end
  end

  describe "#[]" do
    it "looks up rules by name or string" do
      a = rule(name: :a)
      graph = described_class.new([a])

      expect(graph[:a]).to be(a)
      expect(graph["a"]).to be(a)
      expect(graph[:missing]).to be_nil
    end
  end
end
