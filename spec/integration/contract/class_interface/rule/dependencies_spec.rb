# frozen_string_literal: true

RSpec.describe Dry::Validation::Contract, "rule dependencies" do
  subject(:contract) { contract_class.new }

  context "with named rules and dependencies" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        schema do
          required(:account).filled(:string)
          required(:quota).filled(:integer)
          required(:address).filled(:string)
        end

        rule(:quota).depends_on(:account_usable) do
          key.failure("exceeds quota") if value > 10
        end

        rule(:account).named(:account_usable) do
          key.failure("is not usable") unless value == "active"
        end

        rule(:address) do
          key.failure("is invalid") if value == "nowhere"
        end
      end
    end

    it "runs dependents when their dependencies pass" do
      result = contract.(account: "active", quota: 20, address: "somewhere")

      expect(result.errors.to_h).to eql(quota: ["exceeds quota"])
      expect(result.rule_results.map(&:status)).to eql(%i[passed failed passed])
    end

    it "executes dependencies before dependents regardless of definition order" do
      result = contract.(account: "active", quota: 5, address: "somewhere")

      expect(result.rule_results.map(&:name)).to eql([:account_usable, nil, nil])
      expect(result.rule_results.map(&:rule)).to eql(
        [contract_class.rules[1], contract_class.rules[0], contract_class.rules[2]]
      )
    end

    it "skips dependents when a dependency fails and keeps collecting unrelated errors" do
      result = contract.(account: "inactive", quota: 20, address: "nowhere")

      expect(result.errors.to_h).to eql(
        account: ["is not usable"],
        address: ["is invalid"]
      )

      quota_result = result.rule_results.find { |outcome| outcome.rule.keys == [:quota] }
      expect(quota_result).to be_skipped
      expect(quota_result.reason).to eql(
        type: :unmet_dependencies, dependencies: [:account_usable]
      )
    end

    it "skips rules whose keys did not pass schema checks and reports why" do
      result = contract.(account: 123, quota: 20, address: "somewhere")

      expect(result.errors.to_h).to eql(account: ["must be a string"])

      account_result = result.rule_result(:account_usable)
      expect(account_result).to be_skipped
      expect(account_result.reason).to eql(type: :schema_error, keys: [:account])

      quota_result = result.rule_results.find { |outcome| outcome.rule.keys == [:quota] }
      expect(quota_result).to be_skipped
      expect(quota_result.reason).to eql(
        type: :unmet_dependencies, dependencies: [:account_usable]
      )
    end

    it "exposes outcomes for named rules" do
      result = contract.(account: "active", quota: 5, address: "somewhere")

      expect(result.rule_result(:account_usable)).to be_passed
      expect(result.rule_result("account_usable")).to be_passed
      expect(result.rule_result(:unknown)).to be_nil
    end

    it "supports naming a rule after its block" do
      klass = Class.new(Dry::Validation::Contract) do
        schema do
          required(:amount).filled(:integer)
        end

        rule(:amount) { key.failure("too small") if value < 1 }.named(:amount_positive)
        rule(:amount).depends_on(:amount_positive) { key.failure("too big") if value > 10 }
      end

      result = klass.new.(amount: 0)

      expect(result.errors.to_h).to eql(amount: ["too small"])
      expect(result.rule_results.map(&:status)).to eql(%i[failed skipped])
      expect(result.rule_result(:amount_positive)).to be_failed
    end
  end

  context "with transitive dependencies" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        schema do
          required(:a).filled(:integer)
          required(:b).filled(:integer)
          required(:c).filled(:integer)
        end

        rule(:a).named(:a_ok) do
          key.failure("a failed") if value.negative?
        end

        rule(:b).named(:b_ok).depends_on(:a_ok) do
          key.failure("b failed") if value.negative?
        end

        rule(:c).depends_on(:b_ok) do
          key.failure("c failed") if value.negative?
        end
      end
    end

    it "skips the whole chain when the root dependency fails" do
      result = contract.(a: -1, b: -1, c: -1)

      expect(result.errors.to_h).to eql(a: ["a failed"])
      expect(result.rule_results.map(&:status)).to eql(%i[failed skipped skipped])
      expect(result.rule_result(:b_ok).reason).to eql(
        type: :unmet_dependencies, dependencies: [:a_ok]
      )
    end

    it "skips only the remainder of the chain when an intermediate rule fails" do
      result = contract.(a: 1, b: -1, c: -1)

      expect(result.errors.to_h).to eql(b: ["b failed"])
      expect(result.rule_results.map(&:status)).to eql(%i[passed failed skipped])
    end
  end

  context "with invalid definitions" do
    it "raises when a dependency does not exist" do
      contract_class = Class.new(Dry::Validation::Contract) do
        schema do
          required(:a).filled(:integer)
        end

        rule(:a).depends_on(:missing) do
          key.failure("never runs")
        end
      end

      expect { contract_class.new.(a: 1) }.to raise_error(
        Dry::Validation::UnknownRuleDependencyError, /:missing/
      )
    end

    it "raises when dependencies form a cycle" do
      contract_class = Class.new(Dry::Validation::Contract) do
        schema do
          required(:a).filled(:integer)
          required(:b).filled(:integer)
        end

        rule(:a).named(:a_ok).depends_on(:b_ok)
        rule(:b).named(:b_ok).depends_on(:a_ok)
      end

      expect { contract_class.new.(a: 1, b: 2) }.to raise_error(
        Dry::Validation::CyclicRuleDependencyError, /a_ok -> b_ok -> a_ok|b_ok -> a_ok -> b_ok/
      )
    end

    it "raises when a rule depends on itself" do
      contract_class = Class.new(Dry::Validation::Contract) do
        schema do
          required(:a).filled(:integer)
        end

        rule(:a).named(:a_ok).depends_on(:a_ok)
      end

      expect { contract_class.new.(a: 1) }.to raise_error(
        Dry::Validation::CyclicRuleDependencyError, /a_ok -> a_ok/
      )
    end

    it "raises when two rules use the same name" do
      contract_class = Class.new(Dry::Validation::Contract) do
        schema do
          required(:a).filled(:integer)
          required(:b).filled(:integer)
        end

        rule(:a).named(:check)
        rule(:b).named(:check)
      end

      expect { contract_class.new.(a: 1, b: 2) }.to raise_error(
        Dry::Validation::DuplicateRuleNameError, /:check/
      )
    end

    it "detects definition errors before running any rule" do
      ran = []

      contract_class = Class.new(Dry::Validation::Contract) do
        schema do
          required(:a).filled(:integer)
        end

        rule(:a) { ran << :first }
        rule(:a).depends_on(:missing) { ran << :second }
      end

      expect { contract_class.new.(a: 1) }.to raise_error(
        Dry::Validation::UnknownRuleDependencyError
      )
      expect(ran).to be_empty
    end
  end
end
