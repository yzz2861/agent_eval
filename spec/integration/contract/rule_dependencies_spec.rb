# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::Contract, "rule dependencies" do
  subject(:contract) { contract_class.new }

  let(:contract_class) do
    Class.new(Dry::Validation::Contract) do
      def self.name
        "ContractSpec"
      end

      params do
        required(:account_id).filled(:integer)
        required(:amount).filled(:integer)
        required(:address).filled(:string)
      end

      rule(:account_id, name: :account_available) do
        key.failure("account is closed") unless value == 1
      end

      rule(:amount, name: :within_limit, depends_on: :account_available) do
        key.failure("exceeds credit limit") if value > 100
      end

      rule(:address, name: :address_valid) do
        key.failure("address is invalid") unless value.start_with?("Main")
      end
    end
  end

  it "applies dependent rules when prerequisites pass" do
    result = contract.(account_id: 1, amount: 50, address: "Main St")

    expect(result).to be_success
    expect(result.rule_results.transform_values(&:status)).to eql(
      account_available: :passed,
      within_limit: :passed,
      address_valid: :passed
    )
  end

  it "skips a rule when its prerequisite fails but keeps unrelated branches running" do
    result = contract.(account_id: 2, amount: 999, address: "Nowhere")

    expect(result).to be_failure
    expect(result.errors.to_h).to eql(
      account_id: ["account is closed"],
      address: ["address is invalid"]
    )

    expect(result.rule_results[:account_available]).to be_failed
    expect(result.rule_results[:address_valid]).to be_failed

    skipped = result.rule_results[:within_limit]

    expect(skipped).to be_skipped
    expect(skipped.unmet_dependencies).to eql(account_available: :failed)
    expect(skipped.failed_dependencies).to eql([:account_available])
    expect(skipped.reason).to eql(
      "skipped because prerequisite :account_available was failed"
    )
  end

  it "skips a rule when the prerequisite itself was skipped" do
    contract_class.rule(:amount, name: :ledger_ok, depends_on: :within_limit) {}

    result = contract.(account_id: 2, amount: 999, address: "Main St")

    expect(result.rule_results[:within_limit]).to be_skipped
    expect(result.rule_results[:ledger_ok]).to be_skipped
    expect(result.rule_results[:ledger_ok].unmet_dependencies).to eql(
      within_limit: :skipped
    )
    expect(result.rule_results[:ledger_ok].reason).to include(":within_limit was skipped")
  end

  it "skips rules whose keys fail schema checks and reports the reason" do
    result = contract.(account_id: 1, amount: "big", address: "Main St")

    expect(result.errors.to_h).to eql(amount: ["must be an integer"])

    skipped = result.rule_results[:within_limit]

    expect(skipped).to be_skipped
    expect(skipped).to be_schema_error
    expect(skipped.reason).to eql("skipped due to a schema error")
  end

  it "reports multiple unmet prerequisites" do
    contract_class.rule(:amount, name: :needs_both,
                        depends_on: %i[account_available address_valid]) {}

    result = contract.(account_id: 2, amount: 1, address: "Nowhere")

    skipped = result.rule_results[:needs_both]

    expect(skipped).to be_skipped
    expect(skipped.unmet_dependencies).to eql(
      account_available: :failed,
      address_valid: :failed
    )
    expect(skipped.reason).to include(":account_available was failed")
    expect(skipped.reason).to include(":address_valid was failed")
  end

  it "does not report results for unnamed rules" do
    contract_class.rule(:amount) { key.failure("unnamed failure") if value > 10 }

    result = contract.(account_id: 1, amount: 20, address: "Main St")

    expect(result.errors.to_h).to include(amount: array_including("unnamed failure"))
    expect(result.rule_results.keys).not_to include(nil)
  end

  it "freezes rule results" do
    result = contract.(account_id: 1, amount: 1, address: "Main St")

    expect(result.rule_results).to be_frozen
    expect(result.rule_results[:account_available]).to be_frozen
  end

    it "accepts string names and string dependencies" do
      klass = Class.new(Dry::Validation::Contract) do
        params do
          required(:x).filled(:integer)
        end

        rule(:x, name: "first") {}
        rule(:x, name: "second", depends_on: "first") {}
      end

    result = klass.new.call(x: 1)

    expect(result.rule_results.keys).to eql(%i[first second])
  end

  it "executes prerequisites before dependent rules regardless of definition order" do
    executed = []

    klass = Class.new(Dry::Validation::Contract) do
      params do
        required(:x).filled(:integer)
      end

      rule(:x, name: :second, depends_on: :first) do
        executed << :second
      end

      rule(:x, name: :first) do
        executed << :first
      end
    end

    klass.new.call(x: 1)

    expect(executed).to eql(%i[first second])
  end

  context "definition validation" do
    it "raises when a dependency references an unknown rule at instantiation time" do
      contract_class.rule(:amount, name: :bad, depends_on: :missing) {}

      expect { contract_class.new }.to raise_error(
        Dry::Validation::MissingRuleError,
        /:bad depends on :missing.*no rule named :missing/
      )
    end

    it "raises when dependencies form a cycle" do
      contract_class.rule(:amount, name: :a, depends_on: :c) {}
      contract_class.rule(:amount, name: :b, depends_on: :a) {}
      contract_class.rule(:amount, name: :c, depends_on: :b) {}

      expect { contract_class.new }.to raise_error(
        Dry::Validation::CircularDependencyError,
        /circular dependency.*:a -> :c -> :b -> :a/
      )
    end

    it "raises on a self dependency" do
      contract_class.rule(:amount, name: :a, depends_on: :a) {}

      expect { contract_class.new }.to raise_error(
        Dry::Validation::CircularDependencyError,
        /:a -> :a/
      )
    end

    it "raises when a rule name is used twice" do
      contract_class.rule(:amount, name: :duplicate) {}
      contract_class.rule(:address, name: :duplicate) {}

      expect { contract_class.new }.to raise_error(
        Dry::Validation::DuplicateRuleNameError,
        /name :duplicate is used by both/
      )
    end
  end

  context "inheritance" do
    it "lets a child rule depend on an inherited named rule" do
      parent = Class.new(Dry::Validation::Contract) do
        params do
          required(:x).filled(:integer)
        end

        rule(:x, name: :parent_check) do
          key.failure("parent failure") if value < 0
        end
      end

      child = Class.new(parent) do
        params do
          required(:x).filled(:integer)
        end

        rule(:x, name: :child_check, depends_on: :parent_check) do
          key.failure("child failure") if value > 10
        end
      end

      failed = child.new.call(x: -1)

      expect(failed.errors.to_h).to eql(x: ["parent failure"])
      expect(failed.rule_results[:child_check]).to be_skipped
      expect(failed.rule_results[:child_check].unmet_dependencies).to eql(
        parent_check: :failed
      )

      passed = child.new.call(x: 1)

      expect(passed).to be_success
      expect(passed.rule_results[:parent_check]).to be_passed
      expect(passed.rule_results[:child_check]).to be_passed
    end

    it "detects a missing dependency through inheritance when instantiated" do
      parent = Class.new(Dry::Validation::Contract) do
        params do
          required(:x).filled(:integer)
        end
      end

      child = Class.new(parent) do
        params do
          required(:x).filled(:integer)
        end

        rule(:x, name: :child_check, depends_on: :never_defined) {}
      end

      expect { child.new }.to raise_error(Dry::Validation::MissingRuleError)
    end
  end
end
