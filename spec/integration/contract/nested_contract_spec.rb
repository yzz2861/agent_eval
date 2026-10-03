# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::Contract, ".contract" do
  let(:address_contract_class) do
    Class.new(Dry::Validation::Contract) do
      def self.name
        "AddressContract"
      end

      params do
        required(:street).filled(:string)
        required(:zip).filled(:integer)
      end

      rule(:zip) do
        key.failure("must be greater than 0") if key? && value <= 0
      end
    end
  end

  context "applied to a nested key" do
    subject(:contract) { contract_class.new }

    let(:contract_class) do
      address_contract = address_contract_class

      Class.new(Dry::Validation::Contract) do
        def self.name
          "OrderContract"
        end

        params do
          required(:email).filled(:string)
          required(:address).filled(:hash)
          optional(:backup_address).maybe(:hash)
        end

        rule(:email) do
          key.failure("is invalid") unless value.include?("@")
        end

        contract :address, address_contract
        contract :backup_address, address_contract
      end
    end

    it "returns a success result when the nested contract passes" do
      result = contract.(email: "jane@doe.org", address: {street: "Main", zip: "123"})

      expect(result).to be_success
    end

    it "puts the nested contract output into the result values" do
      result = contract.(email: "jane@doe.org", address: {street: "Main", zip: "123"})

      expect(result.to_h[:address]).to eql(street: "Main", zip: 123)
    end

    it "imports nested schema errors with the key prepended to their paths" do
      result = contract.(email: "jane@doe.org", address: {zip: "abc"})

      expect(result.errors.to_h).to eql(
        address: {street: ["is missing"], zip: ["must be an integer"]}
      )
    end

    it "imports nested rule errors with the key prepended to their paths" do
      result = contract.(email: "jane@doe.org", address: {street: "Main", zip: 0})

      expect(result.errors.to_h).to eql(address: {zip: ["must be greater than 0"]})
    end

    it "combines nested errors with the parent contract errors" do
      result = contract.(email: "jane", address: {street: "Main", zip: 0})

      expect(result.errors.to_h).to eql(
        email: ["is invalid"], address: {zip: ["must be greater than 0"]}
      )
    end

    it "merges the nested output even when the nested contract fails" do
      input = {street: "Main", zip: "abc"}
      result = contract.(email: "jane@doe.org", address: input)

      expect(result.to_h[:address]).to eql(address_contract_class.new.(input).to_h)
    end

    it "does not apply the nested contract when the parent schema rejected the value" do
      result = contract.(email: "jane@doe.org", address: "not-a-hash")

      expect(result.errors.to_h).to eql(address: ["must be a hash"])
    end

    it "does not apply the nested contract when the key is missing" do
      result = contract.(email: "jane@doe.org", address: {street: "Main", zip: 1})

      expect(result).to be_success
    end

    it "does not apply the nested contract when the value is nil" do
      result = contract.(
        email: "jane@doe.org",
        address: {street: "Main", zip: 1},
        backup_address: nil
      )

      expect(result).to be_success
    end
  end

  context "applied to a deeply nested key" do
    subject(:contract) { contract_class.new }

    let(:contract_class) do
      address_contract = address_contract_class

      Class.new(Dry::Validation::Contract) do
        params do
          required(:order).hash do
            required(:address).filled(:hash)
          end
        end

        contract "order.address", address_contract
      end
    end

    it "imports errors with the full path prepended" do
      result = contract.(order: {address: {street: "Main", zip: 0}})

      expect(result.errors.to_h).to eql(order: {address: {zip: ["must be greater than 0"]}})
    end

    it "puts the nested output into the result values" do
      result = contract.(order: {address: {street: "Main", zip: "123"}})

      expect(result.to_h[:order][:address]).to eql(street: "Main", zip: 123)
    end

    it "does not apply the nested contract when an ancestor was rejected" do
      result = contract.(order: "not-a-hash")

      expect(result.errors.to_h).to eql(order: ["must be a hash"])
    end

    it "does not apply the nested contract when the nested key is missing" do
      result = contract.(order: {})

      expect(result.errors.to_h).to eql(order: {address: ["is missing"]})
    end
  end

  context "applied to each element of an array" do
    subject(:contract) { contract_class.new }

    let(:contract_class) do
      address_contract = address_contract_class

      Class.new(Dry::Validation::Contract) do
        params do
          required(:addresses).array(:hash)
        end

        contract :addresses, address_contract, each: true
      end
    end

    it "returns a success result when all elements pass" do
      result = contract.(addresses: [{street: "Main", zip: 1}, {street: "Oak", zip: 2}])

      expect(result).to be_success
    end

    it "imports errors with the element index included in their paths" do
      result = contract.(addresses: [{street: "Main", zip: 0}, {zip: 1}])

      expect(result.errors.to_h).to eql(
        addresses: {
          0 => {zip: ["must be greater than 0"]},
          1 => {street: ["is missing"]}
        }
      )
    end

    it "puts the nested outputs into the result values" do
      result = contract.(addresses: [{street: "Main", zip: "123"}])

      expect(result.to_h[:addresses]).to eql([{street: "Main", zip: 123}])
    end

    it "does not apply the nested contract to elements rejected by the parent schema" do
      result = contract.(addresses: ["not-a-hash", {street: "Main", zip: 1}])

      expect(result.errors.to_h).to eql(addresses: {0 => ["must be a hash"]})
    end

    it "does not apply the nested contract when the array itself was rejected" do
      result = contract.(addresses: "not-an-array")

      expect(result.errors.to_h).to eql(addresses: ["must be an array"])
    end

    context "when the key is optional" do
      let(:contract_class) do
        address_contract = address_contract_class

        Class.new(Dry::Validation::Contract) do
          params do
            optional(:addresses).maybe(:array)
          end

          contract :addresses, address_contract, each: true
        end
      end

      it "does not apply the nested contract when the key is missing" do
        expect(contract.({})).to be_success
      end

      it "does not apply the nested contract when the value is nil" do
        expect(contract.(addresses: nil)).to be_success
      end
    end
  end

  context "when the nested contract adds base errors" do
    subject(:contract) { contract_class.new }

    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:address).filled(:hash)
        end

        contract :address, Class.new(Dry::Validation::Contract) {
          params do
            required(:street).filled(:string)
          end

          rule do
            base.failure("is not deliverable") if values[:street] == "Nowhere"
          end
        }
      end
    end

    it "imports base errors under the nested key" do
      result = contract.(address: {street: "Nowhere"})

      expect(result.errors.to_h).to eql(address: ["is not deliverable"])
    end
  end

  context "with context" do
    let(:entry_contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:code).filled(:string)
        end

        rule(:code) do |context:|
          key.failure("wrong tenant") if context[:tenant] == "t2"
          key.failure("other leaked") if context.key?(:other)
          context[:from_child] = true
        end
      end
    end

    let(:contract_class) do
      entry_contract = entry_contract_class

      Class.new(Dry::Validation::Contract) do
        params do
          required(:entry).filled(:hash)
        end

        contract :entry, entry_contract, context: [:tenant]
      end
    end

    it "passes the declared context keys to the nested contract" do
      result = contract_class.new.({entry: {code: "x"}}, tenant: "t2")

      expect(result.errors.to_h).to eql(entry: {code: ["wrong tenant"]})
    end

    it "does not pass context keys that were not declared" do
      result = contract_class.new.({entry: {code: "x"}}, other: "value")

      expect(result.errors.to_h).to be_empty
    end

    it "does not let nested context additions leak into the parent context" do
      result = contract_class.new.({entry: {code: "x"}}, tenant: "t1")

      expect(result.context.each.to_h).to eql(tenant: "t1")
    end

    context "with a key mapping" do
      let(:contract_class) do
        entry_contract = entry_contract_class

        Class.new(Dry::Validation::Contract) do
          params do
            required(:entry).filled(:hash)
          end

          contract :entry, entry_contract, context: {tenant: :current_tenant}
        end
      end

      it "passes parent context values under the mapped names" do
        result = contract_class.new.({entry: {code: "x"}}, current_tenant: "t2")

        expect(result.errors.to_h).to eql(entry: {code: ["wrong tenant"]})
      end
    end
  end

  context "with translated messages" do
    subject(:contract) { contract_class.new }

    let(:address_contract_class) do
      Class.new(Dry::Validation::Contract) do
        config.messages.backend = :i18n

        [:en, :pl].each do |locale|
          config.messages.load_paths <<
            SPEC_ROOT.join("fixtures/messages/nested_contract.#{locale}.yml").realpath
        end

        params do
          required(:street).filled(:string)
          required(:zip).filled(:string)
        end

        rule(:zip) do
          key.failure(:invalid_zip, zip: value) if key? && value != "12345"
        end
      end
    end

    let(:contract_class) do
      address_contract = address_contract_class

      Class.new(Dry::Validation::Contract) do
        config.messages.backend = :i18n

        params do
          required(:address).filled(:hash)
        end

        contract :address, address_contract
      end
    end

    before do
      I18n.available_locales = [:en, :pl]
    end

    it "imports nested rule messages that can be evaluated with another locale" do
      result = contract.(address: {street: "Main", zip: "999"})

      expect(result.errors.to_h).to eql(address: {zip: ["999 is not a valid zip"]})
      expect(result.errors(locale: :pl).to_h).to eql(
        address: {zip: ["999 jest nieprawidlowym kodem"]}
      )
    end

    it "imports nested schema messages that can be evaluated with another locale" do
      result = contract.(address: {street: "", zip: "12345"})

      expect(result.errors.to_h).to eql(address: {street: ["must be filled"]})
      expect(result.errors(locale: :pl).to_h).to eql(
        address: {street: ["cannot be empty (pl)"]}
      )
    end

    it "supports full messages" do
      result = contract.(address: {street: "Main", zip: "999"})

      expect(result.errors(full: true).map(&:to_s)).to eql(["zip 999 is not a valid zip"])
    end
  end

  describe ".contract" do
    it "accepts a contract instance" do
      entry_contract_class = Class.new(Dry::Validation::Contract) do
        option :suffix

        params do
          required(:code).filled(:string)
        end

        rule(:code) do
          key.failure("must end with #{suffix}") unless value.end_with?(suffix)
        end
      end

      contract_class = Class.new(Dry::Validation::Contract) do
        params do
          required(:entry).filled(:hash)
        end

        contract :entry, entry_contract_class.new(suffix: "!")
      end

      result = contract_class.new.(entry: {code: "abc"})

      expect(result.errors.to_h).to eql(entry: {code: ["must end with !"]})
    end

    it "accepts a hash key specification" do
      address_contract = address_contract_class

      contract_class = Class.new(Dry::Validation::Contract) do
        params do
          required(:order).hash do
            required(:address).filled(:hash)
          end
        end

        contract({order: :address}, address_contract)
      end

      result = contract_class.new.(order: {address: {street: "Main", zip: 0}})

      expect(result.errors.to_h).to eql(
        order: {address: {zip: ["must be greater than 0"]}}
      )
    end

    it "expands multi-value hash keys into multiple paths" do
      address_contract = address_contract_class

      contract_class = Class.new(Dry::Validation::Contract) do
        params do
          required(:order).hash do
            required(:shipping_address).filled(:hash)
            required(:billing_address).filled(:hash)
          end
        end

        contract({order: [:shipping_address, :billing_address]}, address_contract)
      end

      result = contract_class.new.(order: {
        shipping_address: {street: "Main", zip: 0},
        billing_address: {street: "Oak", zip: 0}
      })

      expect(result.errors.to_h).to eql(
        order: {
          shipping_address: {zip: ["must be greater than 0"]},
          billing_address: {zip: ["must be greater than 0"]}
        }
      )
    end

    it "raises ArgumentError when the contract is not a Dry::Validation::Contract" do
      expect {
        Class.new(Dry::Validation::Contract) do
          params do
            required(:address).filled(:hash)
          end

          contract :address, "not-a-contract"
        end
      }.to raise_error(ArgumentError, /must be a Dry::Validation::Contract/)
    end

    it "raises InvalidKeysError when the key is not defined in the schema" do
      expect {
        Class.new(Dry::Validation::Contract) do
          def self.name
            "OrderContract"
          end

          params do
            required(:email).filled(:string)
          end

          contract :address, Class.new(Dry::Validation::Contract) {
            params do
              required(:street).filled(:string)
            end
          }
        end
      }.to raise_error(
        Dry::Validation::InvalidKeysError,
        /OrderContract.contract specifies keys that are not defined by the schema/
      )
    end

    it "is inherited by subclasses" do
      address_contract = address_contract_class

      contract_class = Class.new(Dry::Validation::Contract) do
        params do
          required(:address).filled(:hash)
        end

        contract :address, address_contract
      end

      subclass = Class.new(contract_class) do
        params do
          required(:email).filled(:string)
        end
      end

      result = subclass.new.(email: "jane@doe.org", address: {street: "Main", zip: 0})

      expect(result.errors.to_h).to eql(address: {zip: ["must be greater than 0"]})
    end
  end
end
