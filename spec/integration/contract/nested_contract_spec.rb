# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::Contract, "nested contracts" do
  subject(:contract) { contract_class.new }

  let(:address_contract) do
    Class.new(Dry::Validation::Contract) do
      def self.name
        "AddressContract"
      end

      params do
        required(:street).filled(:string)
        required(:zip).filled(:integer)
      end

      rule(:zip) do
        key.failure("must be positive") if value <= 0
      end
    end.new
  end

  it "reuses a contract for a nested hash and merges its output" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:name).filled(:string)
        required(:address).hash
      end

      rule(:address).validate(contract: nested_contract)
    end

    result = contract_class.new.call(
      name: "Jane",
      address: {street: "Main Street", zip: "12"}
    )

    expect(result).to be_success
    expect(result.to_h).to eql(
      name: "Jane",
      address: {street: "Main Street", zip: 12}
    )
  end

  it "prefixes schema and rule errors of a nested contract" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:address).hash
      end

      rule(:address).validate(contract: nested_contract)
    end

    expect(
      contract_class.new.call(address: {street: "", zip: "-1"}).errors.to_h
    ).to eql(address: {street: ["must be filled"], zip: ["must be positive"]})
  end

  it "accepts the contract as a positional macro argument" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:address).hash
      end

      rule(:address).validate(nested_contract)
    end

    result = contract_class.new.call(address: {street: "Main", zip: "12"})

    expect(result).to be_success
    expect(result.to_h[:address]).to eql(street: "Main", zip: 12)
  end

  it "prefixes errors through deeply nested paths" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:order).hash do
          required(:shipping).hash
        end
      end

      rule(order: :shipping).validate(contract: nested_contract)
    end

    expect(
      contract_class.new.call(
        order: {shipping: {street: "", zip: "0"}}
      ).errors.to_h
    ).to eql(
      order: {
        shipping: {street: ["must be filled"], zip: ["must be positive"]}
      }
    )
  end

  it "merges errors and output from contracts nested inside another contract" do
    inner_contract = Class.new(Dry::Validation::Contract) do
      params do
        required(:zip).filled(:integer)
      end
    end.new

    middle_contract = Class.new(Dry::Validation::Contract) do
      params do
        required(:shipping).hash
      end

      rule(:shipping).validate(contract: inner_contract)
    end.new

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:address).hash
      end

      rule(:address).validate(contract: middle_contract)
    end

    result = contract_class.new.call(
      address: {shipping: {zip: "12"}}
    )

    expect(result).to be_success
    expect(result.to_h).to eql(
      address: {shipping: {zip: 12}}
    )

    invalid_result = contract_class.new.call(
      address: {shipping: {zip: "wrong"}}
    )

    expect(invalid_result.errors.to_h).to eql(
      address: {shipping: {zip: ["must be an integer"]}}
    )
  end

  it "reuses a contract for array elements and prefixes errors with indexes" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:addresses).array(:hash)
      end

      rule(:addresses).each(contract: nested_contract)
    end

    result = contract_class.new.call(
      addresses: [
        {street: "Main Street", zip: "12"},
        {street: "", zip: "0"},
        {street: "Second", zip: "wrong"}
      ]
    )

    expect(result.to_h).to eql(
      addresses: [
        {street: "Main Street", zip: 12},
        {street: "", zip: 0},
        {street: "Second", zip: "wrong"}
      ]
    )
    expect(result.errors.to_h).to eql(
      addresses: {
        1 => {street: ["must be filled"], zip: ["must be positive"]},
        2 => {zip: ["must be an integer"]}
      }
    )
  end

  it "does not run the nested contract when the parent schema rejected the value" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:addresses).array(:hash)
      end

      rule(:addresses).each(contract: nested_contract)
    end

    expect(contract_class.new.call(addresses: "wrong").errors.to_h).to eql(
      addresses: ["must be an array"]
    )
  end

  it "skips only array elements rejected by the parent schema" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:addresses).array(:hash)
      end

      rule(:addresses).each(contract: nested_contract)
    end

    result = contract_class.new.call(
      addresses: ["invalid", {street: "Main", zip: "12"}]
    )

    expect(result.to_h).to eql(
      addresses: ["invalid", {street: "Main", zip: 12}]
    )
    expect(result.errors.to_h).to eql(addresses: {0 => ["must be a hash"]})
  end

  it "does not run the nested contract when nested input is missing" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:name).filled(:string)
        optional(:address).hash
      end

      rule(:address).validate(contract: nested_contract)
    end

    expect(contract_class.new.call(name: "Jane", address: nil).errors.to_h).to eql(
      address: ["must be a hash"]
    )
  end

  it "skips later parent rules when the nested contract schema rejects a value" do
    nested_contract = address_contract

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:address).hash do
          optional(:street).value(:string)
        end
      end

      rule(:address).validate(contract: nested_contract)

      rule(address: :street) do
        key.failure("parent rule ran")
      end
    end

    expect(
      contract_class.new.call(address: {street: 1, zip: "1"}).errors.to_h
    ).to eql(address: {street: ["must be a string"]})
  end

  it "passes only declared parent context values to the nested contract" do
    localized_address_contract = Class.new(Dry::Validation::Contract) do
      params do
        required(:street).filled(:string)
      end

      rule(:street) do |context:|
        key.failure("received undeclared context") if context.key?(:secret)
        key.failure("needs country") unless context[:country] == "PL"
        context[:child_only] = true
        context[:country] = "DE"
      end
    end.new

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:address).hash
      end

      rule(:address).validate(contract: localized_address_contract, context: [:country])
    end

    result = contract_class.new.call(
      {address: {street: "Main"}},
      country: "PL", secret: "hidden"
    )

    expect(result).to be_success
    expect(result.context.each.to_h).to eql(
      country: "PL", secret: "hidden", child_only: true
    )
  end

  it "supports renaming parent context values for the nested contract" do
    localized_address_contract = Class.new(Dry::Validation::Contract) do
      params do
        required(:street).filled(:string)
      end

      rule(:street) do |context:|
        key.failure("needs country") unless context[:country_code] == "PL"
      end
    end.new

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:address).hash
      end

      rule(:address).validate(
        contract: localized_address_contract,
        context: {country_code: :country}
      )
    end

    result = contract_class.new.call({address: {street: "Main"}}, country: "PL")

    expect(result).to be_success
  end

  it "preserves message arguments for localized schema and rule errors" do
    I18n.available_locales = %i[en pl]

    localized_address_contract = Class.new(Dry::Validation::Contract) do
      config.messages.backend = :i18n
      config.messages.load_paths << SPEC_ROOT.join("fixtures/messages/errors.pl.yml").realpath
      config.messages.load_paths << SPEC_ROOT.join("fixtures/messages/errors.en.yml").realpath

      params do
        required(:email).filled(:string)
      end

      rule(:email) do
        key.failure(:invalid) unless value.include?("@")
      end
    end.new

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:address).hash
      end

      rule(:address).validate(contract: localized_address_contract)
    end

    result = contract_class.new.call(address: {email: "jane"})

    expect(result.errors(locale: :pl).to_h).to eql(
      address: {email: ["oh nie zły email"]}
    )
    expect(result.errors(locale: :en).to_h).to eql(
      address: {email: ["oh noez bad email"]}
    )
  end

  it "includes hints from nested contract schemas with prefixed paths" do
    Dry::Validation.load_extensions(:hints)

    localized_address_contract = Class.new(Dry::Validation::Contract) do
      params do
        required(:zip).filled(:string, size?: 2..4)
      end
    end.new

    contract_class = Class.new(Dry::Validation::Contract) do
      params do
        required(:addresses).array(:hash)
      end

      rule(:addresses).each(contract: localized_address_contract)
    end

    result = contract_class.new.call(addresses: [{zip: ""}])

    expect(result.hints.to_h).to eql(
      addresses: {0 => {zip: ["length must be within 2 - 4"]}}
    )
  end
end
