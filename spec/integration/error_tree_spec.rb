# frozen_string_literal: true

RSpec.describe(Dry::Monads::ErrorTree) do
  include Dry::Monads[:validated, :list, :error_tree]

  index = described_class::Index

  # A tiny form: a person has a name and a list of addresses.
  # Name, every street and every city are validated independently and
  # then composed into one complete error tree.
  before do
    class Test::AddressForm
      include Dry::Monads[:validated, :list, :error_tree]

      KNOWN_CITIES = %w[London Berlin].freeze

      class << self
        private

        def Valid(value) = Dry::Monads::Validated::Valid.new(value)

        def Invalid(error) = Dry::Monads::Validated::Invalid.new(error)

        def ErrorTree(errors) = Dry::Monads::ErrorTree.new(errors)
      end

      def self.call(form, order: %i[name addresses])
        checks = order.map { public_send("validate_#{_1}", form) }

        combine = Dry::Monads::Validated.pure { |name, addresses| { **form, name: name, addresses: addresses } }
        checks.reduce(combine) { |acc, check| acc.apply(check) }
      end

      def self.validate_name(form)
        if form[:name].to_s.empty?
          Invalid(ErrorTree.new({ [:name] => :blank }))
        else
          Valid(form[:name])
        end
      end

      def self.validate_addresses(form, group_order: %i[street city])
        elements = form[:addresses].map { validate_address(_1, group_order) }

        List::Validated[*elements].traverse.alt_map { _1.prepend(:addresses) }
      end

      def self.validate_address(address, group_order)
        checks = group_order.map do |field|
          case field
          when :street then validate_street(address)
          when :city then validate_city(address)
          end
        end

        combine = Dry::Monads::Validated.pure { |street, city| { **address, street: street, city: city } }
        checks.reduce(combine) { |acc, check| acc.apply(check) }
      end

      def self.validate_street(address)
        if address[:street].to_s.empty?
          Invalid(ErrorTree.new({ [:street] => :blank }))
        else
          Valid(address[:street])
        end
      end

      def self.validate_city(address)
        messages = []
        messages << :blank if address[:city].to_s.empty?
        messages << :unknown_city unless KNOWN_CITIES.include?(address[:city])

        if messages.empty?
          Valid(address[:city])
        else
          Invalid(ErrorTree.new({ [:city] => messages }))
        end
      end
    end
  end

  let(:form) do
    {
      name: "",
      addresses: [
        { street: "", city: "London" },
        { street: "Baker St", city: "" }
      ]
    }
  end

  let(:expected_tree) do
    described_class.new(
      {
        [:name] => [:blank],
        [:addresses, index[0], :street] => [:blank],
        [:addresses, index[1], :city] => [:blank, :unknown_city]
      }
    )
  end

  it "composes independent validations into one tree" do
    result = Test::AddressForm.call(form)

    expect(result).to be_a(Dry::Monads::Validated::Invalid)
    expect(result.error).to eql(expected_tree)
  end

    it "tells which address index every error belongs to" do
    result = Test::AddressForm.call(form)

    expect(result.error[[:addresses, index[0], :street]]).to eql([:blank])
    expect(result.error[[:addresses, index[1], :city]])
      .to eql([:blank, :unknown_city])
  end

  it "keeps several errors on the same path" do
    result = Test::AddressForm.call(form)

    expect(result.error[[:addresses, index[1], :city]]).to eql([:blank, :unknown_city])
  end

  it "returns Valid when every field is fine" do
    valid_form = {
      name: "John",
      addresses: [{ street: "Baker St", city: "London" }]
    }

    expect(Test::AddressForm.call(valid_form)).to be_a(Dry::Monads::Validated::Valid)
  end

  it "does not depend on the order of top-level groups" do
    name_first = Test::AddressForm.call(form, order: %i[name addresses])
    addresses_first = Test::AddressForm.call(form, order: %i[addresses name])

    expect(name_first.error).to eql(expected_tree)
    expect(addresses_first.error).to eql(expected_tree)
  end

  it "does not depend on the order of field groups inside addresses" do
    street_first = Test::AddressForm.validate_addresses(form, group_order: %i[street city])
    city_first = Test::AddressForm.validate_addresses(form, group_order: %i[city street])

    address_tree = described_class.new(
      {
        [:addresses, index[0], :street] => [:blank],
        [:addresses, index[1], :city] => [:blank, :unknown_city]
      }
    )

    expect(street_first.error).to eql(address_tree)
    expect(city_first.error).to eql(address_tree)
  end

  it "keeps the stable order of paths" do
    result = Test::AddressForm.call(form)

    expect(result.error.errors.keys).to eql(
      [
        [:name],
        [:addresses, index[0], :street],
        [:addresses, index[1], :city]
      ]
    )
  end
end
