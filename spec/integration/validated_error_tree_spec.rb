# frozen_string_literal: true

RSpec.describe("Validated::ErrorTree in a nested form") do
  include Dry::Monads::Validated::Mixin

  let(:error_tree) { Dry::Monads::Validated::ErrorTree }
  let(:validated) { Dry::Monads::Validated }
  let(:validated_list) { Dry::Monads::List::Validated }

  let(:form) do
    {
      name: nil,
      email: "jane@example.com",
      addresses: [
        { street: "", city: "Paris", zip: "75001" },
        { street: "Main St", city: "", zip: "??" }
      ]
    }
  end

  let(:expected_errors) do
    error_tree.new(
      :name => :blank,
      [:addresses, 0, :street] => :blank,
      [:addresses, 1, :city] => :blank,
      [:addresses, 1, :zip] => :bad_format
    )
  end

  # Each validation runs independently. Instead of a flat array, every error
  # is attached to the field it belongs to.
  def validate_field(path, value, *codes)
    codes << :blank if codes.empty?

    invalid =
      if value.nil? || value.to_s.empty?
        :blank
      elsif path.last == :zip && value !~ /\A\d{5}\z/
        codes.first
      end

    if invalid
      Invalid(error_tree.new([[path, invalid]]))
    else
      Valid(value)
    end
  end

  def validate_address(address)
    street = validate_field([:street], address[:street])
    city = validate_field([:city], address[:city])
    zip_code = validate_field([:zip], address[:zip], :bad_format)

    validated
      .pure { |street_value, city_value, zip_value|
        { street: street_value, city: city_value, zip: zip_value }
      }
      .apply(street)
      .apply(city)
      .apply(zip_code)
  end

  def validate_addresses(addresses)
    validated_list[*addresses.map { validate_address(_1) }]
      .traverse
      .alt_map { |errors| errors.prefix(:addresses) }
  end

  def build_form(name:, email:, addresses:)
    validated
      .pure { |name_value, email_value, address_values|
        { name: name_value, email: email_value, addresses: address_values }
      }
      .apply(name)
      .apply(email)
      .apply(addresses)
  end

  it "collects every error from independent validations into one tree" do
    result = build_form(
      name: validate_field([:name], form[:name]),
      email: validate_field([:email], form[:email]),
      addresses: validate_addresses(form[:addresses])
    )

    expect(result).to eql(Invalid(expected_errors))
  end

  it "does not depend on the order in which fields are grouped" do
    name = validate_field([:name], form[:name])
    email = validate_field([:email], form[:email])
    addresses = validate_addresses(form[:addresses])

    grouped_last = build_form(name: name, email: email, addresses: addresses)

    grouped_first = validated
      .pure { |address_values, name_value, email_value|
        { name: name_value, email: email_value, addresses: address_values }
      }
      .apply(addresses)
      .apply(name)
      .apply(email)

    expect(grouped_first).to eql(grouped_last)
    expect(grouped_first).to eql(Invalid(expected_errors))
  end

  it "returns a valid value when every field is valid" do
    valid_form = {
      name: "Jane",
      email: "jane@example.com",
      addresses: [
        { street: "Main St", city: "Paris", zip: "75001" }
      ]
    }

    result = build_form(
      name: validate_field([:name], valid_form[:name]),
      email: validate_field([:email], valid_form[:email]),
      addresses: validate_addresses(valid_form[:addresses])
    )

    expect(result).to eql(Valid(
      name: "Jane",
      email: "jane@example.com",
      addresses: Dry::Monads::List[
        { street: "Main St", city: "Paris", zip: "75001" }
      ]
    ))
  end
end
