# frozen_string_literal: true

RSpec.describe Dry::Validation::Macros, ":balance" do
  subject(:contract) do
    contract_class.new
  end

  let(:contract_class) do
    Class.new(Dry::Validation::Contract) do
      schema do
        required(:lines).value(:array)
      end

      rule(:lines).validate(
        balance: {
          group_by: :doc_id,
          unit: :currency,
          left: :debit,
          right: :credit,
          tolerance: {"USD" => "0.01", "JPY" => "1"}
        }
      )
    end
  end

  it "passes when every group balances within the per-unit tolerance" do
    result = contract.(
      lines: [
        {doc_id: "A", currency: "USD", debit: "10.00", credit: "9.995"},
        {doc_id: "A", currency: "JPY", debit: 100, credit: 100}
      ]
    )

    expect(result).to be_success
  end

  it "reports the group, unit, difference, tolerance and line positions" do
    result = contract.(
      lines: [
        {doc_id: "A", currency: "USD", debit: "10.00", credit: "10.00"},
        {doc_id: "A", currency: "USD", debit: "5.00", credit: "3.50"}
      ]
    )

    expect(result).to be_failure
    expect(result.errors[nil]).to eql([
      "left and right amounts do not balance for group A in USD: "\
      "difference 1.5 (tolerance 0.01), lines 1, 2"
    ])
  end

  it "keeps currencies separate instead of cancelling across units" do
    result = contract.(
      lines: [
        {doc_id: "A", currency: "USD", debit: 10, credit: 0},
        {doc_id: "A", currency: "JPY", debit: 0, credit: 10}
      ]
    )

    expect(result.errors[nil].size).to be(2)
  end

  it "attaches missing, bad and unsupported line problems to the line position" do
    result = contract.(
      lines: [
        {doc_id: "A", currency: "USD", debit: 1.0, credit: "1.00"},
        {doc_id: "A", currency: "EUR", debit: "1", credit: "1"},
        {doc_id: nil, currency: "USD", debit: "1", credit: "1"},
        {doc_id: "B", currency: "USD", debit: "oops", credit: ""}
      ]
    )

    expect(result.errors.to_h.fetch(:lines)).to eql(
      0 => {debit: ["debit must be an exact decimal amount"]},
      1 => {currency: ["EUR is not a supported unit"]},
      2 => {doc_id: ["doc_id is required"]},
      3 => {
        debit: ["debit must be an exact decimal amount"],
        credit: ["credit is required"]
      }
    )
  end

  it "succeeds when there are no lines" do
    expect(contract.(lines: [])).to be_success
  end

  it "raises when applied to a non-array value" do
    untyped = Class.new(Dry::Validation::Contract) do
      schema do
        required(:lines).value(:any)
      end

      rule(:lines).validate(
        balance: {
          group_by: :doc_id, unit: :currency, left: :debit, right: :credit,
          tolerance: "0"
        }
      )
    end.new

    expect {
      untyped.(lines: {})
    }.to raise_error(Dry::Validation::InvalidBalanceOptionError, /Array/)
  end

  context "with a scalar tolerance and supported units" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        schema do
          required(:lines).value(:array)
        end

        rule(:lines).validate(
          balance: {
            group_by: :doc_id,
            unit: :currency,
            left: :debit,
            right: :credit,
            tolerance: "0",
            supported_units: %w[USD]
          }
        )
      end
    end

    it "requires exact balance" do
      result = contract.(
        lines: [
          {doc_id: "A", currency: "USD", debit: "1.000000001", credit: "1"}
        ]
      )

      expect(result).to be_failure
    end
  end

  context "with composite group keys" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        schema do
          required(:lines).value(:array)
        end

        rule(:lines).validate(
          balance: {
            group_by: %i[company doc_id],
            unit: :currency,
            left: :debit,
            right: :credit,
            tolerance: "0"
          }
        )
      end
    end

    it "groups by all keys" do
      result = contract.(
        lines: [
          {company: "X", doc_id: "A", currency: "USD", debit: 5, credit: 4},
          {company: "Y", doc_id: "A", currency: "USD", debit: 4, credit: 5}
        ]
      )

      expect(result).to be_failure
      expect(result.errors[nil].join).to include("[").or include("X")
    end
  end

  it "raises without an explicit tolerance" do
    klass = Class.new(Dry::Validation::Contract) do
      schema do
        required(:lines).value(:array)
      end

      rule(:lines).validate(
        balance: {
          group_by: :doc_id, unit: :currency, left: :debit, right: :credit
        }
      )
    end

    expect {
      klass.new.(lines: [])
    }.to raise_error(Dry::Validation::InvalidBalanceOptionError, /tolerance/)
  end

  it "raises when the macro is used without an options hash" do
    klass = Class.new(Dry::Validation::Contract) do
      schema do
        required(:lines).value(:array)
      end

      rule(:lines).validate(:balance)
    end

    expect {
      klass.new.(lines: [])
    }.to raise_error(Dry::Validation::InvalidBalanceOptionError, /options hash/)
  end
end
