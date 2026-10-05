# frozen_string_literal: true

RSpec.describe Dry::Validation::Macros, ":balance" do
  subject(:contract) do
    Dry::Validation::Contract.build do
      schema do
        required(:lines).value(:array)
      end

      rule(:lines).validate(balance: {
                              group_by: %i[batch_id],
                              unit: :currency,
                              left: :debit,
                              right: :credit,
                              tolerance: "0.01",
                              units: %w[CNY USD]
                            })
    end
  end

  it "succeeds when every group balances" do
    result = contract.(
      lines: [
        {batch_id: 1, currency: "CNY", debit: "100.00", credit: "100.00"},
        {batch_id: 2, currency: "USD", debit: "10", credit: "10"}
      ]
    )

    expect(result).to be_success
  end

  it "fails when a group does not balance" do
    result = contract.(
      lines: [
        {batch_id: 1, currency: "CNY", debit: "100.00", credit: "60.00"},
        {batch_id: 1, currency: "CNY", debit: "0.00", credit: "39.00"}
      ]
    )

    expect(result).to be_failure
    message = 'left total 100.0 does not balance right total 99.0 (difference 1.0, group {batch_id: 1}, unit "CNY", rows 0, 1)'
    expect(result.errors.map(&:to_s)).to eql([message])
  end

  it "exposes the group, the difference and the row positions as error meta" do
    result = contract.(
      lines: [
        {batch_id: 1, currency: "CNY", debit: "100.00", credit: "60.00"},
        {batch_id: 1, currency: "CNY", debit: "0.00", credit: "39.00"}
      ]
    )

    error = result.errors.first

    expect(error.meta).to include(
      reason: :unbalanced,
      group: {batch_id: 1},
      unit: "CNY",
      difference: BigDecimal("1.00"),
      rows: [0, 1]
    )
  end

  it "fails when an amount is missing instead of treating it as zero" do
    result = contract.(
      lines: [
        {batch_id: 1, currency: "CNY", debit: nil, credit: "100.00"}
      ]
    )

    expect(result).to be_failure
    expect(result.errors.first.meta).to include(reason: :missing_amount, rows: [0])
  end

  it "fails when a unit is not supported" do
    result = contract.(
      lines: [
        {batch_id: 1, currency: "EUR", debit: "100.00", credit: "100.00"}
      ]
    )

    expect(result).to be_failure
    expect(result.errors.first.meta).to include(reason: :unsupported_unit, unit: "EUR")
  end

  it "requires an options hash" do
    contract_class = Class.new(Dry::Validation::Contract) do
      schema do
        required(:lines).value(:array)
      end

      rule(:lines).validate(:balance)
    end

    expect { contract_class.new.(lines: []) }.to raise_error(ArgumentError, /balance macro/)
  end
end
