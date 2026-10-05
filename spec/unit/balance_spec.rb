# frozen_string_literal: true

RSpec.describe Dry::Validation::Balance do
  subject(:errors) do
    described_class.call(
      rows,
      group_by: %i[batch_id],
      unit: :currency,
      left: :debit,
      right: :credit,
      tolerance: tolerance,
      units: %w[CNY USD]
    )
  end

  let(:tolerance) { "0.01" }

  def row(batch_id:, currency:, debit: nil, credit: nil)
    {batch_id: batch_id, currency: currency, debit: debit, credit: credit}
  end

  context "with balanced groups" do
    let(:rows) do
      [
        row(batch_id: 1, currency: "CNY", debit: "100.00", credit: "60.00"),
        row(batch_id: 1, currency: "CNY", debit: "0.00", credit: "40.00"),
        row(batch_id: 2, currency: "USD", debit: "10.5", credit: "10.5")
      ]
    end

    it "returns no errors" do
      expect(errors).to be_empty
    end
  end

  context "with exact decimal arithmetic" do
    let(:rows) do
      [
        row(batch_id: 1, currency: "CNY", debit: "0.1", credit: "0.3"),
        row(batch_id: 1, currency: "CNY", debit: "0.2", credit: "0.0")
      ]
    end

    it "does not suffer from float rounding" do
      expect(errors).to be_empty
    end
  end

  context "with an unbalanced group" do
    let(:rows) do
      [
        row(batch_id: 1, currency: "CNY", debit: "100.00", credit: "60.00"),
        row(batch_id: 1, currency: "CNY", debit: "0.00", credit: "39.00"),
        row(batch_id: 2, currency: "USD", debit: "5", credit: "5")
      ]
    end

    it "reports the group, the difference and the row positions" do
      expect(errors).to eql(
        [
          {
            reason: :unbalanced,
            group: {batch_id: 1},
            unit: "CNY",
            left: BigDecimal("100.00"),
            right: BigDecimal("99.00"),
            difference: BigDecimal("1.00"),
            rows: [0, 1]
          }
        ]
      )
    end
  end

  context "with a difference within the explicit tolerance" do
    let(:tolerance) { "0.05" }

    let(:rows) do
      [row(batch_id: 1, currency: "CNY", debit: "100.00", credit: "100.04")]
    end

    it "passes" do
      expect(errors).to be_empty
    end
  end

  context "with a difference exceeding the tolerance" do
    let(:tolerance) { "0.05" }

    let(:rows) do
      [row(batch_id: 1, currency: "CNY", debit: "100.00", credit: "100.06")]
    end

    it "fails" do
      expect(errors.map { |error| error[:reason] }).to eql([:unbalanced])
    end
  end

  context "with amounts in different units" do
    let(:rows) do
      [
        row(batch_id: 1, currency: "CNY", debit: "100", credit: "0"),
        row(batch_id: 1, currency: "USD", debit: "0", credit: "100")
      ]
    end

    it "never lets units cancel each other out" do
      expect(errors.size).to be(2)
      expect(errors.map { |error| error[:unit] }).to contain_exactly("CNY", "USD")
      expect(errors).to all(include(reason: :unbalanced))
    end
  end

  context "with a missing amount" do
    let(:rows) do
      [
        row(batch_id: 1, currency: "CNY", debit: nil, credit: "100"),
        row(batch_id: 1, currency: "CNY", debit: "100", credit: "0")
      ]
    end

    it "reports an error instead of defaulting to zero" do
      expect(errors).to eql(
        [
          {
            reason: :missing_amount,
            group: {batch_id: 1},
            unit: "CNY",
            field: :debit,
            value: nil,
            rows: [0]
          }
        ]
      )
    end

    it "does not report a bogus unbalanced error for the tainted group" do
      expect(errors.map { |error| error[:reason] }).not_to include(:unbalanced)
    end
  end

  context "with an amount that fails to convert" do
    let(:rows) do
      [row(batch_id: 1, currency: "CNY", debit: "not-a-number", credit: "0")]
    end

    it "reports an error instead of defaulting to zero" do
      expect(errors).to eql(
        [
          {
            reason: :invalid_amount,
            group: {batch_id: 1},
            unit: "CNY",
            field: :debit,
            value: "not-a-number",
            rows: [0]
          }
        ]
      )
    end
  end

  context "with a non-finite amount" do
    let(:rows) do
      [row(batch_id: 1, currency: "CNY", debit: "Infinity", credit: "0")]
    end

    it "is treated as invalid" do
      expect(errors.map { |error| error[:reason] }).to eql([:invalid_amount])
    end
  end

  context "with an unsupported unit" do
    let(:rows) do
      [row(batch_id: 1, currency: "EUR", debit: "100", credit: "100")]
    end

    it "reports an error instead of defaulting to zero" do
      expect(errors).to eql(
        [
          {
            reason: :unsupported_unit,
            group: {batch_id: 1},
            unit: "EUR",
            rows: [0]
          }
        ]
      )
    end
  end

  context "with a missing unit" do
    let(:rows) do
      [row(batch_id: 1, currency: nil, debit: "100", credit: "100")]
    end

    it "reports an error" do
      expect(errors.map { |error| error[:reason] }).to eql([:unsupported_unit])
    end
  end

  context "with string keys" do
    let(:rows) do
      [
        {"batch_id" => 1, "currency" => "CNY", "debit" => "10", "credit" => "10"}
      ]
    end

    it "works the same as with symbol keys" do
      expect(errors).to be_empty
    end
  end

  context "without an explicit tolerance" do
    let(:rows) { [] }

    it "raises when the option is omitted" do
      expect {
        described_class.call(
          rows,
          group_by: %i[batch_id], unit: :currency,
          left: :debit, right: :credit,
          units: %w[CNY]
        )
      }.to raise_error(ArgumentError, /tolerance/)
    end

    context "when nil is passed" do
      let(:tolerance) { nil }

      it "raises" do
        expect { errors }.to raise_error(ArgumentError, /tolerance/)
      end
    end

    context "when a negative value is passed" do
      let(:tolerance) { "-1" }

      it "raises" do
        expect { errors }.to raise_error(ArgumentError, /tolerance/)
      end
    end
  end

  context "without an explicit list of units" do
    let(:rows) { [] }

    it "raises" do
      expect {
        described_class.call(
          rows,
          group_by: %i[batch_id], unit: :currency,
          left: :debit, right: :credit,
          tolerance: "0.01", units: []
        )
      }.to raise_error(ArgumentError, /units/)
    end
  end

  context "with a non-hash row" do
    let(:rows) { ["oops"] }

    it "raises" do
      expect { errors }.to raise_error(ArgumentError, /Hash/)
    end
  end

  describe ".message" do
    let(:rows) do
      [row(batch_id: 7, currency: "CNY", debit: "1.00", credit: "2.50")]
    end

    it "includes the group, the difference and the row positions" do
      message = described_class.message(errors.first)

      expect(message).to include("difference -1.5")
      expect(message).to include("{batch_id: 7}")
      expect(message).to include('"CNY"')
      expect(message).to include("rows 0")
    end
  end
end
