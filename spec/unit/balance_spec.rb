# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::Balance do
  subject(:balance) do
    described_class.new(
      group_by: :group,
      unit: :currency,
      left: :debit,
      right: :credit,
      tolerance: tolerance
    )
  end

  let(:tolerance) { BigDecimal("0") }

  def line(group:, currency:, debit:, credit:)
    {group: group, currency: currency, debit: debit, credit: credit}
  end

  describe ".call" do
    it "returns no violations when sides balance exactly" do
      rows = [
        line(group: "A", currency: "USD", debit: "10.10", credit: "5.05"),
        line(group: "A", currency: "USD", debit: "0.05", credit: "5.10")
      ]

      expect(described_class.call(rows, **options(tolerance: "0"))).to eql([])
    end

    it "uses BigDecimal arithmetic instead of floating point drift" do
      rows = [
        line(group: "A", currency: "USD", debit: "0.1", credit: "0.2"),
        line(group: "A", currency: "USD", debit: "0.3", credit: "0.2")
      ]

      expect(described_class.call(rows, **options(tolerance: "0"))).to eql([])
    end

    it "never lets amounts in different units cancel each other" do
      rows = [
        line(group: "A", currency: "USD", debit: 10, credit: 0),
        line(group: "A", currency: "EUR", debit: 0, credit: 10)
      ]

      violations = described_class.call(rows, **options(tolerance: "0"))

      expect(violations.map(&:code)).to eql(%i[imbalance imbalance])
      expect(violations.map(&:unit)).to eql(%w[EUR USD])
      expect(violations.map(&:difference)).to eql([
        BigDecimal("-10"), BigDecimal("10")
      ])
    end

    it "never lets different groups cancel each other" do
      rows = [
        line(group: "A", currency: "USD", debit: 10, credit: 0),
        line(group: "B", currency: "USD", debit: 0, credit: 10)
      ]

      violations = described_class.call(rows, **options(tolerance: "0"))

      expect(violations.map(&:group)).to eql(%w[A B])
      expect(violations.map(&:difference)).to eql([
        BigDecimal("10"), BigDecimal("-10")
      ])
    end

    it "reports the difference, tolerance and participating line positions" do
      rows = [
        line(group: "A", currency: "USD", debit: "10.00", credit: "8.50"),
        line(group: "A", currency: "USD", debit: "1.00", credit: "1.00"),
        line(group: "A", currency: "USD", debit: "0.00", credit: "1.00")
      ]

      violations = described_class.call(rows, **options(tolerance: "0.01"))

      expect(violations.size).to be(1)
      violation = violations.first
      expect(violation.code).to be(:imbalance)
      expect(violation.group).to eql("A")
      expect(violation.unit).to eql("USD")
      expect(violation.difference).to eql(BigDecimal("0.5"))
      expect(violation.tolerance).to eql(BigDecimal("0.01"))
      expect(violation.positions).to eql([1, 2, 3])
    end

    it "accepts differences within an explicit tolerance" do
      rows = [
        line(group: "A", currency: "USD", debit: "10.00", credit: "9.995")
      ]

      expect(described_class.call(rows, **options(tolerance: "0.01"))).to eql([])
    end

    it "supports per-unit tolerances" do
      rows = [
        line(group: "A", currency: "USD", debit: "10.00", credit: "9.995"),
        line(group: "A", currency: "JPY", debit: 100, credit: 99)
      ]
      opts = options(tolerance: {"USD" => "0.01", "JPY" => "1"})

      expect(described_class.call(rows, **opts)).to eql([])
    end

    it "normalizes equivalent unit representations when grouping" do
      rows = [
        line(group: "A", currency: :USD, debit: 5, credit: 3),
        line(group: "A", currency: "USD", debit: 3, credit: 5)
      ]

      expect(described_class.call(rows, **options(tolerance: "0"))).to eql([])
    end

    it "reports missing values instead of treating them as zero" do
      rows = [
        {group: "A", currency: "USD", debit: nil, credit: 1},
        {group: "A", currency: "USD", debit: 1, credit: ""},
        {group: "A", debit: 1, credit: 1},
        {currency: "USD", debit: 1, credit: 1}
      ]

      violations = described_class.call(rows, **options(tolerance: "0"))

      expect(violations.map(&:code)).to eql(%i[missing missing missing missing])
      expect(violations.map(&:field)).to eql(%i[debit credit currency group])
      expect(violations.map(&:positions)).to eql([[1], [2], [3], [4]])
      expect(described_class.call(rows, **options(tolerance: "0")).size).to be(4)
    end

    it "reports amounts that cannot be converted instead of using zero" do
      rows = [
        line(group: "A", currency: "USD", debit: "abc", credit: 1),
        line(group: "A", currency: "USD", debit: 1, credit: :one)
      ]

      violations = described_class.call(rows, **options(tolerance: "0"))

      expect(violations.map(&:code)).to eql(%i[invalid_amount invalid_amount])
      expect(violations.map(&:field)).to eql(%i[debit credit])
    end

    it "rejects Float amounts because they are not exact decimals" do
      rows = [line(group: "A", currency: "USD", debit: 0.1, credit: "0.1")]

      violations = described_class.call(rows, **options(tolerance: "0"))

      expect(violations.map(&:code)).to eql(%i[invalid_amount])
    end

    it "reports unsupported units without balancing the line" do
      rows = [line(group: "A", currency: "BTC", debit: 1, credit: 1)]
      opts = options(
        tolerance: "0", supported_units: %w[USD EUR]
      )

      violations = described_class.call(rows, **opts)

      expect(violations.map(&:code)).to eql(%i[unsupported_unit])
      expect(violations.first.field).to be(:currency)
      expect(violations.first.unit).to eql("BTC")
    end

    it "treats tolerance hash keys as the set of supported units" do
      rows = [line(group: "A", currency: "BTC", debit: 1, credit: 1)]
      opts = options(tolerance: {"USD" => "0"})

      violations = described_class.call(rows, **opts)

      expect(violations.map(&:code)).to eql(%i[unsupported_unit])
    end

    it "supports composite group keys" do
      rows = [
        {group: "A", sub: 1, currency: "USD", debit: 5, credit: 4},
        {group: "A", sub: 2, currency: "USD", debit: 4, credit: 5}
      ]
      opts = options(group_by: %i[group sub], tolerance: "0")

      violations = described_class.call(rows, **opts)

      expect(violations.map(&:group)).to eql([["A", 1], ["A", 2]])
    end

    it "uses 1-based line positions" do
      rows = [
        line(group: "A", currency: "USD", debit: "0", credit: "0"),
        line(group: "A", currency: "USD", debit: "1", credit: "0")
      ]

      violation = described_class.call(rows, **options(tolerance: "0")).first

      expect(violation.positions).to eql([1, 2])
    end

    def options(overrides)
      {
        group_by: :group,
        unit: :currency,
        left: :debit,
        right: :credit,
        **overrides
      }
    end
  end

  describe "configuration" do
    [nil, "not a decimal"].each do |bad_tolerance|
      it "raises when tolerance #{bad_tolerance.inspect} cannot be used" do
        expect {
          described_class.new(
            group_by: :group, unit: :currency, left: :debit, right: :credit,
            tolerance: bad_tolerance
          )
        }.to raise_error(Dry::Validation::InvalidBalanceOptionError)
      end
    end

    it "requires an explicit tolerance" do
      expect {
        described_class.new(
          group_by: :group, unit: :currency, left: :debit, right: :credit,
          tolerance: nil
        )
      }.to raise_error(Dry::Validation::InvalidBalanceOptionError, /explicit/)
    end

    it "rejects negative tolerances" do
      expect {
        described_class.new(
          group_by: :group, unit: :currency, left: :debit, right: :credit,
          tolerance: "-0.01"
        )
      }.to raise_error(Dry::Validation::InvalidBalanceOptionError, /negative/)
    end

    it "requires at least one group key" do
      expect {
        described_class.new(
          group_by: [], unit: :currency, left: :debit, right: :credit,
          tolerance: "0"
        )
      }.to raise_error(Dry::Validation::InvalidBalanceOptionError, /group_by/)
    end

    it "rejects supported units that do not match the tolerance hash" do
      expect {
        described_class.new(
          group_by: :group, unit: :currency, left: :debit, right: :credit,
          tolerance: {"USD" => "0"}, supported_units: %w[USD EUR]
        )
      }.to raise_error(Dry::Validation::InvalidBalanceOptionError, /supported_units/)
    end

    it "raises when a row is not a Hash" do
      expect {
        balance.call(["nope"])
      }.to raise_error(ArgumentError, /must be Hashes/)
    end
  end
end
