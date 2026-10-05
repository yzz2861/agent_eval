# frozen_string_literal: true

RSpec.describe Money::RoundingReconciler do
  def fractionals(monies)
    monies.map(&:fractional)
  end

  shared_examples "a conserving reconciliation" do |currency, amounts, target, target_subunits|
    it "keeps every line within one subunit of its rounded value" do
      result = described_class.reconcile(amounts, target: target, currency: currency)

      rounded = amounts.map do |amount|
        (Money::Allocation.convert_to_big_decimal(amount) * Money::Currency.wrap(currency).subunit_to_unit)
          .round(0, Money.rounding_mode).to_i
      end

      fractionals(result.lines).each_with_index do |value, index|
        expect(value - rounded[index]).to be_between(-1, 1).inclusive
      end
    end

    it "conserves the target total exactly" do
      result = described_class.reconcile(amounts, target: target, currency: currency)

      expect(result.lines.sum(&:fractional)).to eq(target_subunits)
      expect(result.total).to eq(Money.new(target_subunits, currency))
    end

    it "makes lines equal rounded value plus adjustment" do
      result = described_class.reconcile(amounts, target: target, currency: currency)

      rounded = amounts.map do |amount|
        (Money::Allocation.convert_to_big_decimal(amount) * Money::Currency.wrap(currency).subunit_to_unit)
          .round(0, Money.rounding_mode).to_i
      end

      fractionals(result.lines).each_with_index do |value, index|
        expect(value).to eq(rounded[index] + result.adjustments[index].fractional)
      end
      expect(result.adjustments.sum(&:fractional)).to eq(target_subunits - rounded.sum)
    end

    it "is deterministic" do
      first = described_class.reconcile(amounts, target: target, currency: currency)
      second = described_class.reconcile(amounts, target: target, currency: currency)

      expect(first.lines).to eq(second.lines)
      expect(first.adjustments).to eq(second.adjustments)
    end
  end

  context "with USD (subunit_to_unit 100)" do
    it "adds the residual to the line rounded down the most" do
      result = described_class.reconcile(
        [BigDecimal("3.333"), BigDecimal("3.333"), BigDecimal("3.334")],
        target: Money.new(10_00, "USD"),
        currency: "USD",
      )

      expect(fractionals(result.lines)).to eq([333, 333, 334])
      expect(fractionals(result.adjustments)).to eq([0, 0, 1])
      expect(result.total).to eq(Money.new(10_00, "USD"))
    end

    it "removes the residual from the lines rounded up the most, breaking ties by line order" do
      result = described_class.reconcile(
        [BigDecimal("1.231"), BigDecimal("1.231")],
        target: BigDecimal("2.45"),
        currency: "USD",
      )

      expect(fractionals(result.lines)).to eq([122, 123])
      expect(fractionals(result.adjustments)).to eq([-1, 0])
    end

    it "handles negative lines with the same remainder rule" do
      result = described_class.reconcile(
        [BigDecimal("-1.005"), BigDecimal("2.005")],
        target: BigDecimal("1.01"),
        currency: "USD",
      )

      expect(fractionals(result.lines)).to eq([-100, 201])
      expect(fractionals(result.adjustments)).to eq([1, 0])
    end

    it "leaves zero lines untouched while other lines have remainders" do
      result = described_class.reconcile(
        [0, BigDecimal("1.004"), BigDecimal("1.004")],
        target: BigDecimal("2.01"),
        currency: "USD",
      )

      expect(fractionals(result.lines)).to eq([0, 101, 100])
      expect(fractionals(result.adjustments)).to eq([0, 1, 0])
    end

    it "adjusts a zero line as a last resort" do
      result = described_class.reconcile(
        [0, 0],
        target: BigDecimal("0.01"),
        currency: "USD",
      )

      expect(fractionals(result.lines)).to eq([1, 0])
      expect(fractionals(result.adjustments)).to eq([1, 0])
    end

    it "leaves lines alone when the rounded lines already match the target" do
      result = described_class.reconcile(
        [BigDecimal("1.00"), BigDecimal("2.00")],
        target: BigDecimal("3.00"),
        currency: "USD",
      )

      expect(fractionals(result.lines)).to eq([100, 200])
      expect(fractionals(result.adjustments)).to eq([0, 0])
    end

    it "accepts a Rational amount without losing precision" do
      result = described_class.reconcile(
        [Rational(10, 3), Rational(20, 3)],
        target: Money.new(10_00, "USD"),
        currency: "USD",
      )

      expect(fractionals(result.lines)).to eq([333, 667])
      expect(result.lines.sum(&:fractional)).to eq(1000)
    end

    it "returns Money results in whole subunits" do
      result = described_class.reconcile(
        [BigDecimal("3.333"), BigDecimal("3.333"), BigDecimal("3.334")],
        target: Money.new(10_00, "USD"),
        currency: "USD",
      )

      expect(result.lines).to all(be_a(Money))
      expect(result.adjustments).to all(be_a(Money))
      expect(result.lines.map(&:currency)).to all(eq(Money::Currency.wrap("USD")))
    end
  end

  context "with JPY (subunit_to_unit 1)" do
    it "reconciles in whole yen" do
      result = described_class.reconcile(
        [BigDecimal("100.4"), BigDecimal("100.4")],
        target: 201,
        currency: "JPY",
      )

      expect(fractionals(result.lines)).to eq([101, 100])
      expect(fractionals(result.adjustments)).to eq([1, 0])
    end
  end

  context "with BHD (subunit_to_unit 1000)" do
    it "reconciles in whole fils" do
      result = described_class.reconcile(
        [BigDecimal("0.0004"), BigDecimal("0.0004")],
        target: BigDecimal("0.001"),
        currency: "BHD",
      )

      expect(fractionals(result.lines)).to eq([1, 0])
      expect(fractionals(result.adjustments)).to eq([1, 0])
    end
  end

  context "with MRU (subunit_to_unit 5)" do
    it "reconciles in whole khoums" do
      result = described_class.reconcile(
        [BigDecimal("0.1"), BigDecimal("0.1")],
        target: BigDecimal("0.2"),
        currency: "MRU",
      )

      expect(fractionals(result.lines)).to eq([0, 1])
      expect(fractionals(result.adjustments)).to eq([-1, 0])
    end
  end

  context "conservation across currencies" do
    context "with USD" do
      it_behaves_like "a conserving reconciliation",
                      "USD",
                      [BigDecimal("3.333"), BigDecimal("3.333"), BigDecimal("3.334")],
                      Money.new(10_00, "USD"),
                      1000
    end

    context "with JPY" do
      it_behaves_like "a conserving reconciliation",
                      "JPY",
                      [BigDecimal("100.4"), BigDecimal("100.4"), BigDecimal("-50.2")],
                      150,
                      150
    end

    context "with BHD" do
      it_behaves_like "a conserving reconciliation",
                      "BHD",
                      [BigDecimal("0.0004"), BigDecimal("0.0004"), BigDecimal("0.0004")],
                      BigDecimal("0.001"),
                      1
    end

    context "with MRU" do
      it_behaves_like "a conserving reconciliation",
                      "MRU",
                      [BigDecimal("0.1"), BigDecimal("0.1")],
                      BigDecimal("0.2"),
                      1
    end

    context "with CLF" do
      it_behaves_like "a conserving reconciliation",
                      "CLF",
                      [BigDecimal("0.00004"), BigDecimal("0.00004")],
                      BigDecimal("0.0001"),
                      1
    end
  end

  context "with non-adjustable lines" do
    it "only nudges lines marked adjustable by a boolean mask" do
      result = described_class.reconcile(
        [BigDecimal("1.004"), BigDecimal("1.004"), BigDecimal("1.004")],
        target: BigDecimal("3.02"),
        currency: "USD",
        adjustable: [false, true, true],
      )

      expect(fractionals(result.lines)).to eq([100, 101, 101])
      expect(fractionals(result.adjustments)).to eq([0, 1, 1])
    end

    it "only nudges lines listed by index" do
      result = described_class.reconcile(
        [BigDecimal("1.004"), BigDecimal("1.004"), BigDecimal("1.004")],
        target: BigDecimal("3.01"),
        currency: "USD",
        adjustable: [2],
      )

      expect(fractionals(result.lines)).to eq([100, 100, 101])
      expect(fractionals(result.adjustments)).to eq([0, 0, 1])
    end

    it "raises when no line is adjustable" do
      expect do
        described_class.reconcile(
          [BigDecimal("1.004")],
          target: BigDecimal("1.01"),
          currency: "USD",
          adjustable: [false],
        )
      end.to raise_error(Money::RoundingReconciler::UnreachableTargetError, /cannot absorb a residual of 1/)
    end

    it "raises when the residual exceeds the adjustable capacity instead of changing the total" do
      expect do
        described_class.reconcile(
          [BigDecimal("1.001")],
          target: BigDecimal("1.03"),
          currency: "USD",
        )
      end.to raise_error(Money::RoundingReconciler::UnreachableTargetError, /cannot absorb a residual of 3/)
    end

    it "raises ArgumentError for a mask of the wrong size" do
      expect do
        described_class.reconcile(
          [BigDecimal("1.00")],
          target: BigDecimal("1.00"),
          currency: "USD",
          adjustable: [true, false],
        )
      end.to raise_error(ArgumentError, /one entry per line/)
    end

    it "raises ArgumentError for an out-of-range index" do
      expect do
        described_class.reconcile(
          [BigDecimal("1.00")],
          target: BigDecimal("1.00"),
          currency: "USD",
          adjustable: [7],
        )
      end.to raise_error(ArgumentError, /out of range/)
    end
  end

  context "with a mismatched target currency" do
    it "raises ArgumentError" do
      expect do
        described_class.reconcile(
          [BigDecimal("1.00")],
          target: Money.new(100, "EUR"),
          currency: "USD",
        )
      end.to raise_error(ArgumentError, /does not match/)
    end
  end
end
