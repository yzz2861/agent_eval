# frozen_string_literal: true

RSpec.describe Money::RoundingCoordinator do
  let(:klass) { described_class }

  describe ".reconcile" do
    context "with positive lines" do
      it "distributes the residual using the largest remainders" do
        result = klass.reconcile([Rational(100, 3)] * 3, 100, currency: "USD")

        expect(result.amounts.map(&:fractional)).to eq([34, 33, 33])
      end

      it "hands ties to earlier lines, deterministically" do
        result = klass.reconcile([Rational(1, 3)] * 3, 1, currency: "USD")

        expect(result.amounts.map(&:fractional)).to eq([1, 0, 0])
        expect(result.adjustments).to eq([1, 0, 0])
      end

      it "moves each adjusted line by at most one subunit" do
        result = klass.reconcile(
          [Rational(10, 4), Rational(10, 4), Rational(10, 4), Rational(10, 4)],
          10,
          currency: "USD",
        )

        # Half-up baseline is [3, 3, 3, 3] (sum 12); two subunits are removed
        # from the earliest tied lines.
        expect(result.amounts.map(&:fractional)).to eq([2, 2, 3, 3])
        expect(result.adjustments).to eq([-1, -1, 0, 0])
        expect(result.adjustments.map(&:abs).max).to eq(1)
      end

      it "returns no adjustment when the independent rounding already matches" do
        result = klass.reconcile([1.5r, 1.5r], 4, currency: "USD")

        expect(result.amounts.map(&:fractional)).to eq([2, 2])
        expect(result.adjustments).to eq([0, 0])
      end
    end

    context "with different subunit_to_unit values" do
      it "splits 1000 fils into three lines for KWD (subunit_to_unit 1000)" do
        result = klass.reconcile([Rational(1000, 3)] * 3, 1000, currency: "KWD")

        expect(result.amounts.first.currency.subunit_to_unit).to eq(1000)
        expect(result.amounts.map(&:fractional)).to eq([334, 333, 333])
      end

      it "splits 10 dinars into three lines for BHD" do
        result = klass.reconcile([Rational(10_000, 3)] * 3, 10_000, currency: "BHD")

        expect(result.amounts.map(&:fractional)).to eq([3334, 3333, 3333])
        expect(result.total).to eq(Money.new(10_000, "BHD"))
      end

      it "only deals in whole yen for JPY (subunit_to_unit 1)" do
        result = klass.reconcile([1, 2, 3], 6, currency: "JPY")

        expect(result.amounts.map(&:fractional)).to eq([1, 2, 3])
        expect(result.adjustments).to eq([0, 0, 0])
        expect(result.total.currency).to eq(Money::Currency.new("JPY"))
      end
    end

    context "with negative lines" do
      it "uses the independent half-up baseline and adjusts by at most one" do
        result = klass.reconcile([Rational(-100, 3)] * 3, -100, currency: "USD")

        expect(result.amounts.map(&:fractional)).to eq([-34, -33, -33])
        expect(result.amounts.sum).to eq(result.total)
      end

      it "records adjustments relative to independent half-up rounding" do
        result = klass.reconcile([Rational(-1, 3)] * 3, -1, currency: "USD")

        # Independent rounding gives [0, 0, 0]; the residual pushes the first
        # line to -1.
        expect(result.amounts.map(&:fractional)).to eq([-1, 0, 0])
        expect(result.adjustments).to eq([-1, 0, 0])
      end

      it "reconciles a mix of positive and negative lines" do
        lines = [Rational(100, 3), Rational(100, 3), Rational(-100, 3)]
        result = klass.reconcile(lines, 33, currency: "USD")

        expect(result.amounts.map(&:fractional)).to eq([33, 33, -33])
        expect(result.adjustments).to eq([0, 0, 0])
      end
    end

    context "with zero lines" do
      it "keeps exact zero lines at zero" do
        result = klass.reconcile([0, 0.5r, 0.5r], 1, currency: "USD")

        expect(result.amounts.map(&:fractional)).to eq([0, 0, 1])
        expect(result.adjustments).to eq([0, -1, 0])
      end

      it "never moves a zero line even when it is the only adjustable line" do
        expect do
          # The locked 0.6 rounds to 1; target 0 cannot be reached by moving
          # only the exact-zero line.
          klass.reconcile([0r, 0.6r], 0, adjustable: [0], currency: "USD")
        end.to raise_error(klass::InfeasibleTarget, /reachable range: 1\.\.1/)
      end
    end

    context "with non-adjustable lines" do
      it "rounds locked lines independently and absorbs residual elsewhere" do
        result = klass.reconcile(
          [Rational(1, 3), Rational(1, 3), Rational(1, 3)],
          1,
          adjustable: [0],
          currency: "USD",
        )

        expect(result.amounts.map(&:fractional)).to eq([1, 0, 0])
        expect(result.adjustments).to eq([1, 0, 0])
      end

      it "accepts a boolean mask, a Range, and negative indices" do
        lines = [Rational(1, 3)] * 3

        by_mask = klass.reconcile(lines, 1, adjustable: [true, false, false], currency: "USD")
        by_range = klass.reconcile(lines, 1, adjustable: 0..0, currency: "USD")
        by_negative = klass.reconcile(lines, 1, adjustable: [-3], currency: "USD")

        expect(by_mask.amounts.map(&:fractional)).to eq([1, 0, 0])
        expect(by_range.amounts.map(&:fractional)).to eq([1, 0, 0])
        expect(by_negative.amounts.map(&:fractional)).to eq([1, 0, 0])
      end

      it "raises instead of forcing a locked line to move" do
        expect do
          klass.reconcile([0.6r, 0.6r, 0.6r], 1, adjustable: [], currency: "USD")
        end.to raise_error(klass::InfeasibleTarget, /reachable range: 3\.\.3/)
      end

      it "rounds locked lines with Money.rounding_mode" do
        lines = [0.5r, 0.5r]
        result = Money.with_rounding_mode(BigDecimal::ROUND_HALF_DOWN) do
          klass.reconcile(lines, 0, adjustable: [], currency: "USD")
        end

        expect(result.amounts.map(&:fractional)).to eq([0, 0])
      end
    end

    context "conservation" do
      it "keeps the per-line sum exactly equal to the target for every case" do
        lines = [Rational(250, 7), Rational(-180, 7), Rational(91, 7)]
        independently_rounded = lines.map { |line| BigDecimal(line.to_d(30).to_s).round.to_i }

        independent_sum = independently_rounded.sum
        (independent_sum - 2..independent_sum + 2).each do |target|
          result = klass.reconcile(lines, target, currency: "USD")

          expect(result.amounts.map(&:fractional).sum).to eq(target)
          expect(result.total.fractional).to eq(target)
          expect(result.amounts.sum).to eq(result.total)
          expect(result.adjustments.sum).to eq(target - independent_sum)
        end
      end

      it "uses exact arithmetic and is immune to binary floating point drift" do
        result = klass.reconcile([0.1, 0.2], 0, currency: "USD")

        expect(result.amounts.map(&:fractional)).to eq([0, 0])
        expect(result.adjustments).to eq([0, 0])
      end

      it "returns Money amounts in the resolved currency" do
        result = klass.reconcile([Rational(100, 3)] * 3, Money.new(100, "USD"))

        expect(result.amounts).to all(eq(Money.new(33, "USD")) | eq(Money.new(34, "USD")))
        expect(result.total).to eq(Money.new(100, "USD"))
      end

      it "satisfies conservation and per-line constraints across many cases" do
        currencies = {
          "USD" => 100,
          "KWD" => 1000,
          "JPY" => 1,
        }
        generator = Random.new(20261005)

        200.times do
          code, scale = currencies.to_a.sample(random: generator)
          size = generator.rand(1..8)
          lines = Array.new(size) do
            numerator = generator.rand(-3 * scale..3 * scale)
            denominator = generator.rand(1..7)
            Rational(numerator, denominator)
          end
          locked = lines.each_index.select { generator.rand < 0.3 }
          independently = lines.map do |line|
            BigDecimal(line.to_d(30).to_s).round(0, Money.rounding_mode).to_i
          end
          movable = lines.each_index.select do |index|
            !locked.include?(index) && !lines[index].zero? && lines[index].denominator != 1
          end
          min_total = independently.sum - movable.size
          max_total = independently.sum + movable.size
          target = generator.rand(min_total..max_total)

          allowed = locked.empty? ? nil : lines.each_index.to_a - locked
          result = klass.reconcile(lines, target, adjustable: allowed, currency: code)
          repeated = klass.reconcile(lines, target, adjustable: allowed, currency: code)

          expect(result.amounts.map(&:fractional).sum).to eq(target)
          expect(result.amounts.sum).to eq(result.total)
          expect(result.amounts.map(&:fractional)).to eq(repeated.amounts.map(&:fractional))
          expect(result.adjustments).to all(be_between(-1, 1))
          expect(result.adjustments.sum).to eq(target - independently.sum)
          lines.each_with_index do |line, index|
            expect(result.amounts[index].fractional).to eq(0) if line.zero?
            if locked.include?(index)
              expect(result.amounts[index].fractional).to eq(independently[index])
              expect(result.adjustments[index]).to eq(0)
            end
          end
        end
      end
    end

    context "when the target is infeasible" do
      it "raises when the target is above the reachable range" do
        expect do
          klass.reconcile([Rational(1, 3)] * 3, 4, currency: "USD")
        end.to raise_error(klass::InfeasibleTarget, /target of 4.*reachable range: -3\.\.3/m)
      end

      it "raises when the target is below the reachable range" do
        expect do
          klass.reconcile([Rational(-1, 3)] * 3, -4, currency: "USD")
        end.to raise_error(klass::InfeasibleTarget, /reachable range: -3\.\.3/)
      end

      it "raises when locked lines already overshoot the target" do
        expect do
          klass.reconcile([0.9r], 0, adjustable: [], currency: "USD")
        end.to raise_error(klass::InfeasibleTarget, /reachable range: 1\.\.1/)
      end
    end

    context "argument validation" do
      it "raises when line_amounts is missing or empty" do
        expect { klass.reconcile(nil, 0, currency: "USD") }.to raise_error(ArgumentError)
        expect { klass.reconcile([], 0, currency: "USD") }.to raise_error(ArgumentError)
      end

      it "raises when the target is not a whole number of subunits" do
        expect do
          klass.reconcile([1, 2], Rational(3, 2), currency: "USD")
        end.to raise_error(ArgumentError, /whole number of subunits/)
      end

      it "raises on an out of range adjustable index" do
        expect do
          klass.reconcile([1, 2], 3, adjustable: [5], currency: "USD")
        end.to raise_error(ArgumentError, /out of range/)
      end

      it "raises on an unsupported adjustable selector" do
        expect do
          klass.reconcile([1, 2], 3, adjustable: "0", currency: "USD")
        end.to raise_error(ArgumentError)
      end

      it "raises when Money inputs use different currencies" do
        expect do
          klass.reconcile([Money.new(1, "USD")], Money.new(1, "EUR"))
        end.to raise_error(ArgumentError, /single currency/)
      end

      it "raises when an explicit currency conflicts with Money inputs" do
        expect do
          klass.reconcile([Money.new(1, "USD")], 1, currency: "EUR")
        end.to raise_error(ArgumentError, /does not match/)
      end
    end

    context "result" do
      it "is a value object with amounts, adjustments and total" do
        result = klass.reconcile([Rational(100, 3)] * 3, 100, currency: "USD")

        expect(result).to respond_to(:amounts)
        expect(result).to respond_to(:adjustments)
        expect(result).to respond_to(:total)
        expect(result.amounts.size).to eq(3)
        expect(result.adjustments.size).to eq(3)
      end
    end
  end

  describe "Money.reconcile_line_amounts" do
    it "delegates to the coordinator" do
      result = Money.reconcile_line_amounts(
        [Rational(100, 3)] * 3,
        100,
        adjustable: [0, 1, 2],
        currency: "USD",
      )

      expect(result).to be_a(Money::RoundingCoordinator::Result)
      expect(result.amounts.map(&:fractional)).to eq([34, 33, 33])
      expect(result.total).to eq(Money.new(100, "USD"))
    end

    it "uses the default currency when no currency is given" do
      result = Money.reconcile_line_amounts([Rational(2, 3), Rational(2, 3)], 1)

      expect(result.total.currency).to eq(Money.default_currency)
      expect(result.amounts.map(&:fractional)).to eq([0, 1])
    end
  end
end
