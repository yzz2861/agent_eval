# frozen_string_literal: true

RSpec.describe Money::Allocation do
  context "when given number as argument" do
    it "raises an error when invalid argument is given" do
      expect { described_class.generate(100, 0) }.to raise_error(ArgumentError)
      expect { described_class.generate(100, -1) }.to raise_error(ArgumentError)
    end

    context "with whole amounts" do
      it "returns the amount when 1 is given" do
        expect(described_class.generate(100, 1)).to eq([100])
      end

      it "splits the amount into equal parts" do
        expect(described_class.generate(100, 2)).to eq([50, 50])
        expect(described_class.generate(100, 4)).to eq([25, 25, 25, 25])
        expect(described_class.generate(100, 5)).to eq([20, 20, 20, 20, 20])
      end

      it "does not lose pennies" do
        expect(described_class.generate(5, 2)).to eq([3, 2])
        expect(described_class.generate(2, 3)).to eq([1, 1, 0])
        expect(described_class.generate(100, 3)).to eq([34, 33, 33])
        expect(described_class.generate(100, 6)).to eq([17, 17, 17, 17, 16, 16])
      end
    end

    context "with fractional amounts" do
      it "returns the amount when 1 is given" do
        expect(described_class.generate(BigDecimal(100), 1, false)).to eq([BigDecimal(100)])
      end

      it "splits the amount into equal parts" do
        expect(described_class.generate(BigDecimal(100), 2, false)).to eq([50, 50])
        expect(described_class.generate(BigDecimal(100), 4, false)).to eq([25, 25, 25, 25])
        expect(described_class.generate(BigDecimal(100), 5, false)).to eq([20, 20, 20, 20, 20])
      end

      it "splits the amount into equal fractions" do
        expect(described_class.generate(BigDecimal(5), 2, false)).to eq([2.5, 2.5])
        expect(described_class.generate(BigDecimal(5), 4, false)).to eq([1.25, 1.25, 1.25, 1.25])
      end

      it "converts a rational with Money.conversion_precision instead of through a float" do
        expect(described_class.generate(Rational(2, 3), 1, false)).to eq([BigDecimal("0.6666666666666667")])
        expect(described_class.generate(Rational(10**400, 1), 1, false)).to eq([BigDecimal("1e400")])
        expect(described_class.generate(Rational(1, 10**400), 1, false)).to eq([BigDecimal("1e-400")])
      end

      it "handles splits into repeating decimals" do
        amount = BigDecimal(100)
        parts = described_class.generate(amount, 3, false)

        # Rounding due to inconsistent BigDecimal size in ruby compared to jruby. In reality the
        # first 2 elements will look like the last one with a '5' at the end, compensating for a
        # missing fraction
        expect(parts.map { |x| x.round(10) }).to eq(
          [
            BigDecimal("33.3333333333"),
            BigDecimal("33.3333333333"),
            BigDecimal("33.3333333333"),
          ],
        )
        expect(parts.sum).to eq(amount)
      end
    end
  end

  context "when given array as argument" do
    it "raises an error when invalid argument is given" do
      expect { described_class.generate(100, []) }.to raise_error(ArgumentError)
    end

    context "with whole amounts" do
      it "returns the amount when array contains only one element" do
        expect(described_class.generate(100, [1])).to eq([100])
        expect(described_class.generate(100, [5])).to eq([100])
      end

      it "splits the amount into whole parts respecting the order" do
        expect(described_class.generate(100, [1, 1])).to eq([50, 50])
        expect(described_class.generate(100, [1, 1, 2])).to eq([25, 25, 50])
        expect(described_class.generate(100, [7, 3])).to eq([70, 30])
      end

      it "accepts floats as arguments" do
        expect(described_class.generate(100, [1.0, 1.0])).to eq([50, 50])
        expect(described_class.generate(100, [0.1, 0.1, 0.2])).to eq([25, 25, 50])
        expect(described_class.generate(100, [0.07, 0.03])).to eq([70, 30])
        expect(described_class.generate(10, [0.1, 0.2, 0.1])).to eq([3, 5, 2])
      end

      it "does not lose pennies" do
        expect(described_class.generate(10, [1, 1, 2])).to eq([3, 2, 5])
        expect(described_class.generate(100, [1, 1, 1])).to eq([34, 33, 33])
      end

      it "handles zero arguments" do
        expect(described_class.generate(100, [1, 1, 0])).to eq([50, 50, 0])
        expect(described_class.generate(100, [0, 1, 1])).to eq([0, 50, 50])
      end
    end

    context "with fractional amounts" do
      it "returns the amount when array contains only one element" do
        expect(described_class.generate(BigDecimal(100), [1], false)).to eq([100])
        expect(described_class.generate(BigDecimal(100), [5], false)).to eq([100])
      end

      it "splits the amount into whole parts respecting the order" do
        expect(described_class.generate(BigDecimal(100), [1, 1], false)).to eq([50, 50])
        expect(described_class.generate(BigDecimal(100), [1, 1, 2], false)).to eq([25, 25, 50])
        expect(described_class.generate(BigDecimal(100), [7, 3], false)).to eq([70, 30])
      end

      it "splits the amount proportionally to the given parts" do
        expect(described_class.generate(BigDecimal(10), [1, 1, 2], false)).to eq([2.5, 2.5, 5])
        expect(described_class.generate(BigDecimal(7), [1, 1], false)).to eq([3.5, 3.5])
      end

      it "keeps the class of the splits the same as given amount" do
        # Note that whole_amount is false but result is whole values
        expect(described_class.generate(10, [1, 1, 2], false)).to eq([3, 2, 5])
      end

      it "handles splits into repeating decimals" do
        amount = BigDecimal(100)
        parts = described_class.generate(amount, [1, 1, 1], false)

        # Rounding due to inconsistent BigDecimal size in ruby compared to jruby. In reality the
        # first 2 elements will look like the last one with a '5' at the end, compensating for a
        # missing fraction
        expect(parts.map { |x| x.round(10) }).to eq(
          [
            BigDecimal("33.3333333333"),
            BigDecimal("33.3333333333"),
            BigDecimal("33.3333333333"),
          ],
        )
        expect(parts.sum).to eq(amount)
      end
    end
  end

  context "with an allocation seen in the wild" do
    it "allocates the full amount" do
      amount = 700273
      allocations = [
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.170126087450276,
        1.0,
        1.0,
        1.0,
        1.0,
      ]

      result = described_class.generate(amount, allocations)
      expect(result.sum).to eq(amount)
      expect(result).to eq(
        [
          61566,
          61565,
          61565,
          61565,
          61565,
          61565,
          61565,
          60953,
          52091,
          52091,
          52091,
          52091,
        ],
      )
    end

    it "allocates the full -amount" do
      amount = -700273
      allocations = [
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.1818583143661,
        1.170126087450276,
        1.0,
        1.0,
        1.0,
        1.0,
      ]

      result = described_class.generate(amount, allocations)
      expect(result.sum).to eq(amount)
      expect(result).to eq(
        [
          -61566,
          -61565,
          -61565,
          -61565,
          -61565,
          -61565,
          -61565,
          -60953,
          -52091,
          -52091,
          -52091,
          -52091,
        ],
      )
    end

    context "when specified precision" do
      let(:amount) { 246.4 }
      let(:allocations) do
        [
          81.29, 81.29, 81.29, 81.29,
          234.8, 234.8, 234.8, 234.8,
          90.36, 90.36, 90.36, 90.36,
          90.36, 90.36, 90.36, 90.36,
          90.36, 90.36, 90.36, 90.36,
          90.36, 90.36, 90.36, 90.36,
          90.36, 90.36, 90.36, 90.36,
          90.36,
        ]
      end

      it "allocates with required precision" do
        result = described_class.generate(amount, allocations, 16)
        expect(result.sum).to eq(amount)

        expected = %w[
          6.3347130857200688 6.3347130857200689 6.3347130857200688 6.3347130857200688
          18.2973383260803562 18.2973383260803563 18.2973383260803563 18.2973383260803563
          7.0415140167999191 7.041514016799919 7.0415140167999191 7.041514016799919
          7.0415140167999191 7.041514016799919 7.0415140167999191 7.041514016799919
          7.0415140167999191 7.041514016799919 7.0415140167999191 7.041514016799919
          7.041514016799919  7.041514016799919 7.041514016799919  7.041514016799919
          7.041514016799919  7.041514016799919 7.041514016799919  7.041514016799919
          7.041514016799919
        ].map { |element| BigDecimal(element) }

        expect(result).to eq(expected)
      end
    end
  end

  describe ".generate_constrained" do
    it "raises an error when constraints are empty" do
      expect { described_class.generate_constrained(100, []) }.to raise_error(ArgumentError)
    end

    it "raises an error for negative weights" do
      expect { described_class.generate_constrained(100, [{ weight: -1 }]) }.to raise_error(ArgumentError)
    end

    it "raises an error when a bound is not a whole number" do
      expect { described_class.generate_constrained(100, [{ min: 1.5 }]) }.to raise_error(ArgumentError)
      expect { described_class.generate_constrained(100, [{ max: 2.5 }]) }.to raise_error(ArgumentError)
    end

    it "raises an error when min is greater than max" do
      expect { described_class.generate_constrained(100, [{ min: 10, max: 5 }]) }.to raise_error(ArgumentError)
    end

    it "raises an error when the amount is below the sum of the minimums" do
      constraints = [{ min: 60 }, { min: 50 }]
      expect { described_class.generate_constrained(100, constraints) }.to raise_error(ArgumentError)
    end

    it "raises an error when the amount exceeds the sum of the maximums" do
      constraints = [{ max: 40 }, { max: 50 }]
      expect { described_class.generate_constrained(100, constraints) }.to raise_error(ArgumentError)
    end

    it "raises an error when zero-weight parts cannot absorb the amount" do
      constraints = [{ weight: 0, min: 0, max: 100 }, { weight: 1, max: 40 }]
      expect { described_class.generate_constrained(100, constraints) }.to raise_error(ArgumentError)
    end

    it "splits proportionally when no bound is reached" do
      constraints = [{ weight: 1 }, { weight: 1 }, { weight: 1 }]
      expect(described_class.generate_constrained(100, constraints)).to eq([34, 33, 33])
    end

    it "truncates fractional amounts toward zero" do
      constraints = [{ weight: 1 }, { weight: 1 }]
      expect(described_class.generate_constrained(BigDecimal("100.9"), constraints)).to eq([50, 50])

      negative_constraints = [{ weight: 1, min: -60 }, { weight: 1, min: -60 }]
      expect(described_class.generate_constrained(Rational(-201, 2), negative_constraints)).to eq([-50, -50])
    end

    it "gives every part at least its minimum" do
      constraints = [{ weight: 1, min: 40 }, { weight: 1 }, { weight: 1 }]
      expect(described_class.generate_constrained(100, constraints)).to eq([60, 20, 20])
    end

    it "caps parts at their maximum and redistributes the remainder instead of clamping" do
      constraints = [{ weight: 1, max: 20 }, { weight: 1 }, { weight: 1 }]
      result = described_class.generate_constrained(100, constraints)

      expect(result).to eq([20, 40, 40])
      expect(result.sum).to eq(100)
    end

    it "redistributes repeatedly as more parts reach their maximum" do
      constraints = [
        { weight: 1, max: 10 },
        { weight: 1, max: 20 },
        { weight: 1 },
        { weight: 1 },
      ]
      expect(described_class.generate_constrained(100, constraints)).to eq([10, 20, 35, 35])
    end

    it "combines minimums and maximums" do
      constraints = [
        { weight: 1, min: 10, max: 15 },
        { weight: 2 },
        { weight: 1 },
      ]
      expect(described_class.generate_constrained(100, constraints)).to eq([15, 57, 28])
    end

    it "assigns leftover units to the largest remainders, breaking ties by order" do
      constraints = [{ weight: 1 }, { weight: 1 }]
      expect(described_class.generate_constrained(5, constraints)).to eq([3, 2])
    end

    it "honours weights when assigning leftover units" do
      constraints = [{ weight: 1 }, { weight: 2 }, { weight: 1 }]
      expect(described_class.generate_constrained(6, constraints)).to eq([2, 3, 1])
    end

    context "with zero weights" do
      it "gives zero-weight parts exactly their minimum" do
        constraints = [{ weight: 0, min: 5, max: 100 }, { weight: 1 }, { weight: 1 }]
        expect(described_class.generate_constrained(100, constraints)).to eq([5, 48, 47])
      end

      it "returns the minimums when all weights are zero" do
        constraints = [{ weight: 0, min: 30 }, { weight: 0, min: 70 }]
        expect(described_class.generate_constrained(100, constraints)).to eq([30, 70])
      end
    end

    context "with negative amounts" do
      it "allocates negative totals within bounds" do
        constraints = [
          { weight: 1, min: -40, max: 0 },
          { weight: 1, min: -40, max: 0 },
          { weight: 1, min: -40, max: 0 },
        ]
        expect(described_class.generate_constrained(-100, constraints)).to eq([-33, -33, -34])
      end

      it "keeps the total exact with remainders" do
        constraints = [
          { weight: 1, min: -10, max: 0 },
          { weight: 1, min: -10, max: 0 },
        ]
        expect(described_class.generate_constrained(-5, constraints)).to eq([-2, -3])
      end
    end

    context "with large amounts" do
      it "splits huge equal weights deterministically" do
        constraints = [{ weight: 1 }, { weight: 1 }, { weight: 1 }]
        expect(described_class.generate_constrained(10**12, constraints))
          .to eq([333_333_333_334, 333_333_333_333, 333_333_333_333])
      end

      it "caps huge amounts and redistributes the remainder" do
        constraints = [{ weight: 1, max: 1 }, { weight: 1, max: 2 }, { weight: 1 }]
        expect(described_class.generate_constrained(10**12, constraints)).to eq([1, 2, 999_999_999_997])
      end

      it "keeps the total exact with mixed bounds and zero weights" do
        constraints = [
          { weight: 3, min: 100 },
          { weight: 7, max: 500_000_000_000 },
          { weight: 0, min: 42 },
          { weight: 11 },
          { weight: 5 },
        ]
        amount = 1_000_000_000_000_007
        result = described_class.generate_constrained(amount, constraints)

        expect(result.sum).to eq(amount)
        expect(result[0]).to be >= 100
        expect(result[1]).to be <= 500_000_000_000
        expect(result[2]).to eq(42)
      end
    end

    context "exhaustive comparison" do
      def brute_force_best_deviation(amount, weights, maxs)
        targets = weights.map { |weight| Rational(amount * weight, weights.sum) }
        ranges = maxs.map { |max| (0..max).to_a }
        best = nil
        ranges[0].product(*ranges[1..]) do |candidate|
          next unless candidate.sum == amount
          deviation = candidate.each_with_index.sum { |part, i| (part - targets[i]).abs }
          best = deviation if best.nil? || deviation < best
        end
        best
      end

      it "matches the brute-force closest allocation for small cases" do
        mismatches = []

        [0, 1, 2, 3].repeated_permutation(3) do |weights|
          next if weights.all?(&:zero?)

          [2, 3, 4].repeated_permutation(3) do |maxs|
            feasible_max = weights.each_index.sum { |i| weights[i].positive? ? maxs[i] : 0 }

            (0..feasible_max).each do |amount|
              constraints = weights.each_index.map { |i| { weight: weights[i], max: maxs[i] } }
              result = described_class.generate_constrained(amount, constraints)
              targets = weights.map { |weight| Rational(amount * weight, weights.sum) }
              deviation = result.each_with_index.sum { |part, i| (part - targets[i]).abs }

              valid = result.sum == amount &&
                result.each_with_index.all? { |part, i| weights[i].zero? ? part.zero? : part.between?(0, maxs[i]) } &&
                deviation == brute_force_best_deviation(amount, weights, maxs)

              mismatches << [amount, weights, maxs, result] unless valid
            end
          end
        end

        expect(mismatches).to be_empty
      end

      it "respects bounds and totals with minimums and negative amounts" do
        mismatches = []

        [0, 1, 2].repeated_permutation(3) do |weights|
          [-2, 0, 1].repeated_permutation(3) do |mins|
            [1, 2].repeated_permutation(3) do |spans|
              maxs = mins.each_with_index.map { |min, i| min + spans[i] }
              total_min = mins.sum
              capacity = weights.each_index.sum { |i| weights[i].positive? ? spans[i] : 0 }

              (total_min..total_min + capacity).each do |amount|
                constraints = weights.each_index.map do |i|
                  { weight: weights[i], min: mins[i], max: maxs[i] }
                end
                result = described_class.generate_constrained(amount, constraints)

                valid = result.sum == amount &&
                  result.each_with_index.all? do |part, i|
                    weights[i].zero? ? part == mins[i] : part.between?(mins[i], maxs[i])
                  end

                mismatches << [amount, weights, mins, maxs, result] unless valid
              end
            end
          end
        end

        expect(mismatches).to be_empty
      end
    end
  end
end
