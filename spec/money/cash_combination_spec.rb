# frozen_string_literal: true

RSpec.describe Money::CashCombination do
  def brute_force(target, available)
    denominations = available.keys.sort.reverse
    ranges = denominations.map { |denomination| (0..available.fetch(denomination)).to_a }

    ranges.first.product(*ranges.drop(1)).filter_map do |quantities|
      combination = denominations.zip(quantities).to_h.reject { |_, quantity| quantity.zero? }
      next unless combination.sum { |denomination, quantity| denomination * quantity } == target

      [quantities.sum, quantities, combination]
    end.min_by { |count, quantities, _| [count, quantities.map { |quantity| -quantity }] }
  end

  describe ".calculate" do
    it "finds fewer pieces than the greedy choice with non-decimal denominations" do
      result = described_class.calculate(
        Money.new(40, "USD"),
        { 24 => 2, 20 => 2, 1 => 30 },
      )

      expect(result).to be_found
      expect(result.combination).to eq(20 => 2)
      expect(result.total_count).to eq(2)
    end

    it "respects bounded inventory" do
      result = described_class.calculate(
        Money.new(40, "USD"),
        { 25 => 1, 10 => 1, 5 => 1, 1 => 40 },
      )

      expect(result).to be_found
      expect(result.combination).to eq(25 => 1, 10 => 1, 5 => 1)
      expect(result.total_count).to eq(3)
    end

    it "uses a deterministic descending-denomination order for equal piece counts" do
      result = described_class.calculate(
        Money.new(12, "USD"),
        { 6 => 2, 4 => 3, 3 => 4, 1 => 12 },
      )

      expect(result).to be_found
      expect(result.combination).to eq(6 => 2)
      expect(result.total_count).to eq(2)
    end

    it "accepts Money denominations in the target currency" do
      result = described_class.calculate(
        Money.new(40, "USD"),
        {
          Money.new(24, "USD") => 2,
          Money.new(20, "USD") => 2,
          Money.new(1, "USD") => 30,
        },
      )

      expect(result).to be_found
      expect(result.combination).to eq(
        Money.new(20, "USD") => 2,
      )
      expect(result.total_count).to eq(2)
    end

    it "returns an empty combination for a zero target" do
      result = described_class.calculate(Money.new(0, "USD"), { 1 => 5 })

      expect(result).to be_found
      expect(result.combination).to eq({})
      expect(result.total_count).to eq(0)
      expect(result.budget_used).to eq(0)
    end

    it "returns no solution when no denominations are available" do
      result = described_class.calculate(Money.new(1, "USD"), {})

      expect(result).to be_no_solution
      expect(result.combination).to be_nil
    end

    it "distinguishes no solution from an exhausted search budget" do
      impossible = described_class.calculate(
        Money.new(11, "USD"),
        { 10 => 1 },
        budget: 100,
      )

      expect(impossible).to be_no_solution
      expect(impossible).not_to be_budget_exhausted
      expect(impossible.combination).to be_nil
      expect(impossible.total_count).to be_nil

      immediate_exhaustion = described_class.calculate(
        Money.new(10, "USD"),
        { 1 => 10 },
        budget: 0,
      )
      expect(immediate_exhaustion).to be_budget_exhausted
      expect(immediate_exhaustion.budget_used).to eq(1)
      expect(immediate_exhaustion.combination).to be_nil

      exhausted = described_class.calculate(
        Money.new(100, "USD"),
        { 1 => 100 },
        budget: 10,
      )

      expect(exhausted).to be_budget_exhausted
      expect(exhausted).not_to be_no_solution
      expect(exhausted.budget_used).to eq(11)
      expect(exhausted.combination).to be_nil
    end

    it "matches brute force for every small bounded case" do
      denomination_sets = [
        [4, 3, 1],
        [8, 5, 2],
        [7, 6, 4, 1],
        [10, 6, 3],
        [9, 5, 2, 1],
      ]

      denomination_sets.each do |denominations|
        (0..2).each do |small_stock|
          (0..2).each do |large_stock|
            stocks = denominations.map.with_index do |_, index|
              index.zero? ? small_stock : large_stock
            end
            available = denominations.zip(stocks).to_h
            maximum_target = available.sum { |denomination, quantity| denomination * quantity }

            (0..maximum_target).each do |target|
              result = described_class.calculate(
                Money.new(target, "USD"),
                available,
              )
              expected = brute_force(target, available)

              if expected.nil?
                expect(result).to be_no_solution
              else
                expected_count, _, expected_combination = expected
                expect(result).to be_found
                expect(result.total_count).to eq(expected_count)
                expect(result.combination).to eq(expected_combination)
              end
            end
          end
        end
      end
    end

    it "validates target and currency before searching" do
      expect { described_class.calculate(30, { 1 => 30 }) }
        .to raise_error(ArgumentError, "target must be a Money object")
      expect { described_class.calculate(Money.new(-1, "USD"), { 1 => 1 }) }
        .to raise_error(ArgumentError, "target amount cannot be negative")
      expect {
        described_class.calculate(Money.new(30, "USD"), { Money.new(1, "EUR") => 1 })
      }.to raise_error(ArgumentError, "all denominations must use the target currency")
    end

    it "validates denominations, quantities, duplicates, and budget" do
      expect { described_class.calculate(Money.new(1, "USD"), { 0 => 1 }) }
        .to raise_error(ArgumentError, "denominations must be positive")
      expect { described_class.calculate(Money.new(1, "USD"), { -1 => 1 }) }
        .to raise_error(ArgumentError, "denominations must be positive")
      expect { described_class.calculate(Money.new(1, "USD"), { 1 => -1 }) }
        .to raise_error(ArgumentError, "quantities must be non-negative integers")
      expect { described_class.calculate(Money.new(1, "USD"), { 1 => 1, Money.new(1, "USD") => 1 }) }
        .to raise_error(ArgumentError, "denominations must be unique")
      expect { described_class.calculate(Money.new(1, "USD"), { 1 => 1 }, budget: -1) }
        .to raise_error(ArgumentError, "budget must be a non-negative integer or nil")
    end

    it "rejects a fractional target when infinite precision is enabled" do
      Money.default_infinite_precision = true

      expect {
        described_class.calculate(Money.new(BigDecimal("1.5"), "USD"), { 1 => 2 })
      }.to raise_error(ArgumentError, "target amount must be an integral fractional value")
    ensure
      Money.default_infinite_precision = false
    end
  end

  describe "#cash_combination" do
    it "delegates to the calculator with the receiver as target" do
      result = Money.new(40, "USD").cash_combination({ 24 => 2, 20 => 2, 1 => 30 })

      expect(result).to be_found
      expect(result.combination).to eq(20 => 2)
      expect(result.total_count).to eq(2)
    end
  end
end
