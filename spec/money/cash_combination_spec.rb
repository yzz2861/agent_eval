# frozen_string_literal: true

RSpec.describe Money::CashCombination do
  def brute_force_combination(denominations, quantities, target)
    ranges = quantities.map { |quantity| 0..quantity }
    choices = ranges.map(&:to_a)
    feasible = choices.first.product(*choices.drop(1)).select do |counts|
      counts.each_with_index.sum { |count, index| count * denominations[index] } == target
    end

    feasible.min do |left, right|
      comparison = left.sum <=> right.sum
      next comparison unless comparison.zero?

      result = 0
      left.each_with_index do |left_count, index|
        difference = right[index] - left_count
        unless difference.zero?
          result = difference
          break
        end
      end
      result
    end
  end

  describe ".find_cash_combination" do
    it "finds the minimum-piece solution when greedy fails for non-decimal denominations" do
      result = Money.find_cash_combination(
        Money.new(6, "USD"),
        [4, 3, 1],
        [1, 2, 6],
      )

      expect(result).to be_found
      expect(result).to be_success
      expect(result).to be_exact
      expect(result.counts).to eq([0, 2, 0])
      expect(result.total_pieces).to eq(2)
      expect(result.pieces).to eq(2)
      expect(result.combination).to eq(4 => 0, 3 => 2, 1 => 0)
      expect(result.solution).to eq(result.combination)
    end

    it "respects available stock" do
      result = Money.find_cash_combination(
        Money.new(6, "USD"),
        [4, 3, 1],
        [1, 1, 6],
      )

      expect(result).to be_found
      expect(result.counts).to eq([1, 0, 2])
      expect(result.total_pieces).to eq(3)
    end

    it "breaks ties by preferring earlier denominations" do
      first = Money.find_cash_combination(
        Money.new(10, "USD"),
        [6, 5, 4, 3],
        [5, 5, 5, 5],
      )
      second = Money.find_cash_combination(
        Money.new(10, "USD"),
        [3, 4, 5, 6],
        [5, 5, 5, 5],
      )

      expect(first.counts).to eq([1, 0, 1, 0])
      expect(second.counts).to eq([0, 1, 0, 1])
    end

    it "accepts same-currency Money denominations and preserves them in the combination" do
      denominations = [Money.new(4, "USD"), Money.new(3, "USD"), Money.new(1, "USD")]
      result = Money.find_cash_combination(Money.new(6, "USD"), denominations, [1, 2, 6])

      expect(result.combination).to eq(
        Money.new(4, "USD") => 0,
        Money.new(3, "USD") => 2,
        Money.new(1, "USD") => 0,
      )
    end

    it "accepts a denomination-to-stock Hash" do
      result = Money.find_cash_combination(
        Money.new(6, "USD"),
        {
          4 => 1,
          3 => 2,
          1 => 6,
        },
      )

      expect(result.counts).to eq([0, 2, 0])
    end

    it "can be called on the target Money object" do
      result = Money.new(6, "USD").cash_combination({ 4 => 1, 3 => 2, 1 => 6 })

      expect(result.counts).to eq([0, 2, 0])
    end

    it "composes zero with no pieces" do
      result = Money.find_cash_combination(Money.new(0, "USD"), [1], [2])

      expect(result).to be_found
      expect(result.counts).to eq([0])
      expect(result.total_pieces).to eq(0)
    end

    it "returns no_solution when the stock total is below the target" do
      result = Money.find_cash_combination(
        Money.new(10, "USD"),
        [6, 4],
        [1, 0],
      )

      expect(result).to be_no_solution
      expect(result).not_to be_found
      expect(result).not_to be_budget_exceeded
      expect(result.counts).to be_nil
      expect(result.combination).to be_nil
    end

    it "returns no_solution when no exact combination exists" do
      result = Money.find_cash_combination(
        Money.new(11, "USD"),
        [6, 4],
        [3, 3],
      )

      expect(result).to be_no_solution
    end

    it "distinguishes budget exhaustion from no solution" do
      result = Money.find_cash_combination(
        Money.new(100, "USD"),
        [6, 4],
        [20, 20],
        search_budget: 1,
      )

      expect(result).to be_budget_exceeded
      expect(result).to be_search_budget_exceeded
      expect(result).not_to be_no_solution
      expect(result.nodes_visited).to eq(1)
      expect(result.counts).to be_nil
    end

    it "validates matching currencies" do
      expect do
        Money.find_cash_combination(Money.new(6, "USD"), [Money.new(3, "EUR")], [2])
      end.to raise_error(ArgumentError, /does not match target currency/)
    end

    it "validates positive integer denominations" do
      expect { Money.find_cash_combination(Money.new(6, "USD"), [0], [1]) }
        .to raise_error(ArgumentError, "denominations must be positive integers")
      expect { Money.find_cash_combination(Money.new(6, "USD"), [-1], [1]) }
        .to raise_error(ArgumentError, "denominations must be positive integers")
      expect { Money.find_cash_combination(Money.new(6, "USD"), [1.5], [1]) }
        .to raise_error(ArgumentError, /denominations must be Integer/)
      expect { Money.find_cash_combination(Money.new(6, "USD"), [1, 1], [1, 1]) }
        .to raise_error(ArgumentError, "denominations must not contain duplicates")
    end

    it "validates integer target, quantities, and budget" do
      expect { Money.find_cash_combination(Money.new(-1, "USD"), [1], [1]) }
        .to raise_error(ArgumentError, "target must not be negative")
      expect { Money.find_cash_combination(Money.new(6, "USD"), [1], [-1]) }
        .to raise_error(ArgumentError, "quantities must be non-negative integers")
      expect { Money.find_cash_combination(Money.new(6, "USD"), [1], [1], search_budget: 0) }
        .to raise_error(ArgumentError, "search_budget must be a positive integer")
    end

    it "rejects targets that are not whole smallest-unit integers under infinite precision",
       :default_infinite_precision_true do
      target = Money.new(6.5, "USD")

      expect do
        Money.find_cash_combination(target, [1], [7])
      end.to raise_error(ArgumentError, "target must use whole smallest currency units")
    end

    it "matches brute force for small inventories across arbitrary denominations" do
      cases = [
        { denominations: [7, 5, 3, 1], quantities: [2, 3, 2, 4], target_range: 0..30 },
        { denominations: [8, 5, 3], quantities: [2, 2, 3], target_range: 0..25 },
        { denominations: [9, 6, 4], quantities: [2, 2, 3], target_range: 0..30 },
      ]

      cases.each do |test_case|
        denominations = test_case.fetch(:denominations)
        quantities = test_case.fetch(:quantities)

        test_case.fetch(:target_range).each do |target|
          result = Money.find_cash_combination(
            Money.new(target, "USD"),
            denominations,
            quantities,
            search_budget: 10_000,
          )
          expected = brute_force_combination(denominations, quantities, target)

          if expected
            expect(result).to be_found
            expect(result.counts).to eq(expected)
            expect(result.total_pieces).to eq(expected.sum)
          else
            expect(result).to be_no_solution
          end
        end
      end
    end
  end
end
