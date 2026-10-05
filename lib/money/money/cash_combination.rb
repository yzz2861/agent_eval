# frozen_string_literal: true

class Money
  # Finds a bounded, exact combination of cash denominations.
  class CashCombination
    class Result
      attr_reader :status, :combination, :total_count, :budget, :budget_used

      def initialize(status:, combination:, total_count:, budget:, budget_used:)
        @status = status
        @combination = combination
        @total_count = total_count
        @budget = budget
        @budget_used = budget_used
      end

      def found?
        status == :found
      end

      def no_solution?
        status == :no_solution
      end

      def budget_exhausted?
        status == :budget_exhausted
      end
    end

    # Calculates the fewest pieces that exactly represent +target+.
    #
    # Denominations and quantities are interpreted in the fractional unit of
    # +target+. Integer keys use that unit directly. Money keys must use the
    # same currency and have an integral fractional value.
    #
    # When several solutions use the same number of pieces, the solution using
    # more pieces of the largest denomination wins, then the next largest
    # denomination, and so on.
    #
    # +budget+ is the maximum number of bounded-knapsack state transitions used
    # by the search. Use nil for an unlimited budget.
    def self.calculate(target, available, budget: nil)
      new(target, available, budget).calculate
    end

    def initialize(target, available, budget)
      @target = target
      @available = available
      @budget = budget
      @budget_used = 0

      validate_target!
      validate_available!
      validate_budget!
    end

    def calculate
      return found_result({}, 0) if target_amount.zero?

      denominations = normalized_denominations
      return no_solution_result if denominations.empty?

      catch(:budget_exhausted) do
        best_count = Array.new(target_amount + 1)
        best_quantities = Array.new(target_amount + 1)
        best_count[0] = 0
        best_quantities[0] = Array.new(denominations.size, 0)

        binary_bundles(denominations).each do |bundle|
          search_with_bundle(bundle, best_count, best_quantities)
        end

        if best_count[target_amount]
          found_result(
            combination_for(best_quantities[target_amount], denominations),
            best_count[target_amount],
          )
        else
          no_solution_result
        end
      end
    end

    private

    attr_reader :target, :available, :budget, :budget_used

    def target_amount
      @target_amount ||= integral_fractional(target)
    end

    def validate_target!
      unless target.is_a?(Money)
        raise ArgumentError, "target must be a Money object"
      end

      amount = target.fractional
      unless amount.is_a?(Integer) || (amount.is_a?(BigDecimal) && amount.integer?)
        raise ArgumentError, "target amount must be an integral fractional value"
      end
      raise ArgumentError, "target amount cannot be negative" if amount.negative?
    end

    def validate_available!
      unless available.is_a?(Hash)
        raise ArgumentError, "available denominations must be a Hash"
      end

      normalized_values = []
      available.each do |denomination, quantity|
        validate_denomination!(denomination)
        validate_quantity!(quantity)
        normalized_values << denomination_value(denomination)
      end

      if normalized_values.uniq.size != normalized_values.size
        raise ArgumentError, "denominations must be unique"
      end
    end

    def validate_denomination!(denomination)
      if denomination.is_a?(Money)
        unless denomination.currency == target.currency
          raise ArgumentError, "all denominations must use the target currency"
        end

        amount = denomination.fractional
        unless amount.is_a?(Integer) || (amount.is_a?(BigDecimal) && amount.integer?)
          raise ArgumentError, "denominations must be integral fractional values"
        end
      elsif !denomination.is_a?(Integer)
        raise ArgumentError, "denominations must be integers or Money objects"
      end

      return if denomination_value(denomination).positive?

      raise ArgumentError, "denominations must be positive"
    end

    def validate_quantity!(quantity)
      unless quantity.is_a?(Integer) && !quantity.negative?
        raise ArgumentError, "quantities must be non-negative integers"
      end
    end

    def validate_budget!
      return if budget.nil?
      unless budget.is_a?(Integer) && !budget.negative?
        raise ArgumentError, "budget must be a non-negative integer or nil"
      end
    end

    def integral_fractional(money)
      money.fractional.to_i
    end

    def denomination_value(denomination)
      denomination.is_a?(Money) ? integral_fractional(denomination) : denomination
    end

    def normalized_denominations
      available.filter_map do |denomination, quantity|
        next if quantity.zero?

        value = denomination_value(denomination)
        next if value > target_amount

        [value, quantity, denomination]
      end.sort_by { |value, _, _| -value }
    end

    def binary_bundles(denominations)
      denominations.flat_map.with_index do |(value, quantity, _), denomination_index|
        bundles = []
        remaining = quantity
        chunk_size = 1

        while remaining.positive?
          pieces = [chunk_size, remaining].min
          bundles << pieces
          remaining -= pieces
          chunk_size *= 2
        end

        bundles.map do |pieces|
          [denomination_index, value, pieces, value * pieces]
        end
      end
    end

    def search_with_bundle(bundle, best_count, best_quantities)
      index = bundle[0]
      pieces = bundle[2]
      bundle_value = bundle[3]

      target_amount.downto(bundle_value) do |amount|
        source_amount = amount - bundle_value
        source_count = best_count[source_amount]
        next if source_count.nil?

        candidate_count = source_count + pieces
        candidate_quantities = best_quantities[source_amount].dup
        candidate_quantities[index] += pieces

        consume_budget!
        next unless better_combination?(
          candidate_count,
          candidate_quantities,
          best_count[amount],
          best_quantities[amount],
        )

        best_count[amount] = candidate_count
        best_quantities[amount] = candidate_quantities
      end
    end

    def consume_budget!
      @budget_used += 1
      return if budget.nil? || budget_used <= budget

      throw :budget_exhausted, budget_exhausted_result
    end

    def better_combination?(candidate_count, candidate_quantities, current_count, current_quantities)
      return true if current_count.nil?
      return false if candidate_count > current_count
      if candidate_count == current_count
        return (candidate_quantities <=> current_quantities).positive?
      end

      true
    end

    def combination_for(quantities, denominations)
      quantities.each_with_index.with_object({}) do |(quantity, index), combination|
        next if quantity.zero?

        combination[denominations[index][2]] = quantity
      end
    end

    def found_result(combination, total_count)
      result(:found, combination, total_count)
    end

    def no_solution_result
      result(:no_solution, nil, nil)
    end

    def budget_exhausted_result
      result(:budget_exhausted, nil, nil)
    end

    def result(status, combination, total_count)
      Result.new(
        status: status,
        combination: combination,
        total_count: total_count,
        budget: budget,
        budget_used: budget_used,
      )
    end
  end
end
