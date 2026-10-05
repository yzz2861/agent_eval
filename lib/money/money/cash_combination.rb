# frozen_string_literal: true

class Money
  class CashCombination
    class Result
      STATUSES = [:found, :no_solution, :budget_exceeded].freeze

      attr_reader :status, :target, :denominations, :counts, :total_pieces, :nodes_visited

      def initialize(status, target, denominations, counts, nodes_visited)
        @status = status
        @target = target
        @denominations = denominations
        @counts = counts
        @total_pieces = counts&.sum
        @nodes_visited = nodes_visited
      end

      def found?
        status == :found
      end

      alias success? found?
      alias exact? found?

      def no_solution?
        status == :no_solution
      end

      def budget_exceeded?
        status == :budget_exceeded
      end

      alias search_budget_exceeded? budget_exceeded?

      def combination
        return unless found?

        denominations.zip(counts).to_h
      end

      alias solution combination
      alias pieces total_pieces
    end

    class State
      attr_accessor :counts, :total_pieces

      def initialize(counts, total_pieces)
        @counts = counts
        @total_pieces = total_pieces
      end
    end

    class MonotonicDeque
      Entry = Struct.new(:amount, :counts, :total_pieces, :value)

      def initialize
        @entries = []
        @head = 0
      end

      def add(entry)
        @entries.pop while remove_tail?(entry)
        @entries << entry
      end

      def remove_expired(minimum_amount)
        @head += 1 while front && front.amount < minimum_amount
      end

      def front
        @entries[@head]
      end

      private

      def remove_tail?(new_entry)
        return false if @entries.empty? || @head >= @entries.size

        last_entry = @entries.last
        last_entry.value > new_entry.value ||
          (last_entry.value == new_entry.value && lexically_preferred?(new_entry.counts, last_entry.counts))
      end

      def lexically_preferred?(left, right)
        left.each_with_index do |left_count, index|
          right_count = right[index]
          return left_count > right_count if left_count != right_count
        end

        false
      end
    end

    DEFAULT_SEARCH_BUDGET = 10_000

    def self.find(target:, denominations:, quantities:, search_budget: DEFAULT_SEARCH_BUDGET)
      new(
        target: target,
        denominations: denominations,
        quantities: quantities,
        search_budget: search_budget,
      ).find
    end

    def initialize(target:, denominations:, quantities:, search_budget:)
      @target = validate_target(target)
      @target_amount = target.fractional.to_i
      @denominations = denominations
      @denomination_amounts = validate_denominations(denominations)
      @quantities = validate_quantities(quantities, denominations)
      @search_budget = validate_search_budget(search_budget)
    end

    def find
      return found(Array.new(denominations.size, 0), 0) if target_amount.zero?

      active_indices = denominations.each_index.select do |index|
        denomination_amounts[index] <= target_amount && quantities[index].positive?
      end

      return no_solution(0) if active_indices.empty?
      return no_solution(0) if available_total(active_indices) < target_amount
      return no_solution(0) unless divisible_by_gcd?(active_indices)

      solve(active_indices)
    end

    private

    attr_reader :target, :target_amount, :denominations, :denomination_amounts, :quantities, :search_budget

    def validate_target(value)
      unless value.is_a?(Money)
        raise ArgumentError, "target must be a Money object"
      end
      unless integer_value?(value.fractional)
        raise ArgumentError, "target must use whole smallest currency units"
      end
      if value.fractional.negative?
        raise ArgumentError, "target must not be negative"
      end

      value
    end

    def validate_denominations(values)
      unless values.is_a?(Array)
        raise ArgumentError, "denominations must be an Array"
      end

      denomination_amounts = values.map { |value| denomination_amount(value) }
      if denomination_amounts.any? { |denomination| denomination <= 0 }
        raise ArgumentError, "denominations must be positive integers"
      end
      if denomination_amounts.size != denomination_amounts.dup.uniq.size
        raise ArgumentError, "denominations must not contain duplicates"
      end

      denomination_amounts
    end

    def denomination_amount(value)
      case value
      when Integer
        value
      when Money
        unless value.currency == target.currency
          raise ArgumentError, "denomination currency #{value.currency} does not match target currency #{target.currency}"
        end
        unless integer_value?(value.fractional)
          raise ArgumentError, "denominations must use whole smallest currency units"
        end

        value.fractional.to_i
      else
        raise ArgumentError,
              "denominations must be Integer smallest-unit amounts or same-currency Money objects"
      end
    end

    def integer_value?(value)
      value.is_a?(Integer) || (value.is_a?(BigDecimal) && value.frac.zero?)
    end

    def validate_quantities(values, provided_denominations)
      unless values.is_a?(Array)
        raise ArgumentError, "quantities must be an Array"
      end
      if values.size != provided_denominations.size
        raise ArgumentError, "quantities must contain one value for each denomination"
      end
      unless values.all? { |value| value.is_a?(Integer) && !value.negative? }
        raise ArgumentError, "quantities must be non-negative integers"
      end

      values
    end

    def validate_search_budget(value)
      unless value.is_a?(Integer) && value.positive?
        raise ArgumentError, "search_budget must be a positive integer"
      end

      value
    end

    def available_total(active_indices)
      active_indices.sum { |index| denomination_amounts[index] * quantities[index] }
    end

    def divisible_by_gcd?(active_indices)
      gcd = active_indices.map { |index| denomination_amounts[index] }.inject(:gcd)
      (target_amount % gcd).zero?
    end

    def solve(active_indices)
      empty_counts = Array.new(denominations.size, 0)
      previous = { 0 => State.new(empty_counts, 0) }
      nodes_visited = 0

      active_indices.each do |index|
        current = {}
        deques = Hash.new { |hash, residue| hash[residue] = MonotonicDeque.new }
        denomination = denomination_amounts[index]
        stock = quantities[index]

        (0..target_amount).each do |amount|
          return budget_exceeded(nodes_visited) if nodes_visited >= search_budget

          nodes_visited += 1

          residue = amount % denomination
          add_previous_state(previous[amount], amount, index, deques[residue])
          deque = deques[residue]
          deque.remove_expired(amount - denomination * stock)
          entry = deque.front
          next unless entry

          selected_count = (amount - entry.amount) / denomination
          counts = entry.counts.dup
          counts[index] = selected_count
          current[amount] = State.new(counts, entry.total_pieces + selected_count)
        end

        previous = current
      end

      final_state = previous[target_amount]
      return no_solution(nodes_visited) unless final_state

      found(final_state.counts, nodes_visited)
    end

    def add_previous_state(state, amount, index, deque)
      return unless state

      counts = state.counts.dup
      current_count = counts[index]
      counts[index] = 0
      position = amount / denomination_amounts[index]
      total_without_current = state.total_pieces - current_count
      deque.add(
        MonotonicDeque::Entry.new(
          amount,
          counts,
          total_without_current,
          total_without_current - position,
        ),
      )
    end

    def found(counts, nodes_visited)
      Result.new(:found, target, denominations, counts, nodes_visited)
    end

    def no_solution(nodes_visited)
      Result.new(:no_solution, target, denominations, nil, nodes_visited)
    end

    def budget_exceeded(nodes_visited)
      Result.new(:budget_exceeded, target, denominations, nil, nodes_visited)
    end
  end
end
