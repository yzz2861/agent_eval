# frozen_string_literal: true

class Money
  class Allocation
    # Allocates a specified amount into parts based on their proportions or distributes
    # it evenly when the number of parts is specified numerically.
    #
    # The total of the allocated amounts will always equal the original amount.
    #
    # The parts can be specified as:
    #   Numeric — performs the split between a given number of parties evenly
    #   Array<Numeric> — allocates the amounts proportionally to the given array
    #
    # @param amount [Numeric] The total amount to be allocated.
    # @param parts [Numeric, Array<Numeric>] Number of parts to split into or an array (proportions for allocation)
    # @param decimal_cutoff [Boolean, Integer] Controls per-split precision:
    #   - When true, splits are truncated to whole amounts.
    #   - When an Integer N, splits are rounded to N decimal places.
    #   - When false or nil, no rounding/truncation is applied.
    #   Defaults to true (whole amounts).
    #
    # @return [Array<Numeric>] An array containing the allocated amounts.
    # @raise [ArgumentError] If parts is empty or not provided.
    def self.generate(amount, parts, decimal_cutoff = true)
      parts =
        if parts.is_a?(Numeric)
          Array.new(parts, 1)
        elsif parts.all?(&:zero?)
          Array.new(parts.count, 1)
        else
          parts.dup
        end

      raise ArgumentError, "need at least one part" if parts.empty?

      if [amount, *parts].any? { |i| i.is_a?(BigDecimal) || i.is_a?(Float) || i.is_a?(Rational) }
        amount = convert_to_big_decimal(amount)
        parts.map! { |p| convert_to_big_decimal(p) }
      end

      result = []
      remaining_amount = amount
      round_to_whole = decimal_cutoff.is_a?(TrueClass)
      round_to_precision = decimal_cutoff.is_a?(Integer)

      parts_sum = parts.sum

      until parts.empty?
        part = parts.pop

        current_split = 0
        if parts_sum > 0
          current_split = remaining_amount * part / parts_sum
          current_split =
            if round_to_whole
              current_split.truncate
            elsif round_to_precision
              current_split.round(decimal_cutoff)
            else
              current_split
            end
        end

        result.unshift current_split
        remaining_amount -= current_split
        parts_sum -= part
      end

      result
    end

    # Allocates a specified amount into parts that each carry a weight and
    # optional minimum and maximum bounds, keeping every part within its
    # bounds while staying as close as possible to the weighted proportions.
    #
    # The amount is first truncated (toward zero) to a whole number of the
    # smallest currency unit, and every returned part is a whole number of
    # that unit. The parts always sum exactly to the truncated amount.
    #
    # Each constraint is a Hash accepting the keys:
    #   :weight [Numeric] — the proportion of the distributable amount this
    #     part receives. Defaults to 1. A part with zero weight always
    #     receives exactly its minimum.
    #   :min [Numeric] — the smallest whole amount the part may receive.
    #     Defaults to 0.
    #   :max [Numeric, nil] — the largest whole amount the part may receive.
    #     Defaults to nil, meaning unbounded.
    #
    # Every part starts at its minimum. The remaining amount is distributed
    # proportionally to the weights of the parts that have not reached their
    # maximum; parts that reach their maximum are fixed and the remainder is
    # redistributed among the parts still below their maximum. Leftover whole
    # units are assigned one by one to the parts with the largest fractional
    # remainder; ties are resolved in favor of the part listed first.
    #
    # Negative amounts follow the same rules: the minimums are allocated
    # first and the (non-negative) difference between the amount and the sum
    # of the minimums is distributed as described above.
    #
    # @param amount [Numeric] The total amount to be allocated.
    # @param constraints [Array<Hash>] Per-part :weight, :min and :max.
    #
    # @return [Array<Integer>] An array containing the allocated amounts.
    # @raise [ArgumentError] If constraints are empty, a weight is negative,
    #   a bound is not a whole number, a minimum exceeds its maximum, or the
    #   bounds cannot accommodate the amount.
    #
    # @example
    #   Money::Allocation.generate_constrained(100, [{ weight: 1, max: 20 }, { weight: 1 }, { weight: 1 }])
    #   #=> [20, 40, 40]
    def self.generate_constrained(amount, constraints)
      raise ArgumentError, "need at least one part" if constraints.empty?

      amount = amount.to_i
      entries = normalize_constraints(constraints)
      check_constrained_bounds(amount, entries)
      distribute_constrained(amount, entries)
    end

    # Converts a given number to BigDecimal.
    # This method supports inputs of BigDecimal, Rational, and other numeric types by ensuring they are all returned
    # as BigDecimal instances for consistent handling.
    #
    # @param number [Numeric, BigDecimal, Rational] The number to convert.
    # @return [BigDecimal] The converted number as a BigDecimal.
    def self.convert_to_big_decimal(number)
      if number.is_a? BigDecimal
        number
      elsif number.is_a? Rational
        number.to_d(Money.conversion_precision)
      else
        BigDecimal(number.to_s)
      end
    end

    def self.normalize_constraints(constraints)
      constraints.map do |constraint|
        weight = constraint.fetch(:weight, 1)
        min = constraint.fetch(:min, 0)
        max = constraint.fetch(:max, nil)

        unless weight.is_a?(Numeric) && weight >= 0
          raise ArgumentError, "weight must be a non-negative number"
        end
        unless min.is_a?(Numeric) && min == min.to_i
          raise ArgumentError, "min must be a whole number"
        end
        unless max.nil? || (max.is_a?(Numeric) && max == max.to_i)
          raise ArgumentError, "max must be a whole number"
        end

        min = min.to_i
        max = max&.to_i
        raise ArgumentError, "min cannot be greater than max" if max && min > max

        { weight: weight.to_r, min: min, max: max }
      end
    end
    private_class_method :normalize_constraints

    def self.check_constrained_bounds(amount, entries)
      total_min = entries.sum { |entry| entry[:min] }
      if amount < total_min
        raise ArgumentError, "amount is below the sum of the minimum amounts"
      end

      return if entries.any? { |entry| entry[:weight].positive? && entry[:max].nil? }

      capacity = entries.sum { |entry| entry[:weight].positive? ? entry[:max] - entry[:min] : 0 }
      if amount > total_min + capacity
        raise ArgumentError, "amount exceeds the sum of the maximum amounts"
      end
    end
    private_class_method :check_constrained_bounds

    def self.distribute_constrained(amount, entries)
      result = entries.map { |entry| entry[:min] }
      remaining = amount - result.sum
      active = entries.each_index.select do |index|
        entry = entries[index]
        entry[:weight].positive? && (entry[:max].nil? || entry[:max] > entry[:min])
      end

      until remaining.zero?
        weight_total = active.sum { |index| entries[index][:weight] }

        capped = active.select do |index|
          max = entries[index][:max]
          max && remaining * entries[index][:weight] >= (max - result[index]) * weight_total
        end

        if capped.any?
          capped.each do |index|
            share = entries[index][:max] - result[index]
            result[index] += share
            remaining -= share
            active.delete(index)
          end
          next
        end

        quotas = active.map do |index|
          exact = remaining * entries[index][:weight] / weight_total
          [index, exact.floor, exact - exact.floor]
        end
        leftover = remaining - quotas.sum { |quota| quota[1] }
        quotas.sort_by { |index, _share, fraction| [-fraction, index] }.first(leftover).each do |quota|
          quota[1] += 1
        end
        quotas.each { |index, share, _fraction| result[index] += share }
        remaining = 0
      end

      result
    end
    private_class_method :distribute_constrained
  end
end
