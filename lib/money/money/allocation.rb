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

    # Allocates a whole-unit amount between parts while honouring per-part
    # weight, minimum and maximum constraints.
    #
    # Unlike a plain proportional allocation followed by clamping, this
    # method iteratively fixes parts that hit a boundary and redistributes the
    # remaining amount proportionally among the still-unfixed parts. The
    # returned amounts always sum to +amount+ exactly.
    #
    # Conventions:
    #   * +amount+ is expressed in whole minor units and must be integral.
    #     Negative amounts are allocated as their absolute value, then negated,
    #     so +min+/+max+ always constrain non-negative magnitudes.
    #   * Each part is a Hash with :weight (default 1), :min (default 0) and
    #     :max (default unlimited) keys. Weights are non-negative Numerics.
    #   * Zero-weight parts do not participate in proportional sharing and are
    #     fixed at their :min, even when they have room below their :max. When
    #     every part has a zero weight, parts without an upper bound split the
    #     remainder evenly; if none exist and the minimums do not already sum
    #     to the total, the constraints are infeasible.
    #   * After continuous shares are known, each part takes its floor and the
    #     leftover whole units are handed out one by one to the parts with the
    #     largest fractional remainder; ties keep input order (earlier first).
    #
    # @param amount [Numeric] The total amount in whole minor units.
    # @param parts [Array<Hash>] Per-part :weight, :min and :max constraints.
    #
    # @return [Array<Numeric>] Whole-unit allocated amounts in input order.
    # @raise [ArgumentError] If the parts or constraints are invalid or
    #   infeasible for the given amount.
    def self.generate_with_constraints(amount, parts)
      raise ArgumentError, "need at least one part" if parts.nil? || parts.empty?

      sign = amount.to_r.negative? ? -1 : 1
      total = integral_value(amount.to_r.abs, "amount")

      weights = []
      minimums = []
      maximums = []

      parts.each do |part|
        raise ArgumentError, "each part must be a Hash of constraints" unless part.is_a?(Hash)

        weight = part.fetch(:weight, 1).to_r
        raise ArgumentError, "weight must be non-negative" if weight.negative?

        minimum = integral_value(part.fetch(:min, 0).to_r, "minimum amount")
        raise ArgumentError, "minimum amount must be non-negative" if minimum.negative?

        maximum =
          if part.key?(:max) && !part[:max].nil?
            value = integral_value(part[:max].to_r, "maximum amount")
            raise ArgumentError, "maximum amount must be non-negative" if value.negative?
            value
          end

        raise ArgumentError, "minimum amount cannot exceed maximum amount" if maximum && minimum > maximum

        weights << weight
        minimums << minimum
        maximums << maximum
      end

      sum_min = minimums.sum
      if sum_min > total
        raise ArgumentError,
          "minimum amounts (#{sum_min}) exceed total amount (#{total})"
      end

      effective_weights = weights.dup
      if effective_weights.all?(&:zero?)
        all_fixed = minimums.sum == total
        unless all_fixed
          weights.each_index { |index| effective_weights[index] = 1 if maximums[index].nil? }
        end
      end

      bounded = effective_weights.each_index.all? do |index|
        effective_weights[index].zero? || maximums[index]
      end
      capacity = effective_weights.each_index.sum do |index|
        if effective_weights[index].zero?
          minimums[index]
        elsif maximums[index]
          maximums[index]
        else
          0
        end
      end
      if bounded && capacity < total
        raise ArgumentError,
          "maximum amounts (#{capacity}) are below total amount (#{total})"
      end

      shares = constrained_shares(total, effective_weights, minimums, maximums)
      distributable = effective_weights.each_index.select { |index| effective_weights[index].positive? }
      amounts = integralize_shares(shares, total, distributable)
      amounts.map { |value| sign * value }
    end

    # Computes continuous (possibly fractional) shares that satisfy the
    # constraints, fixing parts on their upper bound and redistributing the
    # remainder over the parts still free to grow.
    def self.constrained_shares(total, weights, minimums, maximums)
      shares = Array.new(weights.length)
      active = weights.each_index.select { |index| weights[index].positive? }
      fixed_total = minimums.sum

      until active.empty?
        scale = (total - fixed_total) / active.sum { |index| weights[index] }
        overflowing = active.select do |index|
          maximum = maximums[index]
          maximum && scale * weights[index] > maximum - minimums[index]
        end

        break if overflowing.empty?

        overflowing.each do |index|
          shares[index] = maximums[index]
          fixed_total += maximums[index] - minimums[index]
          active.delete(index)
        end
      end

      unless active.empty?
        scale = (total - fixed_total) / active.sum { |index| weights[index] }
        active.each do |index|
          shares[index] = minimums[index] + scale * weights[index]
        end
      end

      weights.each_index { |index| shares[index] ||= minimums[index] }

      shares
    end

    # Rations the leftover whole units after flooring by largest fractional
    # remainder, keeping input order on ties. Only indices allowed to grow are
    # eligible, so fixed zero-weight parts never absorb leftover units.
    def self.integralize_shares(shares, total, eligible_indices = shares.each_index.to_a)
      amounts = shares.map { |share| share.floor }
      leftover = total - amounts.sum

      if leftover.positive?
        fractional = shares.map { |share| share - share.floor }
        indices = eligible_indices
          .sort_by { |index| [-fractional[index], index] }
        indices.first(leftover).each { |index| amounts[index] += 1 }
      end

      amounts
    end

    # Converts a Rational to an Integer when it is whole, mirroring the fact
    # that constrained allocation works in whole minor units.
    def self.integral_value(value, label)
      unless value.denominator == 1
        raise ArgumentError, "#{label} must be a whole number (got #{value})"
      end

      value.to_i
    end
  end
end
