# frozen_string_literal: true

class Money
  # Reconciles per-line rounding with an order-level target total.
  #
  # Invoice lines are often computed from unrounded values and then rounded
  # independently to the currency's smallest unit. The rounded lines can then
  # add up to one or two subunits more or less than the total computed for the
  # whole order. This coordinator redistributes that residual while keeping
  # every amount expressed in whole subunits only.
  #
  # The residual is distributed with the stable and explainable "largest
  # remainder" rule (Hamilton's method):
  #
  # 1. Every line is first rounded independently to a whole number of
  #    subunits; adjustable lines use this as their baseline.
  # 2. If the baseline sum is below the target, the missing subunits are
  #    handed out one at a time to the lines with the largest fractional
  #    remainders (the strongest cases for rounding up).
  # 3. If the baseline sum is above the target, one subunit is removed at a
  #    time from the lines with the smallest fractional remainders (the
  #    strongest cases for rounding down).
  # 4. Equal remainders are broken by the original line position, earlier
  #    lines first, so the result is deterministic.
  #
  # Lines are handled according to their class:
  #
  # - *Zero lines* (an exact unrounded value of 0) always stay at 0.
  # - *Non-adjustable (locked) lines* are rounded independently with
  #   {Money.rounding_mode} and cannot absorb any residual.
  # - *Adjustable, non-integral, non-zero lines* may move by at most one
  #   subunit away from their independently rounded value.
  # - *Integral lines* (including zero lines) already match a whole number of
  #   subunits, have no fractional remainder and are never moved.
  #
  # If the target lies outside the reachable range, {InfeasibleTarget} is
  # raised; the total is never silently changed.
  class RoundingCoordinator
    # Raised when no allowed per-line adjustment reaches the requested total.
    class InfeasibleTarget < StandardError
      def initialize(target, min_total, max_total)
        super(
          "target of #{target} subunit(s) cannot be reached within the " \
          "adjustment constraints (reachable range: #{min_total}..#{max_total})"
        )
      end
    end

    # Outcome of a reconciliation.
    #
    # @!attribute amounts
    #   @return [Array<Money>] Final per-line amounts, in input order.
    # @!attribute adjustments
    #   @return [Array<Integer>] Per-line adjustment in whole subunits,
    #     relative to each line's independently rounded value. Each entry is
    #     in +-1..1+ and the entries sum to +target - sum(independent
    #     rounding)+.
    # @!attribute total
    #   @return [Money] The reached total; always equals +amounts.sum+ and the
    #     requested target.
    Result = Struct.new(:amounts, :adjustments, :total, keyword_init: true)

    HALF = Rational(1, 2)
    private_constant :HALF

    # Rounds unrounded line amounts to whole subunits so they sum exactly to
    # +target_total+.
    #
    # @param line_amounts [Array<Numeric, Money>] Unrounded line values in
    #   subunits (Numeric) or Money objects. All Money inputs must share one
    #   currency.
    # @param target_total [Numeric, Money] Whole-subunit order total to hit.
    #   A Numeric is interpreted in subunits.
    # @param adjustable [nil, Integer, Range, Array<Integer>, Array<Boolean>]
    #   Lines allowed to absorb residual. +nil+ (default) allows every index;
    #   an Integer or Range selects indices (negative indices count from the
    #   end); an Integer array selects indices; a Boolean array of the same
    #   size as +line_amounts+ acts as a mask.
    # @param currency [Currency, String, Symbol, nil] Currency of Numeric
    #   inputs. Defaults to the currency of the Money inputs or
    #   {Money.default_currency}.
    #
    # @return [Result]
    #
    # @raise [ArgumentError] If the inputs are malformed, currencies differ,
    #   or the target is not a whole number of subunits.
    # @raise [InfeasibleTarget] If the target cannot be reached while moving
    #   each adjustable line by at most one subunit.
    def self.reconcile(line_amounts, target_total, adjustable: nil, currency: nil)
      new(line_amounts, target_total, adjustable, currency).call
    end

    def initialize(line_amounts, target_total, adjustable, currency)
      unless line_amounts.is_a?(Array)
        raise ArgumentError, "line_amounts must be an Array"
      end
      raise ArgumentError, "line_amounts cannot be empty" if line_amounts.empty?

      @currency = resolve_currency(line_amounts, target_total, currency)
      @lines = line_amounts.map { |value| to_rational(value) }
      @target = extract_target(target_total)
      @adjustable = normalize_adjustable(adjustable, @lines.size)
    end

    def call
      rounded = Array.new(@lines.size)
      adjustments = Array.new(@lines.size, 0)
      upward_candidates = []
      downward_candidates = []

      @lines.each_with_index do |line, index|
        rounded[index] = nearest_integral(line, Money.rounding_mode)

        next unless @adjustable.include?(index)
        next if line.zero? || line.denominator == 1

        remainder = remainder_fraction(line)
        upward_candidates << index if remainder.positive?
        downward_candidates << index if remainder < 1
      end

      baseline_sum = rounded.sum
      residual = @target - baseline_sum
      min_total = baseline_sum - downward_candidates.size
      max_total = baseline_sum + upward_candidates.size

      if residual.positive?
        unless residual <= upward_candidates.size
          raise InfeasibleTarget.new(@target, min_total, max_total)
        end

        select_by_largest_remainder(upward_candidates, residual).each do |index|
          rounded[index] += 1
        end
      elsif residual.negative?
        removal = -residual
        unless removal <= downward_candidates.size
          raise InfeasibleTarget.new(@target, min_total, max_total)
        end

        select_by_smallest_remainder(downward_candidates, removal).each do |index|
          rounded[index] -= 1
        end
      end

      @lines.each_with_index do |line, index|
        next unless @adjustable.include?(index)
        next if line.zero? || line.denominator == 1

        adjustments[index] = rounded[index] - nearest_integral(line, Money.rounding_mode)
      end

      amounts = rounded.map { |fractional| Money.new(fractional, @currency) }
      Result.new(
        amounts: amounts,
        adjustments: adjustments,
        total: Money.new(@target, @currency),
      )
    end

    private

    def resolve_currency(line_amounts, target_total, currency)
      money_inputs = line_amounts.grep(Money)
      money_inputs << target_total if target_total.is_a?(Money)
      currencies = money_inputs.map(&:currency).uniq

      if currency
        resolved = Currency.wrap(currency)
        unless currencies.all? { |other| other == resolved }
          raise ArgumentError, "currency of Money inputs does not match the given currency"
        end

        resolved
      elsif currencies.empty?
        Money.default_currency || raise(Currency::NoCurrency, "must provide a currency")
      elsif currencies.size > 1
        raise ArgumentError, "all Money inputs must share a single currency"
      else
        currencies.first
      end
    end

    def extract_target(target_total)
      target = to_rational(target_total)
      unless target.denominator == 1
        raise ArgumentError, "target_total must be a whole number of subunits"
      end

      target.numerator
    end

    def normalize_adjustable(adjustable, size)
      indices =
        case adjustable
        when nil
          (0...size).to_a
        when Integer
          [adjustable]
        when Range
          adjustable.to_a
        when Array
          if boolean_mask?(adjustable, size)
            (0...size).select { |index| adjustable[index] }
          else
            adjustable.dup
          end
        else
          raise ArgumentError, "adjustable must be nil, an Integer, a Range, or an Array"
        end

      unless indices.all? { |index| index.is_a?(Integer) }
        raise ArgumentError, "adjustable indices must be Integers"
      end
      valid_index = ->(index) { index.between?(-size, -1) || index.between?(0, size - 1) }
      unless indices.all?(&valid_index)
        raise ArgumentError, "adjustable index out of range"
      end

      indices.map { |index| index >= 0 ? index : index + size }.uniq.sort
    end

    def boolean_mask?(values, size)
      values.size == size && values.all? { |value| value == true || value == false }
    end

    def to_rational(value)
      case value
      when Money
        fractional = value.fractional
        fractional.is_a?(Rational) ? fractional : BigDecimal(fractional.to_s).to_r
      when Rational then value
      when Integer then value.to_r
      when BigDecimal then value.to_r
      when Numeric then BigDecimal(value.to_s).to_r
      else raise ArgumentError, "expected a Numeric or Money, got #{value.class}"
      end
    end

    def remainder_fraction(rational)
      rational - rational.floor
    end

    def select_by_largest_remainder(indices, count)
      indices
        .sort_by { |index| [-remainder_fraction(@lines[index]), index] }
        .first(count)
    end

    def select_by_smallest_remainder(indices, count)
      indices
        .sort_by { |index| [remainder_fraction(@lines[index]), index] }
        .first(count)
    end

    # Rounds to a whole integer using exact Rational arithmetic, honouring the
    # configured BigDecimal rounding mode without floating point drift.
    def nearest_integral(rational, mode)
      floor = rational.floor
      remainder = rational - floor

      case mode
      when BigDecimal::ROUND_FLOOR
        floor
      when BigDecimal::ROUND_CEILING
        remainder.zero? ? floor : floor + 1
      when BigDecimal::ROUND_DOWN
        rational.truncate
      when BigDecimal::ROUND_UP
        if remainder.zero?
          floor
        elsif rational.positive?
          floor + 1
        else
          floor
        end
      when BigDecimal::ROUND_HALF_DOWN
        if remainder > HALF
          floor + 1
        elsif remainder < HALF
          floor
        else
          rational.positive? ? floor : floor + 1
        end
      when BigDecimal::ROUND_HALF_EVEN
        if remainder > HALF
          floor + 1
        elsif remainder < HALF
          floor
        elsif floor.even?
          floor
        else
          floor + 1
        end
      when BigDecimal::ROUND_HALF_UP
        if remainder == HALF && !rational.positive?
          floor
        elsif remainder >= HALF
          floor + 1
        else
          floor
        end
      else
        raise ArgumentError, "unsupported rounding mode: #{mode}"
      end
    end
  end
end
