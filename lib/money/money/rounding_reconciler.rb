# frozen_string_literal: true

class Money
  # Reconciles independently rounded line amounts with an invoice-level total.
  #
  # When every line of an invoice is rounded to the currency's smallest unit
  # on its own, the sum of the rounded lines can differ by a few subunits from
  # the rounded invoice total. The reconciler nudges adjustable lines by at
  # most one subunit each so the rounded lines add up exactly to the target,
  # distributing the residual with a stable largest-remainder rule:
  #
  # - When subunits must be added, the lines that were rounded down the most
  #   (largest positive remainder) receive +1 subunit first.
  # - When subunits must be removed, the lines that were rounded up the most
  #   (most negative remainder) receive -1 subunit first.
  # - Ties are broken by original line order, so the result is deterministic.
  #
  # Negative lines follow the same remainder rule. Zero lines have a zero
  # remainder and are only adjusted as a last resort. Lines not marked as
  # adjustable always keep their naively rounded value.
  #
  # All computation happens in integer subunits of the currency; the target
  # total is never silently changed. If the residual cannot be absorbed by
  # the adjustable lines, an {UnreachableTargetError} is raised.
  class RoundingReconciler
    # Raised when the residual between the rounded lines and the target
    # cannot be absorbed by the adjustable lines (each line absorbs at most
    # one subunit).
    class UnreachableTargetError < StandardError; end

    # The outcome of a reconciliation.
    #
    # +lines+       — final per-line Money amounts, in whole subunits.
    # +adjustments+ — per-line Money delta applied on top of the naively
    #                 rounded line (zero for untouched lines).
    Result = Struct.new(:lines, :adjustments, keyword_init: true) do
      # Sum of the reconciled lines. Always equals the target.
      #
      # @return [Money]
      def total
        lines.sum
      end
    end

    class << self
      # Reconciles unrounded line amounts with a rounded invoice-level target.
      #
      # @param amounts [Array<Numeric>] unrounded line amounts, in currency units.
      # @param target [Money, Numeric] the invoice-level total. A Money is used
      #   as-is (rounded to whole subunits if needed); a Numeric is interpreted
      #   in currency units and rounded with +rounding_mode+.
      # @param currency [Money::Currency, String, Symbol] the shared currency.
      # @param adjustable [nil, Array<Integer>, Array<Boolean>] which lines may
      #   be nudged by one subunit: nil (all lines), a list of line indexes, or
      #   a boolean mask with one entry per line.
      # @param rounding_mode [Integer] BigDecimal rounding mode used to round
      #   each line (and a Numeric target) to whole subunits.
      #
      # @return [Result] final per-line Money amounts and per-line adjustments.
      # @raise [ArgumentError] if a Money target uses a different currency.
      # @raise [UnreachableTargetError] if the residual cannot be absorbed by
      #   the adjustable lines.
      #
      # @example
      #   result = Money::RoundingReconciler.reconcile(
      #     [BigDecimal("3.333"), BigDecimal("3.333"), BigDecimal("3.334")],
      #     target: Money.new(10_00, "USD"),
      #     currency: "USD",
      #   )
      #   result.lines       #=> [Money.new(333), Money.new(333), Money.new(334)]
      #   result.adjustments #=> [Money.new(0), Money.new(0), Money.new(1)]
      def reconcile(amounts, target:, currency: Money.default_currency, adjustable: nil, rounding_mode: Money.rounding_mode)
        currency = Money::Currency.wrap(currency)
        subunit_to_unit = currency.subunit_to_unit

        exact = amounts.map { |amount| Allocation.convert_to_big_decimal(amount) * subunit_to_unit }
        rounded = exact.map { |value| value.round(0, rounding_mode).to_i }
        target_subunits = target_subunits(target, currency, rounding_mode)

        deltas = Array.new(amounts.length, 0)
        distribute(
          target_subunits - rounded.sum,
          remainders(exact, rounded),
          adjustable_indexes(adjustable, amounts.length),
          deltas,
        )

        Result.new(
          lines: rounded.each_with_index.map { |value, index| Money.new(value + deltas[index], currency) },
          adjustments: deltas.map { |delta| Money.new(delta, currency) },
        )
      end

      private

      def target_subunits(target, currency, rounding_mode)
        if target.is_a?(Money)
          unless target.currency == currency
            raise ArgumentError, "target currency #{target.currency} does not match #{currency}"
          end

          Allocation.convert_to_big_decimal(target.fractional).round(0, rounding_mode).to_i
        else
          (Allocation.convert_to_big_decimal(target) * currency.subunit_to_unit).round(0, rounding_mode).to_i
        end
      end

      # Signed distance between the exact subunit value and its rounded value,
      # e.g. +0.4 for a line rounded down from 100.4 to 100.
      def remainders(exact, rounded)
        exact.each_with_index.map { |value, index| value - rounded[index] }
      end

      def adjustable_indexes(adjustable, size)
        case adjustable
        when nil
          (0...size).to_a
        when Array
          if adjustable.all? { |entry| entry == true || entry == false }
            raise ArgumentError, "adjustable mask must have one entry per line" unless adjustable.length == size

            adjustable.each_index.select { |index| adjustable[index] }
          else
            adjustable.each do |index|
              unless index.is_a?(Integer) && index >= 0 && index < size
                raise ArgumentError, "adjustable index #{index.inspect} out of range"
              end
            end
            adjustable.uniq
          end
        else
          raise ArgumentError, "adjustable must be nil, an Array of indexes, or an Array of booleans"
        end
      end

      # Hands out the residual one subunit at a time to the adjustable lines
      # with the largest remainder in the direction of the adjustment.
      def distribute(residual, remainders, adjustable, deltas)
        return if residual.zero?

        if adjustable.empty? || residual.abs > adjustable.size
          raise UnreachableTargetError,
                "cannot absorb a residual of #{residual} subunit(s) with #{adjustable.size} adjustable line(s); " \
                "each line absorbs at most one subunit"
        end

        step = residual.positive? ? 1 : -1
        ordered = adjustable.sort_by { |index| [-step * remainders[index], index] }
        ordered.first(residual.abs).each { |index| deltas[index] += step }
      end
    end
  end
end
