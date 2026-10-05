# frozen_string_literal: true

require "bigdecimal"

module Dry
  module Validation
    # Generic left/right balance checker for grouped detail rows
    #
    # Rows are plain Hashes (symbol or string keys). Rows are grouped by the
    # given group fields plus the unit field, so amounts in different units
    # (e.g. currencies) are always summed and compared separately and can
    # never cancel each other out.
    #
    # All amounts are coerced to BigDecimal for exact decimal arithmetic.
    # Missing amounts, amounts that fail to convert, and rows with a unit
    # that is not in the explicit list of supported units are reported as
    # errors - they are never silently treated as zero.
    #
    # @example
    #   errors = Dry::Validation::Balance.call(
    #     rows,
    #     group_by: [:batch_id],
    #     unit: :currency,
    #     left: :debit,
    #     right: :credit,
    #     tolerance: "0.01",
    #     units: %w[CNY USD]
    #   )
    #
    # @api public
    module Balance
      # @api private
      ZERO = BigDecimal("0").freeze

      class << self
        # Check that left and right amounts balance within each group
        #
        # @param rows [Array<Hash>] detail rows (symbol or string keys)
        # @param group_by [Array<Symbol, String>] fields identifying a group
        # @param unit [Symbol, String] field holding the amount unit (e.g. currency)
        # @param left [Symbol, String] field holding left-side amounts
        # @param right [Symbol, String] field holding right-side amounts
        # @param tolerance [BigDecimal, Integer, Float, String] maximum allowed
        #   absolute difference per group, expressed in the group's own unit.
        #   Must be set explicitly; there is no implicit default.
        # @param units [Array] the supported unit values; a row carrying any
        #   other (or no) unit is an error, never a zero
        #
        # @return [Array<Hash>] one hash per problem found, empty when every
        #   group balances. Each hash carries a :reason, the :group values,
        #   the :unit and the affected row positions in :rows. Unbalanced
        #   groups also carry :left, :right and :difference totals.
        #
        # @api public
        def call(rows, group_by:, unit:, left:, right:, tolerance:, units:)
          group_keys = Array(group_by)
          limit = coerce_tolerance(tolerance)
          supported = coerce_units(units)

          groups = {}
          tainted = {}
          errors = []

          rows.each_with_index do |row, index|
            unless row.is_a?(::Hash)
              raise ::ArgumentError,
                    "balance rows must be Hashes (#{row.class} given at index #{index})"
            end

            group = group_keys.to_h { |name| [name, fetch(row, name)] }
            unit_value = fetch(row, unit)
            group_id = [group.values, unit_value]

            if unit_value.nil? || !supported.include?(unit_value.to_s)
              errors << {reason: :unsupported_unit, group: group, unit: unit_value, rows: [index]}
              tainted[group_id] = true
              next
            end

            amounts = amounts_for(row, left: left, right: right) do |reason, field, raw|
              errors << {
                reason: reason, group: group, unit: unit_value,
                field: field, value: raw, rows: [index]
              }
            end

            if amounts.nil?
              tainted[group_id] = true
              next
            end

            entry = groups[group_id] ||= {
              group_id: group_id, group: group, unit: unit_value,
              left: ZERO, right: ZERO, rows: []
            }
            entry[:left] += amounts[:left]
            entry[:right] += amounts[:right]
            entry[:rows] << index
          end

          groups.each_value do |entry|
            next if tainted[entry[:group_id]]

            difference = entry[:left] - entry[:right]
            next if difference.abs <= limit

            errors << {
              reason: :unbalanced,
              group: entry[:group], unit: entry[:unit],
              left: entry[:left], right: entry[:right],
              difference: difference, rows: entry[:rows]
            }
          end

          errors
        end

        # Build a human-readable message for an error returned by .call
        #
        # @param error [Hash] an error hash as returned by .call
        #
        # @return [String]
        #
        # @api public
        def message(error)
          location = "group #{error[:group].inspect}, unit #{error[:unit].inspect}, " \
                     "rows #{error[:rows].join(', ')}"

          case error[:reason]
          when :unbalanced
            "left total #{format(error[:left])} does not balance right total " \
              "#{format(error[:right])} (difference #{format(error[:difference])}, #{location})"
          when :missing_amount
            "amount #{error[:field].inspect} is missing (#{location})"
          when :invalid_amount
            "amount #{error[:field].inspect} is not a valid number: " \
              "#{error[:value].inspect} (#{location})"
          when :unsupported_unit
            "unit #{error[:unit].inspect} is not supported (#{location})"
          else
            "balance check failed (#{location})"
          end
        end

        private

        # @api private
        def amounts_for(row, left:, right:)
          amounts = {}
          valid = true

          {left: left, right: right}.each do |side, field|
            raw = fetch(row, field)
            amount = coerce_amount(raw)

            if amount.nil?
              yield(missing?(raw) ? :missing_amount : :invalid_amount, field, raw)
              valid = false
            else
              amounts[side] = amount
            end
          end

          amounts if valid
        end

        # @api private
        def fetch(row, field)
          return row[field] if row.key?(field)

          row[field.is_a?(::Symbol) ? field.to_s : field.to_sym]
        end

        # @api private
        def missing?(raw)
          raw.nil? || (raw.is_a?(::String) && raw.strip.empty?)
        end

        # Coerce a value to BigDecimal, returning nil when not possible
        #
        # @api private
        def coerce_amount(value)
          case value
          when ::BigDecimal
            value.finite? ? value : nil
          when ::Integer
            BigDecimal(value)
          when ::Float
            value.finite? ? BigDecimal(value.to_s) : nil
          when ::String
            amount = BigDecimal(value, exception: false)
            amount&.finite? ? amount : nil
          end
        end

        # @api private
        def coerce_tolerance(tolerance)
          amount = coerce_amount(tolerance)

          if amount.nil? || amount.negative?
            raise ::ArgumentError,
                  "tolerance must be set explicitly to a non-negative number " \
                  "(#{tolerance.inspect} given)"
          end

          amount
        end

        # @api private
        def coerce_units(units)
          list = Array(units)

          if list.empty?
            raise ::ArgumentError,
                  "units must list the supported units explicitly (none given)"
          end

          list.map(&:to_s)
        end

        # @api private
        def format(amount)
          amount.to_s("F")
        end
      end
    end
  end
end
