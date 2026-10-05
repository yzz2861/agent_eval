# frozen_string_literal: true

require "bigdecimal"

module Dry
  module Validation
    # Generic balancing engine that aggregates two-sided detail lines
    #
    # Lines are grouped by one or more group keys and a unit (for example a
    # currency). For every group the sum of the left side must equal the sum
    # of the right side, compared with an explicit per-unit tolerance. All
    # arithmetic is done with +BigDecimal+ to avoid floating point drift.
    #
    # Missing values, values that cannot be converted and unsupported units
    # are reported per line instead of being silently treated as zero, so
    # amounts in different units can never cancel each other out.
    #
    # @api public
    class Balance
      # A single imbalance or per-line defect found while balancing
      #
      # @!attribute [r] code
      #   @return [Symbol] One of +:missing+, +:unsupported_unit+,
      #     +:invalid_amount+ or +:imbalance+
      # @!attribute [r] field
      #   @return [Symbol, nil] Name of the offending line field
      # @!attribute [r] group
      #   @return [Object, nil] Group key value
      # @!attribute [r] unit
      #   @return [Object, nil] Unit value
      # @!attribute [r] positions
      #   @return [Array<Integer>] 1-based positions of participating lines
      # @!attribute [r] difference
      #   @return [BigDecimal, nil] Left minus right for +:imbalance+
      # @!attribute [r] tolerance
      #   @return [BigDecimal, nil] Allowed tolerance for the group's unit
      Violation = ::Data.define(
        :code, :field, :group, :unit, :positions, :difference, :tolerance
      )

      # Localized message identifiers used for per-line violations
      MESSAGES = {
        missing: :balance_missing,
        unsupported_unit: :balance_unsupported_unit,
        invalid_amount: :balance_invalid_amount
      }.freeze

      # Values that represent an intentionally absent amount
      EMPTY_AMOUNTS = [nil, ""].freeze

      # @!attribute [r] group_keys
      #   @return [Array<Symbol>]
      attr_reader :group_keys

      # @!attribute [r] unit_key
      #   @return [Symbol]
      attr_reader :unit_key

      # @!attribute [r] left_key
      #   @return [Symbol]
      attr_reader :left_key

      # @!attribute [r] right_key
      #   @return [Symbol]
      attr_reader :right_key

      # Check that two sides of detail lines balance per group and unit
      #
      # @param [Symbol, Array<Symbol>] group_by Key or keys identifying a group
      # @param [Symbol] unit Key holding the unit (e.g. currency) of a line
      # @param [Symbol] left Key holding the left-side amount
      # @param [Symbol] right Key holding the right-side amount
      # @param [BigDecimal, #to_d, Hash{Object=>BigDecimal}] tolerance Explicit
      #   tolerance; a Hash maps individual units to their tolerances and also
      #   defines the supported units
      # @param [Array, nil] supported_units Explicit list of supported units
      #
      # @return [Array<Violation>]
      #
      # @api public
      def self.call(rows, group_by:, unit:, left:, right:, tolerance: nil, supported_units: nil)
        new(
          group_by: group_by, unit: unit, left: left, right: right,
          tolerance: tolerance, supported_units: supported_units
        ).call(rows)
      end

      # @api private
      def initialize(group_by:, unit:, left:, right:, tolerance:, supported_units: nil)
        validate_keys!(group_by, unit, left, right)

        @group_keys = Array(group_by).map(&:to_sym)
        @unit_key = unit.to_sym
        @left_key = left.to_sym
        @right_key = right.to_sym
        @scalar_tolerance, @unit_tolerances = normalize_tolerance(tolerance)
        @supported_units = normalize_supported_units(supported_units)
        validate_config!
      end

      # Check that two sides of detail lines balance per group and unit
      #
      # @param [Array<Hash>] rows Plain hashes representing detail lines
      #
      # @return [Array<Violation>]
      #
      # @api public
      def call(rows)
        groups = Hash.new { |hash, key| hash[key] = Group.new }
        violations = []

        rows.each_with_index do |row, index|
          before = violations.size
          parsed = inspect_row(row, index + 1, violations)
          next unless violations.size == before

          group_value, unit_value, left_value, right_value = parsed
          groups[[group_value, unit_value.to_s]].add(left_value, right_value, index + 1)
        end

        violations.concat(imbalances(groups))
      end

      private

      # @api private
      class Group
        attr_reader :positions

        def initialize
          @left = BigDecimal("0")
          @right = BigDecimal("0")
          @positions = []
        end

        def add(left, right, position)
          @left += left
          @right += right
          @positions << position
        end

        def difference
          @left - @right
        end
      end

      def inspect_row(row, position, violations)
        unless row.is_a?(::Hash)
          raise ::ArgumentError, "balance rows must be Hashes, #{row.inspect} was given"
        end

        [
          read_group(row, position, violations),
          read_unit(row, position, violations),
          read_amount(row, @left_key, position, violations),
          read_amount(row, @right_key, position, violations)
        ]
      end

      def read_group(row, position, violations)
        missing = @group_keys.reject { |key| row.key?(key) && !row[key].nil? }
        missing.each do |key|
          violations << Violation.new(
            :missing, key, nil, nil, [position], nil, nil
          )
        end
        return nil unless missing.empty?

        values = @group_keys.map { |key| row[key] }
        values.size == 1 ? values.first : values
      end

      def read_unit(row, position, violations)
        unit = row[@unit_key]

        if !row.key?(@unit_key) || unit.nil?
          violations << Violation.new(:missing, @unit_key, nil, nil, [position], nil, nil)
          nil
        else
          supported_unit?(unit) ? unit : unsupported_unit(unit, position, violations)
        end
      end

      def unsupported_unit(unit, position, violations)
        violations << Violation.new(
          :unsupported_unit, @unit_key, nil, unit, [position], nil, nil
        )
        nil
      end

      def read_amount(row, key, position, violations)
        value = row[key]

        if !row.key?(key) || EMPTY_AMOUNTS.include?(value)
          violations << Violation.new(:missing, key, nil, nil, [position], nil, nil)
          return nil
        end

        if value.is_a?(::Float)
          violations << Violation.new(:invalid_amount, key, nil, nil, [position], nil, nil)
          return nil
        end

        BigDecimal(value.to_s)
      rescue ::ArgumentError, ::BigDecimal::Error
        violations << Violation.new(:invalid_amount, key, nil, nil, [position], nil, nil)
        nil
      end

      def imbalances(groups)
        sorted = groups.sort_by { |(group, unit), _| [group_key_for_sort(group), unit.to_s] }

        sorted.filter_map do |(group, unit), bucket|
          difference = bucket.difference
          tolerance = tolerance_for(unit)

          next if difference.abs <= tolerance

          Violation.new(
            :imbalance, nil, group, unit, bucket.positions.sort, difference, tolerance
          )
        end
      end

      def group_key_for_sort(group)
        group.is_a?(::Array) ? group.map(&:to_s) : group.to_s
      end

      def supported_unit?(unit)
        units = @supported_units || @unit_tolerances&.keys
        units.nil? || units.include?(unit.to_s)
      end

      def tolerance_for(unit)
        @scalar_tolerance || @unit_tolerances.fetch(unit.to_s)
      end

      def normalize_tolerance(tolerance)
        if tolerance.nil?
          raise InvalidBalanceOptionError, ":tolerance must be set explicitly"
        end

        if tolerance.is_a?(::Hash)
          tolerances = tolerance.to_h do |unit, value|
            [unit.to_s, to_bigdecimal!(value, :tolerance)]
          end
          [nil, tolerances]
        else
          [to_bigdecimal!(tolerance, :tolerance), nil]
        end
      end

      def normalize_supported_units(supported_units)
        return nil if supported_units.nil?

        Array(supported_units).map(&:to_s)
      end

      def to_bigdecimal!(value, option)
        case value
        when ::BigDecimal
          value
        when ::Integer, ::String
          BigDecimal(value.to_s)
        else
          raise InvalidBalanceOptionError,
                "#{option} must be a BigDecimal-convertible value, #{value.inspect} was given"
        end
      rescue ::ArgumentError
        raise InvalidBalanceOptionError,
              "#{option} must be a BigDecimal-convertible value, #{value.inspect} was given"
      end

      def validate_config!
        if @group_keys.empty? || @group_keys.include?(nil)
          raise InvalidBalanceOptionError, ":group_by must name at least one key"
        end

        if @unit_tolerances && @unit_tolerances.empty?
          raise InvalidBalanceOptionError, ":tolerance must configure at least one unit"
        end

        validate_tolerances!
        validate_units!
      end

      def validate_keys!(group_by, unit, left, right)
        named = {group_by: group_by, unit: unit, left: left, right: right}

        named.each do |name, value|
          if value.nil? || (name.equal?(:group_by) && Array(value).any?(nil))
            raise InvalidBalanceOptionError, ":#{name} must name a key"
          end
        end

        keys = [unit, left, right, *Array(group_by)]
        unless keys.all? { |key| key.is_a?(::Symbol) || key.is_a?(::String) }
          raise InvalidBalanceOptionError, "balance keys must be symbols or strings"
        end
      end

      def validate_tolerances!
        values = @scalar_tolerance.nil? ? @unit_tolerances.values : [@scalar_tolerance]

        if values.any?(&:negative?)
          raise InvalidBalanceOptionError, ":tolerance must not be negative"
        end
      end

      def validate_units!
        return if @supported_units.nil?
        return unless @unit_tolerances

        if @supported_units.sort != @unit_tolerances.keys.sort
          raise InvalidBalanceOptionError,
                ":supported_units must match the tolerance units"
        end
      end
    end
  end
end
