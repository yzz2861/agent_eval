# frozen_string_literal: true

module Dry
  module Types
    # Strict, configurable decimal type for fixed-precision numeric values
    #
    # @api public
    class Decimal < Nominal
      ROUNDING_MODES = {
        up: ::BigDecimal::ROUND_UP,
        down: ::BigDecimal::ROUND_DOWN,
        truncate: ::BigDecimal::ROUND_DOWN,
        ceiling: ::BigDecimal::ROUND_CEILING,
        ceil: ::BigDecimal::ROUND_CEILING,
        floor: ::BigDecimal::ROUND_FLOOR,
        half_up: ::BigDecimal::ROUND_HALF_UP,
        half_down: ::BigDecimal::ROUND_HALF_DOWN,
        half_even: ::BigDecimal::ROUND_HALF_EVEN,
        banker: ::BigDecimal::ROUND_HALF_EVEN
      }.freeze

      ROUNDING_CONSTANTS = ROUNDING_MODES.values.uniq.freeze

      FLOAT_EXACT_PRECISION = 1_100

      DECIMAL_STRING = /\A[+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?\z/

      # @return [Integer]
      attr_reader :precision

      # @return [Integer]
      attr_reader :scale

      # @return [Integer, nil]
      attr_reader :rounding

      # @return [Boolean]
      attr_reader :accept_float

      # Build a configured decimal type
      #
      # @overload call(precision, scale = 0, **options)
      # @overload call(precision:, scale: 0, **options)
      #
      # @return [Decimal]
      #
      # @api public
      def self.call(...)
        new(...)
      end

      # @see .call
      def self.[](...)
        new(...)
      end

      # @param [Integer] precision Maximum total number of significant digits
      # @param [Integer] scale Number of digits after the decimal point
      # @param [Symbol, Integer, nil] rounding BigDecimal rounding mode
      # @param [Boolean] accept_float Whether Float values are accepted
      #
      # @api public
      def initialize(
        precision = Undefined,
        scale = Undefined,
        *,
        rounding: nil,
        accept_float: Undefined,
        **options
      )
        if Undefined.equal?(precision)
          precision = options.delete(:precision) { raise ::ArgumentError, "missing keyword: :precision" }
        end
        scale = options.delete(:scale) { 0 } if Undefined.equal?(scale)

        @precision = validate_positive_integer(precision, :precision)
        @scale = validate_scale(scale)
        @rounding = resolve_rounding(rounding)
        @accept_float = resolve_float_option(accept_float)

        super(::BigDecimal, **options)
      end

      # @return [Boolean]
      def accept_float?
        accept_float
      end
      alias_method :allow_float?, :accept_float?

      # @api private
      def call_unsafe(input)
        coerce(input)
      end

      # @api private
      def call_safe(input)
        call_unsafe(input)
      rescue CoercionError
        yield(input)
      end

      # @api public
      def try(input, &block)
        success(call_unsafe(input))
      rescue CoercionError => error
        result = failure(input, error)
        block ? yield(result) : result
      end

      # Return a type with updated options
      #
      # @return [Decimal]
      #
      # @api public
      def with(
        precision: Undefined,
        scale: Undefined,
        rounding: Undefined,
        accept_float: Undefined,
        **options
      )

        self.class.new(
          Undefined.default(precision, @precision),
          Undefined.default(scale, @scale),
          rounding: Undefined.default(rounding, rounding_option),
          accept_float: Undefined.default(accept_float, @accept_float),
          **options
        )
      end

      # @api public
      def to_ast(meta: true)
        [:decimal, [
          precision,
          scale,
          {rounding: rounding_option, accept_float: accept_float?},
          meta_ast(meta)
        ]]
      end

      # @api public
      def lax
        Lax.new(self)
      end

      # @return [Symbol, nil]
      def rounding_option
        return nil if rounding.nil?

        ROUNDING_MODES.each_key.find { |name| ROUNDING_MODES[name] == rounding }
      end

      private

      def coerce(input)
        decimal =
          case input
          when ::BigDecimal
            input
          when ::Integer
            BigDecimal(input)
          when ::String
            parse_string(input)
          when ::Float
            coerce_float(input)
          else
            raise_coercion_error(input, "must be a String, Integer, BigDecimal, or Float")
          end

        raise_coercion_error(input, "must be finite") unless decimal.finite?
        quantize(input, decimal)
      end

      def parse_string(input)
        unless DECIMAL_STRING.match?(input)
          raise_coercion_error(input, "is not a valid decimal string")
        end

        BigDecimal(input)
      rescue ::ArgumentError => exception
        raise CoercionError.new(exception.message)
      end

      def coerce_float(input)
        unless accept_float?
          raise_coercion_error(input, "Float values are not accepted; use a String or BigDecimal")
        end

        raise_coercion_error(input, "must be finite") unless input.finite?
        BigDecimal(input.to_r, FLOAT_EXACT_PRECISION)
      end

      def quantize(input, decimal)
        truncated = decimal.round(scale, ::BigDecimal::ROUND_DOWN)
        needs_rounding = truncated != decimal

        if needs_rounding && rounding.nil?
          raise_coercion_error(
            input,
            "has more than #{scale} decimal digit#{"s" unless scale == 1}; " \
              "pass a rounding mode to quantize it"
          )
        end

        result = needs_rounding ? decimal.round(scale, rounding) : truncated
        result = result.abs if result.zero?

        ensure_precision(input, result)
      end

      def ensure_precision(input, decimal)
        return decimal if decimal.zero?

        _sign, _digits, _base, exponent = decimal.split
        integer_digits = [exponent, 0].max

        if integer_digits > precision - scale
          raise_coercion_error(input, "exceeds precision #{precision} with scale #{scale}")
        end

        decimal
      end

      def resolve_rounding(value)
        value = value.call if value.respond_to?(:call)

        case value
        when nil, false
          nil
        when Symbol
          ROUNDING_MODES.fetch(value) do
            raise ::ArgumentError, "unsupported rounding mode: #{value.inspect}"
          end
        when Integer
          unless ROUNDING_CONSTANTS.include?(value)
            raise ::ArgumentError, "unsupported rounding mode: #{value.inspect}"
          end

          value
        else
          raise ::ArgumentError, "unsupported rounding mode: #{value.inspect}"
        end
      end

      def resolve_float_option(value)
        return false if Undefined.equal?(value)

        unless value == true || value == false
          raise ::ArgumentError, "accept_float must be a Boolean"
        end

        value
      end

      def validate_positive_integer(value, name)
        unless value.is_a?(::Integer) && value.positive?
          raise ::ArgumentError, "#{name} must be a positive Integer"
        end

        value
      end

      def validate_scale(value)
        unless value.is_a?(::Integer) && !value.negative?
          raise ::ArgumentError, "scale must be a non-negative Integer"
        end

        scale = value

        unless scale <= precision
          raise ::ArgumentError, "scale must be less than or equal to precision"
        end

        scale
      end

      def raise_coercion_error(input, message)
        raise CoercionError, "#{input.inspect} (#{input.class}) #{message}"
      end
    end
  end
end
