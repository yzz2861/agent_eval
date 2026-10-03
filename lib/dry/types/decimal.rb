# frozen_string_literal: true

require "bigdecimal"
require "bigdecimal/util"

module Dry
  module Types
    # A decimal type designed for values that must stay exact, such as money.
    #
    # Unlike the plain {Nominal} BigDecimal type, a Decimal can be configured
    # with a total {#precision} (significant digits), a {#scale} (digits after
    # the decimal point) and a {#rounding} mode.
    #
    # By default inputs that would need to be rounded are *rejected*. Callers
    # opt into quantization explicitly by passing a +rounding:+ mode.
    #
    # @example strict money type
    #   money = Dry::Types["decimal.exact"].fixed(precision: 8, scale: 2)
    #   money.call("12.34")    # => 0.1234e2
    #   money.call("12.345")   # => raises CoercionError
    #
    #   rounded = money.with_rounding(:half_up)
    #   rounded.call("12.345") # => 0.1235e2
    #
    # Floats are rejected by default because a binary float is not an exact
    # representation of most decimal fractions. Pass +accept_float: true+ to
    # allow them, in which case their full decimal expansion is used.
    #
    # @api public
    class Decimal < Nominal
      include ::Dry::Equalizer(:precision, :scale, :rounding, :accept_float,
                                inspect: false, immutable: true)

      # Rounding mode names accepted by the type mapped onto the integer
      # modes defined by BigDecimal.
      ROUNDING_MODES = {
        up: BigDecimal::ROUND_UP,
        down: BigDecimal::ROUND_DOWN,
        ceiling: BigDecimal::ROUND_CEILING,
        floor: BigDecimal::ROUND_FLOOR,
        half_up: BigDecimal::ROUND_HALF_UP,
        half_down: BigDecimal::ROUND_HALF_DOWN,
        half_even: BigDecimal::ROUND_HALF_EVEN,
        banker: BigDecimal::ROUND_HALF_EVEN
      }.freeze

      # Matches decimal strings written in plain or scientific notation.
      # Underscores, leading/trailing whitespace and tokens such as +NaN+
      # deliberately do not match.
      DECIMAL_STRING = /\A[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\z/.freeze

      # Significant digits retained when expanding a Float to its exact
      # decimal value (a binary64 fraction terminates well within this).
      FLOAT_EXPANSION_DIGITS = 40

      private_constant :ROUNDING_MODES, :DECIMAL_STRING, :FLOAT_EXPANSION_DIGITS

      # @return [Integer, nil] Total number of significant digits accepted
      attr_reader :precision

      # @return [Integer, nil] Number of digits kept after the decimal point
      attr_reader :scale

      # @return [Integer, nil] Rounding mode used for quantization
      attr_reader :rounding

      # @return [Boolean] Whether binary floats are accepted
      attr_reader :accept_float

      # Build a decimal type constrained by precision and scale.
      #
      # @param precision [Integer] total number of significant digits
      # @param scale [Integer] digits after the decimal point
      # @param rounding [Integer, Symbol, nil] rounding mode, +nil+ rejects
      #   inputs that need rounding
      # @param accept_float [Boolean] whether +Float+ inputs are accepted
      #
      # @return [Decimal]
      #
      # @api public
      def self.fixed(precision:, scale: 0, rounding: nil, accept_float: false)
        new(
          precision: precision,
          scale: scale,
          rounding: rounding.nil? ? nil : resolve_rounding(rounding),
          accept_float: accept_float
        )
      end

      # Configure precision and scale on an existing decimal type.
      #
      # @param (see self.fixed)
      #
      # @return [Decimal]
      #
      # @api public
      def fixed(precision:, scale: 0, rounding: nil, accept_float: @accept_float)
        with(
          precision: precision,
          scale: scale,
          rounding: rounding.nil? ? nil : self.class.resolve_rounding(rounding),
          accept_float: accept_float
        )
      end

      # Look up a rounding mode given a symbolic name or an integer mode.
      #
      # @param mode [Symbol, Integer]
      #
      # @return [Integer]
      #
      # @raise [ArgumentError] when the mode is unknown
      #
      # @api private
      def self.resolve_rounding(mode)
        case mode
        when ::Integer
          unless ROUNDING_MODES.value?(mode)
            raise ::ArgumentError, "unknown rounding mode #{mode.inspect}"
          end

          mode
        when ::Symbol
          ROUNDING_MODES.fetch(mode) do
            raise ::ArgumentError,
                  "unknown rounding mode #{mode.inspect}, " \
                  "supported modes are #{ROUNDING_MODES.keys.uniq.inspect}"
          end
        else
          raise ::ArgumentError,
                "rounding mode must be a Symbol or Integer, #{mode.class} given"
        end
      end

      # @param primitive [Class] kept for {Options} compatibility
      #
      # @option precision [Integer, nil] total significant digits
      # @option scale [Integer, nil] digits after the decimal point
      # @option rounding [Integer, Symbol, nil] rounding mode
      # @option accept_float [Boolean] accept Float inputs
      #
      # @api private
      def initialize(primitive = ::BigDecimal, precision: Undefined, scale: Undefined,
                     rounding: Undefined, accept_float: Undefined, **options)
        precision = Undefined.default(precision, nil)
        scale = Undefined.default(scale, nil)
        accept_float = Undefined.default(accept_float, false)

        @precision = precision.nil? ? nil : validate_dimension(:precision, precision)
        @scale = scale.nil? ? nil : validate_dimension(:scale, scale)

        if @precision && @scale && @scale > @precision
          raise ::ArgumentError,
                "scale (#{@scale}) cannot be greater than precision (#{@precision})"
        end

        @rounding = Undefined.default(rounding, nil)
        @rounding = @rounding.nil? ? nil : self.class.resolve_rounding(@rounding)
        @accept_float = accept_float

        super(::BigDecimal, **options)
      end

      # Return a copy of the type with updated options while preserving the
      # current precision, scale, rounding and float configuration.
      #
      # @return [Decimal]
      #
      # @api public
      def with(**new_options)
        if new_options.empty?
          self
        else
          meta = new_options.key?(:meta) ? new_options.fetch(:meta) : @meta
          self.class.new(
            precision: new_options.fetch(:precision, @precision),
            scale: new_options.fetch(:scale, @scale),
            rounding: new_options.fetch(:rounding, @rounding),
            accept_float: new_options.fetch(:accept_float, @accept_float),
            meta: meta
          )
        end
      end

      # Return a copy of the type with a different rounding mode.
      #
      # @param mode [Symbol, Integer] rounding mode
      #
      # @return [Decimal]
      #
      # @see self.resolve_rounding
      #
      # @api public
      def with_rounding(mode)
        with(rounding: self.class.resolve_rounding(mode))
      end

      # Return a copy of the type that accepts (or rejects) Float inputs.
      #
      # @param value [Boolean]
      #
      # @return [Decimal]
      #
      # @api public
      def accepting_float(value = true)
        with(accept_float: value)
      end

      # @return [Boolean]
      #
      # @api public
      def accept_float? = @accept_float

      # @return [Boolean]
      #
      # @api public
      def fixed? = !@precision.nil?

      # Return a lax variant that keeps the original input on failure
      # instead of raising.
      #
      # @return [Lax]
      #
      # @api public
      def lax = Lax.new(self)

      # @param [Object] input
      #
      # @return [BigDecimal]
      #
      # @raise [CoercionError]
      #
      # @api private
      def call_unsafe(input) = coerce_decimal(input)

      # @param [Object] input
      #
      # @return [BigDecimal]
      #
      # @api private
      def call_safe(input, &block)
        return call_unsafe(input) unless block

        begin
          call_unsafe(input)
        rescue CoercionError
          yield(input)
        end
      end

      # @param [Object] input
      # @param [#call, nil] block
      #
      # @return [Result::Success, Result::Failure, Object]
      #
      # @api public
      def try(input, &block)
        result = begin
          success(coerce_decimal(input))
        rescue CoercionError => error
          failure(input, error)
        end

        block ? block.(result) : result
      end

      # @return [Array]
      #
      # @api public
      def to_ast(meta: true)
        [:decimal, [primitive, decimal_options, meta_ast(meta)]]
      end

      private

      # @return [Hash]
      #
      # @api private
      def decimal_options
        {
          precision: @precision,
          scale: @scale,
          rounding: @rounding,
          accept_float: @accept_float
        }
      end

      # Validate a non-negative integer precision/scale argument
      #
      # @return [Integer]
      #
      # @api private
      def validate_dimension(name, value)
        value = begin
          Integer(value)
        rescue ::ArgumentError, ::TypeError
          raise ::ArgumentError,
                "#{name} must be a non-negative Integer, #{value.inspect} given"
        end

        unless value >= 0
          raise ::ArgumentError, "#{name} must be non-negative, #{value} given"
        end

        value
      end

      # Coerce and validate an input value
      #
      # @return [BigDecimal]
      #
      # @api private
      def coerce_decimal(input)
        decimal = parse(input)
        ensure_finite(decimal, input)
        decimal = normalize(decimal)
        decimal = apply_scale(decimal)
        check_precision(decimal)
        decimal
      end

      # Parse the input into a BigDecimal, handling each supported class
      # separately so binary floats never sneak in as exact values.
      #
      # @return [BigDecimal]
      #
      # @api private
      def parse(input)
        case input
        when ::BigDecimal
          input
        when ::Integer
          BigDecimal(input)
        when ::Float
          parse_float(input)
        when ::String
          parse_string(input)
        else
          coercion_failure(input, "cannot be coerced to BigDecimal")
        end
      end

      # @return [BigDecimal]
      #
      # @api private
      def parse_float(input)
        unless @accept_float
          coercion_failure(
            input,
            "is a Float; floats are not accepted by default because binary " \
            "floats are not exact decimal values (use accept_float: true to " \
            "opt in to converting the full decimal expansion)"
          )
        end

        if input.nan?
          coercion_failure(input, "is not a finite decimal value (NaN)")
        elsif !input.infinite?.nil?
          coercion_failure(input, "is not a finite decimal value (Infinity)")
        end

        # Use the exact rational expansion of the binary float rather than
        # Float#to_d, which returns the shortest round-trip decimal and
        # would silently disguise binary representation error.
        rational = input.to_r
        decimal = BigDecimal(rational.numerator, FLOAT_EXPANSION_DIGITS) / rational.denominator
        decimal
      end

      # @return [BigDecimal]
      #
      # @api private
      def parse_string(input)
        unless DECIMAL_STRING.match?(input)
          coercion_failure(input, "is not a valid decimal string")
        end

        decimal = BigDecimal(input, exception: true)
        ensure_finite(decimal, input)
      rescue ::ArgumentError
        coercion_failure(input, "is not a valid decimal string")
      end

      # Reject NaN and Infinity, even when BigDecimal could parse them.
      #
      # @return [BigDecimal]
      #
      # @api private
      def ensure_finite(decimal, input)
        if decimal.nan?
          coercion_failure(input, "is not a finite decimal value (NaN)")
        elsif !decimal.infinite?.nil?
          coercion_failure(input, "is not a finite decimal value (Infinity)")
        end

        decimal
      end

      # Normalize a parsed value. Negative zero is collapsed to +0 so that
      # monetary zeros compare and render consistently.
      #
      # @return [BigDecimal]
      #
      # @api private
      def normalize(decimal)
        if decimal.zero? && decimal.to_s("F").start_with?("-")
          BigDecimal("0")
        else
          decimal
        end
      end

      # Quantize to the configured scale.
      #
      # Without a rounding mode an input with too many fractional digits is
      # rejected. With a rounding mode the value is rounded explicitly.
      #
      # @return [BigDecimal]
      #
      # @api private
      def apply_scale(decimal)
        return decimal if @scale.nil?

        unless fits_scale?(decimal, @scale)
          if @rounding.nil?
            raise CoercionError,
                  "#{format_decimal(decimal)} cannot be represented with " \
                  "scale #{@scale}; provide a rounding mode to quantize it"
          end

          decimal = decimal.round(@scale, @rounding)
        end

        decimal
      end

      # Check that the quantized value fits within the total precision.
      #
      # @api private
      def check_precision(decimal)
        return if @precision.nil?

        allowed_exponent = @precision - (@scale || 0)

        return if decimal.zero? || decimal.exponent <= allowed_exponent

        raise CoercionError,
              "#{format_decimal(decimal)} exceeds precision #{@precision} " \
              "with scale #{@scale || 0} (at most #{allowed_exponent} " \
              "integer digit#{"s" unless allowed_exponent == 1} allowed)"
      end

      # Whether the value can be expressed with at most +scale+ fractional
      # digits without losing information.
      #
      # @return [Boolean]
      #
      # @api private
      def fits_scale?(decimal, scale)
        decimal_scale(decimal) <= scale
      end

      # Number of significant fractional digits. BigDecimal 3.1+ exposes this
      # directly as +#scale+; fall back to the exponent/precision model on
      # older versions.
      #
      # @return [Integer]
      #
      # @api private
      def decimal_scale(decimal)
        return decimal.scale if decimal.respond_to?(:scale)
        return 0 if decimal.zero?

        [decimal.precision - [decimal.exponent, 0].max, 0].max
      end

      # Render a BigDecimal in plain (non-scientific) notation for messages.
      #
      # @return [String]
      #
      # @api private
      def format_decimal(decimal)
        decimal.to_s("F")
      end

      # @raise [CoercionError]
      #
      # @api private
      def coercion_failure(input, reason)
        raise CoercionError, "#{input.inspect} #{reason}"
      end
    end
  end
end
