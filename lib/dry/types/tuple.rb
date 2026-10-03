# frozen_string_literal: true

module Dry
  module Types
    # Tuple types describe arrays with types assigned to positions.
    #
    # Fixed positions are coerced in order. A trailing +rest:+ type applies to
    # every remaining value. Trailing +default+ and +optional+ positions may be
    # omitted. Lax tuples retain an invalid value at its index; constrained
    # tuples apply outer array rules after positional coercion succeeds.
    #
    # @api public
    class Tuple < Array
      UNDEFINED_REST = ::Object.new.freeze

      # @return [Array<Type,Object>]
      attr_reader :types

      # @return [Type,Object,nil]
      attr_reader :rest

      # @param [Class] primitive
      # @param [Hash] options
      #
      # @option options [Array<Type,Object>] :types
      # @option options [Type,Object,nil] :rest
      #
      # @api private
      def initialize(primitive, types:, rest: UNDEFINED_REST, **options)
        @types = types
        @rest = UNDEFINED_REST.equal?(rest) ? nil : rest

        tuple_options = options.merge(types: @types)
        tuple_options[:rest] = @rest if rest?

        super(primitive, **tuple_options)
      end

      # @return [Boolean]
      #
      # @api public
      def rest? = !@rest.nil?

      # @return [String]
      #
      # @api public
      def name = "Tuple"

      # @param [Object] input
      #
      # @return [Array]
      #
      # @api private
      def call_unsafe(input)
        try(input) { |failure| raise failure.error }.input
      end

      # @param [Object] input
      #
      # @return [Array]
      #
      # @api private
      def call_safe(input)
        try(input) { return yield(input) }.input
      end

      # @param [Array,Object] input
      # @param [#call,nil] block
      #
      # @return [Result,Logic::Result]
      #
      # @api public
      def try(input, &block)
        if primitive?(input)
          error = arity_error(input)
          result = coerce(input) unless error

          if error.nil? && result.failure?
            error = result.error
          end

          if error
            failure = failure(input, error)
            block ? yield(failure) : failure
          else
            success(result.input)
          end
        else
          failure = failure(input, CoercionError.new("#{input} is not an array"))
          block ? yield(failure) : failure
        end
      end

      # Build a lax tuple. Lax tuples keep invalid positional values instead
      # of rejecting the whole array.
      #
      # @return [Lax]
      #
      # @api public
      def lax
        tuple_options = {}
        tuple_options[:rest] = rest.lax if rest?

        Tuple::Lax.new(Tuple.new(
          primitive,
          types: types.map(&:lax),
          **tuple_options,
          meta: meta
        ))
      end

      # @see Nominal#to_ast
      #
      # @api public
      def to_ast(meta: true)
        fixed = types.map { |type| type_ast(type, meta: meta) }
        rest_node = rest? ? type_ast(rest, meta: meta) : nil

        [:tuple, [fixed, rest_node, meta_ast(meta)]]
      end

      # @api private
      def constructor_type = ::Dry::Types::Tuple::Constructor

      # @api private
      def call_lax(input)
        return input unless primitive?(input)
        return input if arity_error(input)

        output = []

        types.each_with_index do |type, index|
          output << element_lax(type, input, index)
        end

        if rest?
          input.drop(types.size).each do |value|
            output << rest.call_safe(value) { |coerced = value| coerced }
          end
        end

        output
      end

      private

      def coerce(input)
        output = []

        types.each_with_index do |type, index|
          result = element_result(type, input, index)

          if result.failure?
            return failure(input, TupleError.at(index, result.error))
          end

          output << result.input
        end

        if rest?
          tail_index = types.size

          input.drop(types.size).each do |value|
            result = rest.try(value)
            if result.failure?
              return failure(input, TupleError.at(tail_index, result.error))
            end

            output << result.input
            tail_index += 1
          end
        end

        success(output)
      end

      def arity_error(input)
        minimum = types.rindex { |type| required_position?(type) }&.+(1) || 0

        if input.size < minimum || (!rest? && input.size > types.size)
          index = [input.size, types.size].min
          input.size < minimum ? TupleError.missing(index) : TupleError.unexpected(index)
        end
      end

      def type_ast(type, meta:)
        type.respond_to?(:to_ast) ? type.to_ast(meta: meta) : type
      end

      def required_position?(type)
        !position_default?(type) && !position_optional?(type)
      end

      def position_default?(type)
        type.respond_to?(:default?) && type.default?
      end

      def position_optional?(type)
        type.respond_to?(:optional?) && type.optional?
      end

      def element_result(type, input, index)
        if index < input.size
          type.try(input[index])
        elsif position_default?(type)
          type.try(Undefined)
        else
          success(nil)
        end
      end

      def element_lax(type, input, index)
        if index < input.size
          type.call_safe(input[index]) { |value = input[index]| value }
        elsif position_default?(type)
          type.call_unsafe(Undefined)
        else
          nil
        end
      end
    end
  end
end
