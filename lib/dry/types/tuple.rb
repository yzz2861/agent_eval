# frozen_string_literal: true

module Dry
  module Types
    # Fixed-size positional types with an optional rest type
    #
    # Fixed positions are coerced in order and the optional rest type is
    # applied to every remaining element. Missing or unexpected positions are
    # structural failures. Trailing defaults fill omitted fixed positions.
    #
    # Constraints remain active in regular tuples and are unwrapped by lax.
    # Lax keeps an invalid element in its original position, while structural
    # failures return the whole input unchanged.
    #
    # @example event data with numeric samples
    #   event = Dry::Types["nominal.array"].tuple(
    #     Dry::Types["strict.string"],
    #     Dry::Types["coercible.integer"],
    #     rest: Dry::Types["coercible.float"]
    #   )
    #
    #   event.(["click", "3", "1.25", "2.5"]) # => ["click", 3, 1.25, 2.5]
    #
    # @api public
    class Tuple < Array
      # @return [Array<Type>]
      attr_reader :types

      # @return [Type, undefined]
      attr_reader :rest

      # @param [Class] primitive
      # @param [Hash] options
      #
      # @option options [Array<Type>] :types
      # @option options [Type, undefined] :rest
      #
      # @api private
      def initialize(primitive, **options)
        types = options.fetch(:types, EMPTY_ARRAY).map { resolve_type(_1) }
        rest = options.fetch(:rest, Undefined)
        rest = Undefined if rest.nil?
        rest = resolve_type(rest) unless Undefined.equal?(rest)

        @types = types
        @rest = rest

        super(primitive, **options, types: types, rest: rest)
      end

      # @param [Object] input
      #
      # @return [Array]
      #
      # @api private
      def call_unsafe(input)
        assert_array!(input)
        assert_arity!(input)

        output = []

        input.each_with_index do |value, index|
          begin
            coerced = type_at(index).call_unsafe(value)
          rescue CoercionError => element_error
            raise TupleError.at(index, element_error)
          end

          output << coerced unless index >= types.size && Undefined.equal?(coerced)
        end

        append_missing_defaults_unsafe(output, input.size)

        output
      end

      # @param [Object] input
      #
      # @return [Array]
      #
      # @api private
      def call_safe(input)
        return yield(input) unless primitive?(input)
        return yield(input) if arity_error(input)

        output = []

        input.each_with_index do |value, index|
          coerced = type_at(index).call_safe(value) { return yield(input) }
          output << coerced unless index >= types.size && Undefined.equal?(coerced)
        end

        append_missing_defaults_safe(output, input.size) { return yield(input) }

        output
      end

      # @param [Array, Object] input
      # @param [#call,nil] block
      #
      # @yieldparam [Failure] failure
      # @yieldreturn [Result]
      #
      # @return [Result, Logic::Result]
      #
      # @api public
      def try(input, &block)
        unless primitive?(input)
          failure = failure(input, CoercionError.new("#{input} is not an array"))
          return block ? yield(failure) : failure
        end

        arity_error = arity_error(input)
        if arity_error
          failure = failure(input, arity_error)
          return block ? yield(failure) : failure
        end

        output = []
        error = nil

        input.each_with_index do |value, index|
          result = type_at(index).try(value)

          if result.failure?
            error = TupleError.at(index, result.error)
            break
          end

          output << result.input unless index >= types.size && Undefined.equal?(result.input)
        end

        unless error
          types.each_with_index do |type, index|
            next if index < input.size

            result = type.try(Undefined)
            if result.failure?
              error = TupleError.at(index, result.error)
              break
            end

            output << result.input
          end
        end

        if error
          failure = failure(input, error)
          block ? yield(failure) : failure
        else
          success(output)
        end
      end

      # @return [Lax]
      #
      # @api public
      def lax
        lax_rest = Undefined.equal?(rest) ? Undefined : rest.lax
        Lax.new(with(types: types.map(&:lax), rest: lax_rest))
      end

      # @see Nominal#to_ast
      #
      # @api public
      def to_ast(meta: true)
        rest_ast = Undefined.equal?(rest) ? nil : type_ast(rest, meta: meta)

        [
          :tuple,
          [types.map { type_ast(_1, meta: meta) }, rest_ast, meta_ast(meta)]
        ]
      end

      # @api private
      def constructor_type = ::Dry::Types::Array::Constructor

      private

      # @api private
      def type_at(index)
        index < types.size ? types[index] : rest
      end

      # @api private
      def arity_error(input)
        minimum_size = types.size - trailing_defaults_size

        if input.size < minimum_size
          TupleError.missing(input.size, input.size, minimum_size, types.size, has_rest?)
        elsif !has_rest? && input.size > types.size
          TupleError.unexpected(types.size, input.size, types.size)
        end
      end

      # @api private
      def trailing_defaults_size
        count = 0

        types.reverse_each do |type|
          break unless type.default?

          count += 1
        end

        count
      end

      # @api private
      def has_rest? = !Undefined.equal?(rest)

      # @api private
      def assert_array!(input)
        unless primitive?(input)
          raise CoercionError, "#{input} is not an array"
        end
      end

      # @api private
      def assert_arity!(input)
        error = arity_error(input)
        raise error if error
      end

      # @api private
      def append_missing_defaults_unsafe(output, input_size)
        types.each_with_index do |type, index|
          next if index < input_size

          begin
            output << type.call_unsafe(Undefined)
          rescue CoercionError => element_error
            raise TupleError.at(index, element_error)
          end
        end
      end

      # @api private
      def append_missing_defaults_safe(output, input_size)
        types.each_with_index do |type, index|
          next if index < input_size

          output << type.call_safe(Undefined) { yield }
        end
      end

      # @api private
      def resolve_type(type)
        case type
        when Type then type
        when ::String then Types[type]
        else type
        end
      end

      # @api private
      def type_ast(type, meta:)
        type.respond_to?(:to_ast) ? type.to_ast(meta: meta) : type
      end
    end

  end
end
