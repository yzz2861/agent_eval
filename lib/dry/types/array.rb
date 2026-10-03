# frozen_string_literal: true

module Dry
  module Types
    # Array type can be used to define an array with optional member type
    #
    # @api public
    class Array < Nominal
      # Build an array type with a member type
      #
      # @param [Type,#call] type
      #
      # @return [Array::Member]
      #
      # @api public
      def of(type)
        member =
          case type
          when ::String then Types[type]
          else type
          end

        Array::Member.new(primitive, **options, member: member)
      end

      # Build a tuple type with positional types and an optional rest type
      #
      # @param [Array<Type,#call>] types
      # @param [Type,#call,nil] rest
      #
      # @return [Tuple]
      #
      # @api public
      def tuple(*types, rest: Undefined, **)
        tuple_options = {}
        tuple_options[:rest] = resolve_tuple_type(rest) unless Undefined.equal?(rest)

        Tuple.new(
          primitive,
          types: types.map { |type| resolve_tuple_type(type) },
          **tuple_options,
          meta: meta
        )
      end

      # @api private
      def constructor_type
        ::Dry::Types::Array::Constructor
      end

      private

      def resolve_tuple_type(type)
        type.is_a?(::String) ? Types[type] : type
      end
    end
  end
end
