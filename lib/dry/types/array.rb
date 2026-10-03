# frozen_string_literal: true

module Dry
  module Types
    # Array type can be used to define an array with optional member type
    #
    # @api public
    class Array < Nominal
      # Build a tuple type with fixed positional types and an optional rest type
      #
      # @param [Array<Type>] types
      # @param [Type, undefined] rest
      #
      # @return [Tuple]
      #
      # @api public
      def tuple(*types, rest: Undefined)
        Tuple.new(primitive, **options, types: types, rest: rest, meta: meta)
      end

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

      # @api private
      def constructor_type
        ::Dry::Types::Array::Constructor
      end
    end
  end
end
