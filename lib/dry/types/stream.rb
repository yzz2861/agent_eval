# frozen_string_literal: true

module Dry
  module Types
    # Streaming collection type for single-pass enumerable inputs
    #
    # @api public
    class Stream < Nominal
      ERROR_MODES = {
        abort: :raise,
        stop: :raise,
        raise: :raise,
        fail_fast: :raise,
        fast: :raise,
        continue: :continue,
        collect: :continue,
        indexed: :continue,
        items: :continue
      }.freeze

      # Build a stream type with a member type
      #
      # @param [Type, #call] type
      # @param [Hash] options
      #
      # @return [Stream::Member]
      #
      # @api public
      def of(type, **options)
        member =
          case type
          when ::String then Types[type]
          else type
          end

        Member.new(primitive, **options_for_member, **options, member: member)
      end

      # Do not consume the input when checking whether it can be wrapped.
      # Member validity is only known after the returned stream is consumed.
      #
      # @param [Object] input
      #
      # @return [Boolean]
      #
      # @api public
      def valid?(input = Undefined) = primitive?(input)

      # @return [String]
      #
      # @api public
      def name = "Stream"

      # @api private
      def constructor_type = ::Dry::Types::Stream::Constructor

      private

      # @api private
      def options_for_member
        options.except(:namespace)
      end
    end
  end
end
