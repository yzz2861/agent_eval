# frozen_string_literal: true

module Dry
  module Types
    # Stream is a lazy collection type for single-pass enumerables such as
    # the enumerators returned by bulk imports. Unlike {Array}, applying a
    # stream type never materializes the input: members are converted one by
    # one as the returned {Stream::Result} is iterated.
    #
    # @api public
    class Stream < Nominal
      # Error handling strategies for member conversion
      #
      # - +:halt+ stops iteration by raising on the first failing member
      # - +:collect+ yields an indexed {Stream::Item} per member instead
      ERROR_STRATEGIES = %i[halt collect].freeze

      # Build a stream type with a member type
      #
      # @param [Type, #call, String] type
      # @param [Symbol] on_error error strategy, :halt or :collect
      #
      # @return [Stream::Member]
      #
      # @api public
      def of(type, on_error: :halt)
        unless ERROR_STRATEGIES.include?(on_error)
          raise ::ArgumentError, "unknown error strategy: #{on_error.inspect}"
        end

        member =
          case type
          when ::String then Types[type]
          else type
          end

        Stream::Member.new(primitive, **options, member: member, on_error: on_error)
      end

      # Streams accept any single-pass traversable input, not only enumerators
      #
      # @param [Object] value
      #
      # @return [Boolean]
      #
      # @api public
      def primitive?(value) = value.respond_to?(:each)
    end
  end
end
