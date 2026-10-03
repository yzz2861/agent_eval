# frozen_string_literal: true

module Dry
  module Types
    class Stream < Nominal
      # Indexed per-member outcome yielded by {Stream::Result} when the
      # stream type uses the :collect error strategy
      #
      # @api public
      class Item
        include ::Dry::Equalizer(:index, :value, :error, immutable: true)

        # @return [Integer] position of the member in the stream
        attr_reader :index

        # @return [Object] converted member, Undefined when failed
        attr_reader :value

        # @return [CoercionError, nil] conversion error
        attr_reader :error

        # @api private
        def initialize(index:, value: Undefined, error: nil)
          @index = index
          @value = value
          @error = error
          freeze
        end

        # @return [Boolean]
        #
        # @api public
        def success? = @error.nil?

        # @return [Boolean]
        #
        # @api public
        def failure? = !success?
      end
    end
  end
end
