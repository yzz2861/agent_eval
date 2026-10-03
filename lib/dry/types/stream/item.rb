# frozen_string_literal: true

module Dry
  module Types
    class Stream
      # Indexed item produced by a stream using the +:continue+ error mode
      #
      # @api public
      class Item
        include ::Dry::Equalizer(:index, :value, :error, immutable: true)

        # @return [Integer]
        attr_reader :index

        # @return [Object]
        attr_reader :value

        # @return [Object, nil]
        attr_reader :error

        # @api private
        def self.success(index, value)
          new(index, value, nil)
        end

        # @api private
        def self.failure(index, value, error)
          new(index, value, error)
        end

        # @api private
        def initialize(index, value, error)
          @index = index
          @value = value
          @error = error
          freeze
        end

        # @return [Boolean]
        #
        # @api public
        def success? = error.nil?

        # @return [Boolean]
        #
        # @api public
        def failure? = !success?
      end
    end
  end
end
