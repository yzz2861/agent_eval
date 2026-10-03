# frozen_string_literal: true

module Dry
  module Types
    # Error raised when a tuple element cannot be coerced
    #
    # @api public
    class TupleError < CoercionError
      # @return [Array<Integer>]
      attr_reader :path

      # @return [Object, nil]
      attr_reader :cause_error

      # @api private
      def initialize(path, message, cause_error = nil)
        @path = Array(path)
        @cause_error = cause_error
        super(message)
      end

      # @return [Integer]
      #
      # @api public
      def index = path.last

      # @api private
      def self.at(index, error)
        if error.is_a?(TupleError)
          path = [index, *error.path]
          location = path.map { "[#{_1}]" }.join
          message = error.message.sub(
            /\A(Tuple element at )\[\d+(?:\]\[\d+)*\]/,
            "\\1#{location}"
          )
          new(path, message, error.cause_error || error)
        else
          new([index], "Tuple element at [#{index}] is invalid: #{error.message}", error)
        end
      end

      # @api private
      def self.missing(index, actual_size, required_size, expected_size, has_rest)
        requirement =
          if has_rest
            "at least #{required_size}"
          elsif required_size < expected_size
            "between #{required_size} and #{expected_size}"
          else
            "exactly #{required_size}"
          end

        new(
          [index],
          "Tuple element at [#{index}] is missing: tuple requires #{requirement} " \
            "elements, got #{actual_size}"
        )
      end

      # @api private
      def self.unexpected(index, actual_size, expected_size)
        new(
          [index],
          "Tuple element at [#{index}] is unexpected: tuple requires exactly " \
            "#{expected_size} elements, got #{actual_size}"
        )
      end
    end
  end
end
