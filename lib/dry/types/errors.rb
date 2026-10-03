# frozen_string_literal: true

module Dry
  module Types
    extend ::Dry::Core::ClassAttributes

    # @!attribute [r] namespace
    #   @return [Container{String => Nominal}]
    defines :namespace

    namespace self

    # Base class for coercion errors raise by dry-types
    #
    class CoercionError < ::StandardError
      # @api private
      def self.handle(exception, meta: Undefined)
        if block_given?
          yield
        else
          raise new(
            exception.message,
            meta: meta,
            backtrace: exception.backtrace
          )
        end
      end

      # Metadata associated with the error
      #
      # @return [Object]
      attr_reader :meta

      # @api private
      def initialize(message, meta: Undefined, backtrace: Undefined)
        unless message.is_a?(::String)
          raise ::ArgumentError, "message must be a string, #{message.class} given"
        end

        super(message)
        @meta = Undefined.default(meta, nil)
        set_backtrace(backtrace) unless Undefined.equal?(backtrace)
      end
    end

    # Collection of multiple errors
    #
    class MultipleError < CoercionError
      # @return [Array<CoercionError>]
      attr_reader :errors

      # @param [Array<CoercionError>] errors
      def initialize(errors)
        super("")
        @errors = errors
      end

      # @return string
      def message = errors.map(&:message).join(", ")

      # @return [Array]
      def meta = errors.map(&:meta)
    end

    class SchemaError < CoercionError
      # @return [String, Symbol]
      attr_reader :key

      # @return [Object]
      attr_reader :value

      # @param [String,Symbol] key
      # @param [Object] value
      # @param [String, #to_s] result
      def initialize(key, value, result)
        @key = key
        @value = value
        super(
          "#{value.inspect} (#{value.class}) has invalid type " \
          "for :#{key} violates constraints (#{result} failed)"
        )
      end
    end

    MapError = ::Class.new(CoercionError)

    # Base class for errors raised by {Dry::Types::DiscriminatedUnion}
    #
    class DiscriminatorError < CoercionError
      # @return [Array<Symbol, String>]
      attr_reader :path

      # @param [String] message
      # @param [Array<Symbol, String>] path
      def initialize(message, path: EMPTY_ARRAY)
        @path = path
        super(message)
      end

      private

      def tag_path = @path.map { |segment| segment.inspect }.join(" -> ")
    end

    # Raised when the discriminator tag is not present in the input
    #
    class MissingTagError < DiscriminatorError
      # @param [Array<Symbol, String>] path
      def initialize(path)
        @path = path
        super("discriminator tag #{tag_path} is missing in Hash input", path: path)
      end
    end

    # Raised when the discriminator tag does not match any of the branches
    #
    class UnknownTagError < DiscriminatorError
      # @return [Object]
      attr_reader :tag

      # @return [Array<Object>]
      attr_reader :known_tags

      # @param [Object] tag
      # @param [Array<Object>] known_tags
      # @param [Array<Symbol, String>] path
      def initialize(tag, known_tags, path)
        @tag = tag
        @known_tags = known_tags
        @path = path

        super(
          "unknown discriminator tag #{tag.inspect} at #{tag_path}, " \
          "expected one of #{known_tags.inspect}",
          path: path
        )
      end
    end

    # Raised when the discriminator tag itself has an unexpected type
    #
    class InvalidTagError < DiscriminatorError
      # @return [Object]
      attr_reader :tag

      # @param [Object] tag
      # @param [Array<Symbol, String>] path
      def initialize(tag, path)
        @tag = tag
        @path = path
        super(
          "discriminator tag at #{tag_path} " \
          "has invalid type #{tag.class}, expected Symbol or String",
          path: path
        )
      end
    end

    SchemaKeyError = ::Class.new(CoercionError)
    private_constant(:SchemaKeyError)

    class MissingKeyError < SchemaKeyError
      # @return [Symbol]
      attr_reader :key

      # @param [String,Symbol] key
      def initialize(key)
        @key = key
        super("#{key.inspect} is missing in Hash input")
      end
    end

    class UnknownKeysError < SchemaKeyError
      # @return [Array<Symbol>]
      attr_reader :keys

      # @param [<String, Symbol>] keys
      def initialize(keys)
        @keys = keys
        super("unexpected keys #{keys.inspect} in Hash input")
      end
    end

    class ConstraintError < CoercionError
      # @return [String, #to_s]
      attr_reader :result
      # @return [Object]
      attr_reader :input

      # @param [String, #to_s] result
      # @param [Object] input
      def initialize(result, input)
        @result = result
        @input = input

        if result.is_a?(::String)
          super(result)
        else
          super(to_s)
        end
      end

      # @return [String]
      def message
        "#{input.inspect} violates constraints (#{result} failed)"
      end
      alias_method :to_s, :message
    end
  end
end
