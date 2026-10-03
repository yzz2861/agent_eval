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

      # Group-level errors collected while evaluating a schema
      #
      # @return [Array<KeyGroupError>]
      attr_accessor :group_errors

      # @api private
      def initialize(message, meta: Undefined, backtrace: Undefined)
        unless message.is_a?(::String)
          raise ::ArgumentError, "message must be a string, #{message.class} given"
        end

        super(message)
        @meta = Undefined.default(meta, nil)
        @group_errors = EMPTY_ARRAY
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

    # Error raised when a group of keys violates its presence constraint
    #
    class KeyGroupError < CoercionError
      # @return [Symbol]
      attr_reader :kind

      # @return [Array<Array<Array<Symbol>>>]
      attr_reader :members

      # @return [Array<Array<Array<Symbol>>>] members present in the input
      attr_reader :present_paths

      # @return [Array<Array<Array<Symbol>>>] members missing from the input
      attr_reader :missing_paths

      # @param kind [Symbol]
      # @param members [Array<Array<Array<Symbol>>>]
      # @param present_paths [Array<Array<Array<Symbol>>>]
      # @param missing_paths [Array<Array<Array<Symbol>>>]
      #
      # @api private
      def initialize(kind, members, present_paths, missing_paths)
        @kind = kind
        @members = members
        @present_paths = present_paths
        @missing_paths = missing_paths

        super(message_for(kind))
      end

      private

      # @api private
      def message_for(kind)
        case kind
        when :exactly_one
          "expected exactly one of #{format_members(members)} to be present, " \
          "got #{format_members(present_paths)}"
        when :at_least_one
          "expected at least one of #{format_members(members)} to be present, got none"
        when :all_or_none
          "expected all or none of #{format_members(members)} to be present, " \
          "missing #{format_members(missing_paths)}"
        end
      end

      # @api private
      def format_members(members)
        members.map { |paths|
          formatted = paths.map { |path| path.map(&:to_s).join(".") }
          formatted.size == 1 ? formatted.first : "(#{formatted.join(" + ")})"
        }.inspect
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
