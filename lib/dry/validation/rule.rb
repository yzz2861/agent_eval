# frozen_string_literal: true

require "dry/validation/constants"

module Dry
  module Validation
    # Rules capture configuration and evaluator blocks
    #
    # When a rule is applied, it creates an `Evaluator` using schema result and its
    # block will be evaluated in the context of the evaluator.
    #
    # @see Contract#rule
    #
    # @api public
    class Rule < Function
      include ::Dry::Equalizer(:keys, :block, :name, :depends_on, inspect: false)

      # @!attribute [r] keys
      #   @return [Array<Symbol, String, Hash>]
      #   @api private
      option :keys

      # @!attribute [r] name
      #   @return [Symbol, String, nil] Optional name that other rules can depend on
      #   @api private
      option :name, optional: true

      # @!attribute [r] depends_on
      #   @return [Array<Symbol, String>, Symbol, String, nil] Names of prerequisite rules
      #   @api private
      option :depends_on, optional: true

      # @!attribute [r] macros
      #   @return [Array<Symbol>]
      #   @api private
      option :macros, default: proc { EMPTY_ARRAY.dup }

      # @api private
      def initialize(*, name: nil, depends_on: EMPTY_ARRAY, **, &block)
        super
        @name = name&.to_sym
        @depends_on = Array(depends_on).flatten.map(&:to_sym).uniq.freeze
      end

      # Return the rule's name, if it has one
      #
      # @return [Symbol, nil]
      #
      # @api public
      attr_reader :name

      # Return names of rules that must pass before this rule is applied
      #
      # @return [Array<Symbol>]
      #
      # @api public
      attr_reader :depends_on

      # Evaluate the rule within the provided context
      #
      # @param [Contract] contract
      # @param [Result] result
      #
      # @api private
      def call(contract, result)
        Evaluator.new(
          contract,
          keys: keys,
          macros: macros,
          block_options: block_options,
          result: result,
          values: result.values,
          _context: result.context,
          &block
        )
      end

      # Define which macros should be executed
      #
      # @see Contract#rule
      # @return [Rule]
      #
      # @api public
      def validate(*macros, &block)
        @macros = parse_macros(*macros)
        @block = block if block
        self
      end

      # Define a validation function for each element of an array
      #
      # The function will be applied only if schema checks passed
      # for a given array item.
      #
      # @example
      #   rule(:nums).each do |index:|
      #     key([:number, index]).failure("must be greater than 0") if value < 0
      #   end
      #   rule(:nums).each(min: 3)
      #   rule(address: :city) do
      #      key.failure("oops") if value != 'Munich'
      #   end
      #
      # @return [Rule]
      #
      # @api public
      #
      # rubocop:disable Metrics/AbcSize
      def each(*macros, &block)
        root = keys[0]
        macros = parse_macros(*macros)
        @keys = []

        @block = proc do
          unless result.base_error?(root) || !values.key?(root) || values[root].nil?
            values[root].each_with_index do |_, idx|
              path = [*Schema::Path[root].to_a, idx]

              next if result.schema_error?(path)

              evaluator = with(macros: macros, keys: [path], index: idx, &block)

              failures.concat(evaluator.failures)
            end
          end
        end

        @block_options = map_keywords(block) if block

        self
      end
      # rubocop:enable Metrics/AbcSize

      # Return a nice string representation
      #
      # @return [String]
      #
      # @api public
      def inspect
        %(#<#{self.class} keys=#{keys.inspect}>)
      end

      # Parse function arguments into macros structure
      #
      # @return [Array]
      #
      # @api private
      def parse_macros(*args)
        args.each_with_object([]) do |spec, macros|
          case spec
          when Hash
            add_macro_from_hash(macros, spec)
          else
            macros << Array(spec)
          end
        end
      end

      def add_macro_from_hash(macros, spec)
        spec.each do |k, v|
          macros << [k, v.is_a?(::Array) ? v : [v]]
        end
      end
    end
  end
end
