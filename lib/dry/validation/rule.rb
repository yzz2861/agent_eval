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
      #   @return [Symbol, nil]
      #   @api public
      option :name, optional: true

      # @!attribute [r] depends_on
      #   @return [Array<Symbol>]
      #   @api public
      option :depends_on, default: proc { EMPTY_ARRAY.dup }

      # @!attribute [r] macros
      #   @return [Array<Symbol>]
      #   @api private
      option :macros, default: proc { EMPTY_ARRAY.dup }

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

      # Assign a name to the rule so that other rules can depend on it
      #
      # @example
      #   rule(:account).named(:account_active) do
      #     key.failure("must be active") unless active?(value)
      #   end
      #
      # @param [Symbol, String] name
      #
      # @return [Rule]
      #
      # @api public
      def named(name, &block)
        @name = name.to_sym
        apply_block(block) if block
        self
      end

      # Declare rules that must pass before this rule is executed
      #
      # When any of the dependencies did not pass (it failed or was skipped
      # itself), this rule is skipped and its outcome explains why.
      #
      # @example
      #   rule(:quota).depends_on(:account_active) do
      #     key.failure("quota exceeded") if over_quota?(value)
      #   end
      #
      # @param [Array<Symbol, String>] names Names of prerequisite rules
      #
      # @return [Rule, Array<Symbol>] self when declaring dependencies,
      #   the declared dependencies when called without arguments
      #
      # @api public
      def depends_on(*names, &block)
        return @depends_on if names.empty? && !block

        @depends_on = names.flatten.map { |name| name.to_sym }
        apply_block(block) if block
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
        details = +"keys=#{keys.inspect}"
        details << " name=#{name.inspect}" if name
        details << " depends_on=#{depends_on.inspect}" unless depends_on.empty?
        %(#<#{self.class} #{details}>)
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

      private

      # Replace the rule's block and recompute its keyword options
      #
      # @api private
      def apply_block(block)
        @block = block
        @block_options = map_keywords(block)
      end
    end
  end
end
