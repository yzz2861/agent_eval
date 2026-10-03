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
      include ::Dry::Equalizer(:keys, :block, inspect: false)

      # @!attribute [r] keys
      #   @return [Array<Symbol, String, Hash>]
      #   @api private
      option :keys

      # @!attribute [r] macros
      #   @return [Array<Symbol>]
      #   @api private
      option :macros, default: proc { EMPTY_ARRAY.dup }

      # @!attribute [r] skip_schema_errors
      #   @return [Boolean]
      #   @api private
      option :skip_schema_errors, default: proc { true }

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

      # Define a validation function for matching two arrays
      #
      # The function receives an Association with matched records and the
      # original array indexes. Records whose association keys failed schema
      # checks are ignored. Repeated keys keep every record instead of only
      # making the last record available.
      #
      # @example
      #   rule(:invoices, :allocations).associate(
      #     :id, :invoice_id
      #   ) do |association:|
      #     association.groups.each do |group|
      #       key([:invoices, group[:left_index]]).failure("too much")
      #     end
      #   end
      #
      # @return [Rule]
      #
      # @api public
      def associate(left_key, right_key, &block)
        left_root, right_root = keys

        @skip_schema_errors = false

        @block = proc do
          next if result.base_error?(left_root) || result.base_error?(right_root)
          next unless values.key?(left_root) && values.key?(right_root)
          next if values[left_root].nil? || values[right_root].nil?

          association = Association.new(
            left: values[left_root],
            right: values[right_root],
            left_key: left_key,
            right_key: right_key,
            left_path: left_root,
            right_path: right_root,
            result: result
          )

          evaluator = with(keys: [], association: association, &block)
          failures.concat(evaluator.failures)
        end

        @block_options = map_keywords(block) if block

        self
      end

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
