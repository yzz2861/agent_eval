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

      # @!attribute [r] association_rule
      #   @return [Boolean]
      #   @api private
      option :association_rule, default: proc { false }

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

      # Define a validation function for matching elements of two arrays
      #
      # The function receives an Association with valid items and their original
      # indexes. Duplicate keys retain every item, and items rejected by the
      # schema are excluded from the association.
      #
      # @example
      #   rule(:invoices, :allocations).associate(:id, :invoice_id) do |association:|
      #     association.groups.each do |group|
      #       total = group[:right].sum { |item| item.value[:amount] }
      #       if total > group[:left].first.value[:amount]
      #         key(association.right_error_path(group[:right].first.index)).failure("too much")
      #       end
      #     end
      #
      #     association.unmatched_right.each do |item|
      #       key(association.right_error_path(item.index, :invoice_id)).failure("not found")
      #     end
      #   end
      #
      # @return [Rule]
      #
      # @api public
      def associate(left_key, right_key = left_key, &block)
        left_root, right_root = keys.map { |key| Schema::Path[key] }

        @block = proc do
          left_array = values[*left_root]
          right_array = values[*right_root]

          next unless [left_array, right_array].all?(::Array)
          next if result.base_error?(left_root) || result.base_error?(right_root)

          association = Association.new(
            left_path: left_root.to_a,
            right_path: right_root.to_a,
            left_key: left_key,
            right_key: right_key,
            result: result
          )

          evaluator = with(keys: [left_root, right_root], association: association, &block)
          failures.concat(evaluator.failures)
        end

        @block_options = map_keywords(block) if block
        @association_rule = true

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
