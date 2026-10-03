# frozen_string_literal: true

require "concurrent/map"

require "dry/validation/constants"

module Dry
  module Validation
    # Result objects are returned by contracts
    #
    # @api public
    class Result
      include ::Dry::Equalizer(:schema_result, :context, :errors, inspect: false)

      # Build a new result
      #
      # @param [Dry::Schema::Result] schema_result
      #
      # @api private
      def self.new(schema_result, context = ::Concurrent::Map.new, options = EMPTY_HASH)
        result = super
        yield(result) if block_given?
        result.freeze
      end

      # Context that's shared between rules
      #
      # @return [Concurrent::Map]
      #
      # @api public
      attr_reader :context

      # Result from contract's schema
      #
      # @return [Dry::Schema::Result]
      #
      # @api private
      attr_reader :schema_result

      # Result options
      #
      # @return [Hash]
      #
      # @api private
      attr_reader :options

      # Initialize a new result
      #
      # @api private
      def initialize(schema_result, context, options)
        @schema_result = schema_result
        @context = context
        @options = options
        @nested_contract_results = options.fetch(:nested_contract_results, EMPTY_ARRAY).dup
        @errors = initialize_errors
      end

      # Return values wrapper with the input processed by schema
      #
      # @return [Values]
      #
      # @api public
      def values
        @values ||= Values.new(schema_result.to_h)
      end

      # Get error set
      #
      # @!macro errors-options
      #   @param [Hash] new_options
      #   @option new_options [Symbol] :locale Set locale for messages
      #   @option new_options [Boolean] :hints Enable/disable hints
      #   @option new_options [Boolean] :full Get messages that include key names
      #
      # @return [MessageSet]
      #
      # @api public
      def errors(new_options = EMPTY_HASH)
        new_options.empty? ? @errors : @errors.with(schema_errors(new_options), new_options)
      end

      # Check if result is successful
      #
      # @return [Bool]
      #
      # @api public
      def success?
        @errors.empty?
      end

      # Check if result is not successful
      #
      # @return [Bool]
      #
      # @api public
      def failure?
        !success?
      end

      # Check if values include an error for the provided key
      #
      # @api public
      def error?(key)
        errors.any? { |msg| Schema::Path[msg.path].include?(Schema::Path[key]) }
      end

      # Check if the base schema (without rules) includes an error for the provided key
      #
      # @api private
      def schema_error?(key)
        schema_result.error?(key) || nested_schema_error?(Schema::Path[key].to_a)
      end

      # Check if the rules includes an error for the provided key
      #
      # @api private
      def rule_error?(key)
        !schema_error?(key) && error?(key)
      end

      # Check if the result contains any base rule errors
      #
      # @api private
      def base_rule_error?
        !errors.filter(:base?).empty?
      end

      # Check if there's any error for the provided key
      #
      # This does not consider errors from the nested values
      #
      # @api private
      def base_error?(key)
        schema_result.errors.any? { |error|
          key_path = Schema::Path[key]
          err_path = Schema::Path[error.path]

          next unless key_path.same_root?(err_path)

          key_path == err_path
        }
      end

      # Add a new error for the provided key
      #
      # @api private
      def add_error(error)
        @errors.add(error)
        self
      end

      # Add errors, transformed values, and context from a nested contract result
      #
      # @api private
      def add_contract_result(path, contract_result)
        prefix = Schema::Path[path].to_a

        schema_result.at(prefix) { |nested_result|
          nested_result.replace(contract_result.to_h)
        }

        contract_result.context.each_pair do |key, value|
          context[key] = value unless context.key?(key)
        end

        register_contract_results(prefix, contract_result)

        add_nested_schema_messages(prefix, contract_result).each do |message|
          @errors.add(message)
        end

        contract_result.errors.source_messages.each do |message|
          next unless message.is_a?(Message)

          @errors.add(
            Message[
              message.text,
              [*prefix, *message.path],
              message.meta
            ]
          )
        end

        self
      end

      # Read a value under provided key
      #
      # @param [Symbol] key
      #
      # @return [Object]
      #
      # @api public
      def [](key)
        values[key]
      end

      # Check if a key was set
      #
      # @param [Symbol] key
      #
      # @return [Bool]
      #
      # @api public
      def key?(key)
        values.key?(key)
      end

      # Coerce to a hash
      #
      # @api public
      def to_h
        values.to_h
      end

      # Return a string representation
      #
      # @api public
      def inspect
        if context.empty?
          "#<#{self.class}#{to_h} errors=#{errors.to_h}>"
        else
          "#<#{self.class}#{to_h} errors=#{errors.to_h} context=#{context.each.to_h}>"
        end
      end

      # Freeze result and its error set
      #
      # @api private
      def freeze
        values.freeze
        errors.freeze
        super
      end

      # Pattern matching
      #
      # @api private
      def deconstruct_keys(keys)
        values.deconstruct_keys(keys)
      end

      # Pattern matching
      #
      # @api private
      def deconstruct
        [values, context.each.to_h]
      end

      private

      # @api private
      def schema_errors(options)
        return schema_result.message_set(options).to_a if @nested_contract_results.empty?

        schema_messages(options, EMPTY_ARRAY)
      end

      # @api private
      def schema_messages(options, prefix)
        local_schema_messages(options, prefix) +
          @nested_contract_results.flat_map { |nested_prefix, result|
            result.send(:schema_messages, options, [*prefix, *nested_prefix])
          }
      end

      # @api private
      def local_schema_messages(options, prefix)
        schema_result.message_compiler
          .with(options)
          .(prefix_ast(schema_result.result_ast, prefix))
          .to_a
      end

      # @api private
      def schema_hints(options, prefix)
        compiled_messages = local_schema_hints(options, prefix).to_a

        all_messages = compiled_messages + @nested_contract_results.flat_map { |nested_prefix, result|
          result.send(:schema_hints, options, [*prefix, *nested_prefix]).to_a
        }

        Schema::MessageSet.new(all_messages, failures: false)
      end

      # @api private
      def local_schema_hints(options, prefix)
        Schema::MessageSet.new(
          schema_result.message_compiler
            .with(options.merge(failures: false))
            .(prefix_ast(schema_result.result_ast, prefix))
            .to_a,
          failures: false
        )
      end

      # @api private
      def prefix_ast(ast, prefix)
        prefix.reverse.reduce(ast) { |nodes, key| [[:key, [key, [:set, nodes]]]] }
      end

      # @api private
      def add_nested_schema_messages(prefix, result)
        result.send(:local_schema_messages, EMPTY_HASH, prefix) +
          result.send(:nested_contract_results).flat_map { |nested_prefix, nested_result|
            add_nested_schema_messages([*prefix, *nested_prefix], nested_result)
          }
      end

      # @api private
      def register_contract_results(prefix, contract_result)
        @nested_contract_results << [prefix, contract_result]

        contract_result.send(:nested_contract_results).each do |nested_prefix, nested_result|
          @nested_contract_results << [[*prefix, *nested_prefix], nested_result]
        end
      end

      # @api private
      def nested_schema_error?(key_path, results = @nested_contract_results)
        results.any? do |prefix, result|
          next false unless key_path.empty? || key_path[0, prefix.length] == prefix

          relative_path = key_path[prefix.length..]

          if relative_path.nil? || relative_path.empty?
            result.send(:schema_failure?)
          else
            result.schema_error?(relative_path)
          end
        end
      end

      # @api private
      def schema_failure?
        schema_result.failure? ||
          @nested_contract_results.any? { |_, result| result.send(:schema_failure?) }
      end

      # @api private
      attr_reader :nested_contract_results

      # @api private
      def initialize_errors(options = self.options)
        MessageSet.new(schema_errors(options), options)
      end
    end
  end
end
