# frozen_string_literal: true

require "dry/initializer"
require "dry/validation/constants"

module Dry
  module Validation
    # NestedContract applies another contract to a nested value or to each
    # element of an array value and merges the outcome back into the parent
    # result
    #
    # The nested contract's output replaces the value in the parent result and
    # its errors are imported with the nested path (and the array index, when
    # applied to elements) prepended to their paths
    #
    # @see Contract.contract
    #
    # @api public
    class NestedContract
      extend ::Dry::Initializer

      # @!attribute [r] path
      #   @return [Array<Symbol>]
      #   @api private
      option :path

      # @!attribute [r] contract
      #   @return [Contract]
      #   @api private
      option :contract

      # @!attribute [r] each
      #   @return [Boolean]
      #   @api private
      option :each, default: proc { false }

      # @!attribute [r] context_keys
      #   @return [Hash] Mapping of nested context keys to parent context keys
      #   @api private
      option :context_keys, default: proc { EMPTY_HASH }

      # Apply the nested contract to the value(s) found in the parent result
      #
      # The contract is not applied when the parent schema already rejected
      # the value or when there's no value to validate
      #
      # @param [Result] result
      #
      # @api private
      def call(result)
        if each?
          call_each(result)
        else
          call_one(path, result)
        end
      end

      # Return true when the contract is applied to each array element
      #
      # @return [Boolean]
      #
      # @api private
      def each?
        self.each
      end

      # Return a nice string representation
      #
      # @return [String]
      #
      # @api public
      def inspect
        %(#<#{self.class} path=#{path.inspect} contract=#{contract.class}>)
      end

      private

      # @api private
      def call_each(result)
        return if result.base_error?(path) || !result.key?(path)

        elements = result.values[path]
        return if elements.nil?

        elements.each_with_index do |element, index|
          element_path = [*path, index]

          next if element.nil? || result.schema_error?(element_path)

          apply(element_path, result)
        end
      end

      # @api private
      def call_one(path, result)
        return if !result.key?(path) || result.values[path].nil?

        apply(path, result)
      end

      # @api private
      def apply(target_path, result)
        sub_result = contract.call(result.values[target_path], child_context(result.context))

        merge_output(result, target_path, sub_result.to_h)

        sub_result.errors.source_messages.each_with_index do |message, index|
          next if message.respond_to?(:hint?) && message.hint?

          result.add_error(import_message(sub_result, message, index, target_path))
        end
      end

      # Build the context passed to the nested contract
      #
      # Only the declared keys are picked from the parent context, so the
      # nested contract runs with its own isolated context and whatever it
      # adds there never leaks back into the parent context
      #
      # @return [Hash]
      #
      # @api private
      def child_context(parent_context)
        return EMPTY_HASH if context_keys.empty?

        context_keys.each_with_object({}) do |(child_key, parent_key), context|
          context[child_key] = parent_context[parent_key] if parent_context.key?(parent_key)
        end
      end

      # Replace the value in the parent result with the nested contract's output
      #
      # @api private
      def merge_output(result, target_path, output)
        parent_output = result.schema_result.to_h
        *head, leaf = target_path
        holder = head.empty? ? parent_output : parent_output.dig(*head)
        holder[leaf] = output
      end

      # Import an error message from the nested result under the target path
      #
      # Messages keep their original text (or message template callable) and
      # meta, so that they can still be evaluated with another locale or
      # different options via `Result#errors`
      #
      # @return [Message]
      #
      # @api private
      def import_message(sub_result, message, index, target_path)
        full_path = [*target_path, *message.path.compact]

        if message.is_a?(Message)
          Message[message.text, full_path, message.meta]
        else
          Message[schema_message_source(sub_result, index), full_path, message.meta]
        end
      end

      # Build a message source that re-evaluates a nested schema message
      #
      # Schema messages are plain text by the time the nested result is built,
      # so the original message is looked up again (by its position) in a fresh
      # message set compiled with the requested options
      #
      # @return [Proc]
      #
      # @api private
      def schema_message_source(sub_result, index)
        ->(**opts) {
          message = sub_result.schema_result.message_set(opts.compact).to_a[index]
          [message.text, message.meta]
        }
      end
    end
  end
end
