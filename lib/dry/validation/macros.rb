# frozen_string_literal: true

module Dry
  module Validation
    # API for registering and accessing Rule macros
    #
    # @api public
    module Macros
      module Registrar
        # Register a macro
        #
        # @example register a global macro
        #   Dry::Validation.register_macro(:even_numbers) do
        #     key.failure('all numbers must be even') unless values[key_name].all?(&:even?)
        #   end
        #
        # @example register a contract macro
        #   class MyContract < Dry::Validation::Contract
        #     register_macro(:even_numbers) do
        #       key.failure('all numbers must be even') unless values[key_name].all?(&:even?)
        #     end
        #   end
        #
        # @param [Symbol] name The name of the macro
        # @param [Array] args Optional default positional arguments for the macro
        #
        # @return [self]
        #
        # @see Macro
        #
        # @api public
        def register_macro(...)
          macros.register(...)
          self
        end
      end

      # Registry for macros
      #
      # @api public
      class Container
        include Core::Container::Mixin

        # Register a new macro
        #
        # @example in a contract class
        #   class MyContract < Dry::Validation::Contract
        #     register_macro(:even_numbers) do
        #       key.failure('all numbers must be even') unless values[key_name].all?(&:even?)
        #     end
        #   end
        #
        # @param [Symbol] name The name of the macro
        #
        # @return [self]
        #
        # @api public
        def register(name, *args, &block)
          macro = Macro.new(name, args: args, block: block)
          super(name, macro, call: false, &nil)
          self
        end
      end

      # Return a registered macro
      #
      # @param [Symbol] name The name of the macro
      #
      # @return [Proc]
      #
      # @api public
      def self.[](name)
        container[name]
      end

      # Register a global macro
      #
      # @see Container#register
      #
      # @return [Macros]
      #
      # @api public
      def self.register(...)
        container.register(...)
        self
      end

      # @api private
      def self.container
        @container ||= Container.new
      end
    end

    # Acceptance macro
    #
    # @api public
    Macros.register(:acceptance) do
      key.failure(:acceptance, key: key_name) unless values[key_name].equal?(true)
    end

    # Nested contract macro
    #
    # @api public
    Macros.register(:contract) do |macro:|
      contract, context_keys = macro.args

      unless contract.is_a?(Contract)
        raise ::ArgumentError, "+contract+ must be a Dry::Validation::Contract instance"
      end

      next unless key? && !value.nil?

      nested_context = context_keys.then { |keys|
        case keys
        when ::Symbol
          {keys => _context[keys]} if _context.key?(keys)
        when ::Array
          keys.each_with_object({}) { |key, context|
            context[key] = _context[key] if _context.key?(key)
          }
        when ::Hash
          keys.each_with_object({}) { |(child_key, parent_key), context|
            context[child_key] = _context[parent_key] if _context.key?(parent_key)
          }
        else
          EMPTY_HASH
        end
      }

      result.add_contract_result(path.to_a, contract.call(value, nested_context || EMPTY_HASH))
    end
  end
end
