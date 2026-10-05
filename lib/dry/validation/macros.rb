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

    # Balance macro
    #
    # Aggregates two-sided detail lines by group keys and a unit field and
    # verifies that the left side equals the right side for every group.
    #
    # @example
    #   class EntryContract < Dry::Validation::Contract
    #     schema do
    #       required(:lines).value(:array)
    #     end
    #
    #     rule(:lines).validate(
    #       balance: {
    #         group_by: :doc_id,
    #         unit: :currency,
    #         left: :debit,
    #         right: :credit,
    #         tolerance: { "USD" => "0.01", "JPY" => "1" }
    #       }
    #     )
    #   end
    #
    # @see Balance
    #
    # @api public
    Macros.register(:balance) do |macro:|
      options = macro.args.first

      unless options.is_a?(::Hash)
        raise InvalidBalanceOptionError,
              ":balance expects an options hash, #{options.inspect} was given"
      end

      unless value.nil? || value.is_a?(::Array)
        raise InvalidBalanceOptionError,
              ":balance must be applied to an Array, #{value.class} was given"
      end

      violations = Balance.call(value || [], **options)

      violations.each do |violation|
        if violation.code.equal?(:imbalance)
          base.failure(
            :balance,
            group: violation.group,
            unit: violation.unit,
            difference: violation.difference.to_s("F"),
            tolerance: violation.tolerance.to_s("F"),
            positions: violation.positions
          )
        else
          message = Balance::MESSAGES.fetch(violation.code)
          tokens = {
            field: violation.field,
            value: violation.unit
          }

          key([key_name, violation.positions.first - 1, violation.field]).failure(
            message, **tokens
          )
        end
      end
    end
  end
end
