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

    interval_overlap = proc do |macro:|
      options = macro.args[0] || EMPTY_HASH
      root = path.to_a
      records = values[root]

      checker = Macros::IntervalOverlap.new(root: root, records: records, result: result, **options)
      conflict = checker.call

      if conflict
        first, second = conflict
        first_path = [*root, first.index]
        second_path = [*root, second.index]
        message = checker.message

        key(first_path).failure(message, other_index: second.index)
        key(second_path).failure(message, other_index: first.index)
      end
    end

    # Interval overlap macros
    #
    # @example
    #   rule(:bookings).validate(non_overlapping: {
    #     group_by: :resource_id,
    #     start_field: :starts_at,
    #     end_field: :ends_at,
    #     endpoints: :right_open
    #   })
    #
    # @api public
    Macros.register(:non_overlapping, &interval_overlap)
    Macros.register(:interval_overlap, &interval_overlap)
  end
end
