# frozen_string_literal: true

require "dry/validation/macros/non_overlapping_intervals"

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

    # Interval overlap macro
    #
    # Checks that records (typically rows of a booking detail array) grouped by
    # a resource key do not occupy overlapping time intervals.
    #
    # @example bookings must not overlap per room, using half-open intervals
    #   schema do
    #     required(:bookings).array(:hash) do
    #       required(:room_id).filled(:integer)
    #       required(:starts_on).filled(:date)
    #       required(:ends_on).filled(:date)
    #     end
    #   end
    #
    #   rule(:bookings).validate(
    #     non_overlapping_intervals: {
    #       group_key: :room_id, start_key: :starts_on, end_key: :ends_on,
    #       endpoints: "[)"
    #     }
    #   )
    #
    # Endpoint presets are `"[]"` (default), `"[)"`, `"(]"`, `"()"`, or the
    # aliases `:closed`, `:closed_open` and `:open`; individual sides can be
    # overridden with `left_open:`/`right_open:`. Two intervals that meet at a
    # single point overlap only when the earlier interval's finish side and
    # the later interval's start side are both closed. Empty intervals
    # (inverted ranges, or a zero-width interval with an open endpoint) are
    # skipped, as are records whose grouping or endpoint fields failed schema
    # checks.
    #
    # Failures are attached to both records participating in every detected
    # conflict, located by their original array index. Detection uses a sorted
    # sweep and performs O(n log n) comparisons per resource group rather than
    # comparing every pair of records.
    #
    # @see Macros::NonOverlappingIntervals
    #
    # @api public
    Macros.register(:non_overlapping_intervals) do |macro:|
      options = macro.args[0]
      detector = Macros::NonOverlappingIntervals.new(**options)
      root = key_name

      records = values[root]

      if records.is_a?(::Array) && !result.schema_error?(::Dry::Schema::Path[root].to_a)
        path_prefix = ::Dry::Schema::Path[root].to_a

        detector
          .call(records, ->(path) { result.schema_error?(path) }, path_prefix)
          .each do |indices|
            indices.each do |index|
              key([*path_prefix, index]).failure(detector.message)
            end
          end
      end
    end
  end
end
