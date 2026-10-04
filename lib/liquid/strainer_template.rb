# frozen_string_literal: true

require 'set'

module Liquid
  # StrainerTemplate is the computed class for the filters system.
  # New filters are mixed into the strainer class which is then instantiated for each liquid template render run.
  #
  # The Strainer only allows method calls defined in filters given to it via StrainerFactory.add_global_filter,
  # Context#add_filters or Template.register_filter
  class StrainerTemplate
    def initialize(context)
      @context = context
    end

    class << self
      # Adds a filter module to this strainer.
      #
      # When +pure+ is true, all public methods of the module are declared as
      # pure filters: they must not depend on the render context and must not
      # have side effects. Only pure filters are eligible for compile-time
      # constant folding of literal filter expressions.
      def add_filter(filter, pure: false)
        unless include?(filter)
          invokable_non_public_methods = (filter.private_instance_methods + filter.protected_instance_methods).select { |m| invokable?(m) }
          if invokable_non_public_methods.any?
            raise MethodOverrideError, "Filter overrides registered public methods as non public: #{invokable_non_public_methods.join(', ')}"
          end

          include(filter)

          filter_methods.merge(filter.public_instance_methods.map(&:to_s))
        end

        if pure
          pure_filter_methods.merge(filter.public_instance_methods.map(&:to_s))
        end

        @filter_version = filter_version + 1
      end

      def invokable?(method)
        filter_methods.include?(method.to_s)
      end

      # Whether the given filter was explicitly declared as pure, meaning it
      # does not depend on the render context and has no side effects.
      def pure_filter?(method)
        pure_filter_methods.include?(method.to_s)
      end

      # Monotonic counter bumped every time the filter registry of this
      # strainer changes. Used to invalidate cached constant-folded filter
      # results so they are never reused across an incompatible registry.
      def filter_version
        @filter_version ||= 0
      end

      def inherited(subclass)
        super
        subclass.instance_variable_set(:@filter_methods, @filter_methods.dup)
        subclass.instance_variable_set(:@pure_filter_methods, @pure_filter_methods.dup)
      end

      def filter_method_names
        filter_methods.map(&:to_s).to_a
      end

      private

      def filter_methods
        @filter_methods ||= Set.new
      end

      def pure_filter_methods
        @pure_filter_methods ||= Set.new
      end
    end

    def invoke(method, *args)
      if self.class.invokable?(method)
        send(method, *args)
      elsif @context.strict_filters
        raise Liquid::UndefinedFilter, "undefined filter #{method}"
      else
        args.first
      end
    rescue ::ArgumentError => e
      raise Liquid::ArgumentError, e.message, e.backtrace
    end
  end
end
