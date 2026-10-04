# frozen_string_literal: true

require 'set'
require_relative 'pure_filters'

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
      def add_filter(filter)
        return if include?(filter)

        invokable_non_public_methods = (filter.private_instance_methods + filter.protected_instance_methods).select { |m| invokable?(m) }
        if invokable_non_public_methods.any?
          raise MethodOverrideError, "Filter overrides registered public methods as non public: #{invokable_non_public_methods.join(', ')}"
        end

        # Only methods whose implementation actually changes as a result of
        # including this filter affect purity. Methods inherited by the filter
        # module from one of its own ancestors are not overrides.
        public_methods = filter.public_instance_methods.map(&:to_s)
        previous_owners = public_methods.to_h { |m| [m, method_owner(m)] }

        include(filter)

        filter_methods.merge(public_methods)

        # A method newly provided (or overridden) by this module is only pure
        # when the module explicitly declares it as such. Overriding a pure
        # filter with a non-declared implementation therefore drops it from the
        # pure set, and bumping the version invalidates any results that were
        # folded against the previous implementation.
        changed_methods = public_methods.select { |m| method_owner(m) != previous_owners[m] }
        changed_methods.each do |m|
          if filter.respond_to?(:pure_filter_declared?) && filter.pure_filter_declared?(m)
            pure_filter_methods.add(m)
          else
            pure_filter_methods.delete(m)
          end
        end

        bump_filter_registry_version
      end

      def invokable?(method)
        filter_methods.include?(method.to_s)
      end

      # Returns whether a filter was explicitly declared pure and is safe to
      # evaluate without a render-time context.
      def pure_filter?(method)
        pure_filter_methods.include?(method.to_s)
      end

      # Monotonically increasing value that changes whenever the set or purity
      # of registered filters changes. Folded constants captured against one
      # version must not be reused after the registry changes.
      def filter_registry_version
        @filter_registry_version ||= 0
      end

      def inherited(subclass)
        super
        subclass.instance_variable_set(:@filter_methods, @filter_methods.dup)
        subclass.instance_variable_set(:@pure_filter_methods, pure_filter_methods.dup)
        subclass.instance_variable_set(:@filter_registry_version, @filter_registry_version || 0)
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

      def bump_filter_registry_version
        @filter_registry_version = filter_registry_version + 1
      end

      def method_owner(method_name)
        instance_method(method_name).owner
      rescue NameError
        nil
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
