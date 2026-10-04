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
      def add_filter(filter)
        return if include?(filter)

        invokable_non_public_methods = (filter.private_instance_methods + filter.protected_instance_methods).select { |m| invokable?(m) }
        if invokable_non_public_methods.any?
          raise MethodOverrideError, "Filter overrides registered public methods as non public: #{invokable_non_public_methods.join(', ')}"
        end

        include(filter)

        filter_methods.merge(filter.public_instance_methods.map(&:to_s))

        if filter.respond_to?(:output_guarantee_declarations)
          filter_guarantees.merge!(filter.output_guarantee_declarations)
        end
      end

      def invokable?(method)
        filter_methods.include?(method.to_s)
      end

      # Returns the output-safety declaration for a filter method:
      # [:produce, context], [:preserve, contexts], or nil when the filter
      # declared nothing and its result must not carry any safety marker.
      def guarantee_for(method)
        filter_guarantees[method.to_s]
      end

      def inherited(subclass)
        super
        subclass.instance_variable_set(:@filter_methods, @filter_methods.dup)
        subclass.instance_variable_set(:@filter_guarantees, filter_guarantees.dup)
      end

      def filter_method_names
        filter_methods.map(&:to_s).to_a
      end

      private

      def filter_methods
        @filter_methods ||= Set.new
      end

      def filter_guarantees
        @filter_guarantees ||= {}
      end
    end

    def invoke(method, *args)
      if self.class.invokable?(method)
        invoke_with_output_guarantees(method, args)
      elsif @context.strict_filters
        raise Liquid::UndefinedFilter, "undefined filter #{method}"
      else
        args.first
      end
    rescue ::ArgumentError => e
      raise Liquid::ArgumentError, e.message, e.backtrace
    end

    private

    def invoke_with_output_guarantees(method, args)
      return send(method, *args) unless @context&.output_mode

      input_guarantee = args.first.is_a?(SafeValue) ? args.first.guarantee : nil
      args.each_with_index do |arg, index|
        args[index] = arg.to_s if arg.is_a?(SafeValue)
      end
      result = send(method, *args)

      case (declaration = self.class.guarantee_for(method))&.first
      when :produce
        result.is_a?(String) ? SafeValue.new(result, declaration.last) : result
      when :preserve
        if input_guarantee && declaration.last.include?(input_guarantee) && result.is_a?(String)
          SafeValue.new(result, input_guarantee)
        else
          result
        end
      else
        result
      end
    end
  end
end
