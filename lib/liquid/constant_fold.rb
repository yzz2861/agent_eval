# frozen_string_literal: true

module Liquid
  # Compile-time constant folding of filter expressions made up entirely of
  # literals (e.g. <tt>{{ "hi" | upcase | append: "!" }}</tt>).
  #
  # Only filters explicitly declared pure (see Liquid::PureFilters) and
  # registered on the parsing Environment's strainer are folded. Any unknown
  # filter, dynamic argument, or failure while evaluating the fold forces the
  # expression back onto its normal runtime path so observable behavior is
  # preserved.
  #
  # The folded result is bound to the parsing environment and to the filter
  # registry version captured at parse time. It is only reused by renders that
  # use the same environment, the same base strainer class (so context-local
  # filters can't change the result), and an unchanged registry.
  module ConstantFold
    class << self
      # Attempts to fold a parsed variable. Returns nil when the expression
      # cannot be safely folded; callers then keep the regular runtime path.
      #
      # @param name [Object] parsed leading expression
      # @param filters [Array] parsed filter tuples
      # @param environment [Liquid::Environment] parsing environment
      # @return [Hash, nil] fold descriptor or nil
      def fold(name, filters, environment)
        return nil if filters.nil? || filters.empty?
        return nil unless literal?(name)

        strainer_template = environment.strainer_template

        result = name
        filters.each do |filter_name, filter_args, filter_kwargs|
          return nil unless strainer_template.pure_filter?(filter_name)
          return nil unless filter_args.all? { |arg| literal?(arg) }
          return nil if filter_kwargs && filter_kwargs.values.any? { |arg| !literal?(arg) }

          args = filter_kwargs ? filter_args + [filter_kwargs] : filter_args

          begin
            result = strainer_template.new(nil).invoke(filter_name, result, *args)
          rescue ::StandardError
            # A failing fold (e.g. a wrong arity or a raised error) must behave
            # exactly like the runtime expression, so defer it to render time.
            return nil
          end

          # Context#invoke applies #to_liquid after every filter; mirror that
          # so chained filters observe identical intermediate values.
          result = result.to_liquid
        end

        {
          value: result,
          environment: environment,
          strainer_template: strainer_template,
          registry_version: strainer_template.filter_registry_version,
        }
      end

      # Whether a fold captured at parse time is still safe to reuse for a
      # given render context.
      #
      # @param fold [Hash] fold descriptor
      # @param context [Liquid::Context] render context
      # @return [Boolean]
      def reusable?(fold, context)
        return false unless fold
        return false unless fold[:environment].equal?(context.environment)
        return false if context.custom_filters?

        environment_strainer = context.environment.strainer_template
        return false unless environment_strainer.equal?(fold[:strainer_template])
        environment_strainer.filter_registry_version == fold[:registry_version]
      end

      private

      # Literal AST nodes are plain values without an #evaluate method. Anything
      # that needs a context (VariableLookup, RangeLookup) prevents folding.
      def literal?(expression)
        case expression
        when Array
          expression.all? { |item| literal?(item) }
        when Hash
          expression.values.all? { |item| literal?(item) }
        else
          !expression.respond_to?(:evaluate)
        end
      end
    end
  end
end
