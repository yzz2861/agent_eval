# frozen_string_literal: true

require 'set'

module Liquid
  # Explicit declaration that a filter module's methods are pure.
  #
  # A pure filter must not depend on render-time context and must not have side
  # effects: given the same arguments it must always produce the same result, and
  # it must not mutate its arguments or global state. Only explicitly declared
  # pure filters are eligible for compile-time constant folding of filter
  # expressions that are composed entirely of literals.
  #
  # Filter modules opt in by extending this module and calling +pure_filter+ for
  # every method that meets the contract:
  #
  #   module MyFilters
  #     extend Liquid::PureFilters
  #
  #     def shout(input)
  #       input.to_s.upcase
  #     end
  #     pure_filter :shout
  #   end
  module PureFilters
    DECLARED_METHODS_KEY = :@__liquid_pure_filter_methods__
    private_constant :DECLARED_METHODS_KEY

    # Declares one or more filter methods as pure.
    #
    # @param method_names [Array<Symbol, String>] names of pure filter methods
    # @return [void]
    def pure_filter(*method_names)
      methods = declared_pure_filter_methods
      method_names.each { |name| methods << name.to_s }
      nil
    end

    # @return [Array<String>] names of filters declared pure on this module
    def pure_filter_methods
      declared_pure_filter_methods.to_a
    end

    # @param name [Symbol, String] filter method name
    # @return [Boolean] whether the filter was explicitly declared pure
    def pure_filter_declared?(name)
      declared_pure_filter_methods.include?(name.to_s)
    end

    private

    def declared_pure_filter_methods
      # Only methods declared directly on this module count. Declarations on an
      # ancestor module are surfaced through #pure_filter_methods instead.
      if instance_variable_defined?(DECLARED_METHODS_KEY)
        instance_variable_get(DECLARED_METHODS_KEY)
      else
        instance_variable_set(DECLARED_METHODS_KEY, Set.new)
      end
    end
  end
end
