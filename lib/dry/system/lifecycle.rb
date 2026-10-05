# frozen_string_literal: true

require "dry/system/errors"

module Dry
  module System
    # Component lifecycles determine how long a component's instance lives and
    # which scope is responsible for disposing it.
    #
    # Three lifecycles are supported, ordered from longest- to shortest-lived:
    #
    # - `:singleton` - one instance for the whole lifetime of the container.
    #   This is equivalent to registering with `memoize: true`.
    # - `:scoped` - one instance per active {Scope}. Instances are created on
    #   first resolution within a scope and disposed when that scope ends.
    #   Resolving a scoped component without an active scope raises
    #   {NoActiveScopeError}; see {Container.scoped}.
    # - `:transient` - a new instance on every resolution. This is the default
    #   behavior for components registered with a block.
    #
    # A component may only depend on components with the same or a longer
    # lifecycle: singletons may depend only on singletons, scoped components may
    # depend on singletons and other scoped components, and transient components
    # may depend on anything. Violations are detected while components are being
    # built and raise {CaptiveDependencyError}.
    #
    # @api public
    module Lifecycle
      # A single frame in the chain of components being built during resolution
      #
      # @api private
      Frame = Struct.new(:key, :lifecycle)

      # All supported lifecycles, ordered from longest- to shortest-lived
      #
      # @api public
      VALUES = %i[singleton scoped transient].freeze

      # @api private
      RANKS = {singleton: 2, scoped: 1, transient: 0}.freeze

      class << self
        # Coerces the given value to a lifecycle, raising {InvalidLifecycleError}
        # if it is not a valid lifecycle
        #
        # @api private
        def coerce(value, key: nil)
          lifecycle = value.to_sym
          return lifecycle if VALUES.include?(lifecycle)

          raise InvalidLifecycleError.new(value, key: key)
        rescue NoMethodError
          raise InvalidLifecycleError.new(value, key: key)
        end

        # Returns the rank of the given lifecycle, with higher ranks representing
        # longer-lived components
        #
        # @api private
        def rank(lifecycle)
          RANKS.fetch(lifecycle)
        end

        # Returns the effective lifecycle for an item registered in the container
        #
        # Items registered without an explicit `lifecycle:` option are treated as
        # singletons when they are memoized or registered as pre-built values,
        # and as transient otherwise.
        #
        # @api private
        def effective(item)
          if (lifecycle = item.options[:lifecycle])
            coerce(lifecycle)
          elsif item.options[:memoize]
            :singleton
          elsif item.callable?
            :transient
          else
            :singleton
          end
        end
      end
    end
  end
end
