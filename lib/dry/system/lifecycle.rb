# frozen_string_literal: true

require "dry/system/errors"

module Dry
  module System
    # Represents the lifecycle of a component: how long a single instance of the
    # component is kept alive and reused.
    #
    # Three lifecycles are supported, ordered from the longest to the shortest lived:
    #
    # - {SINGLETON} (+:singleton+) - a single instance shared across the whole
    #   container. Created lazily on first resolution and kept for the lifetime of
    #   the container.
    # - {SCOPED} (+:scoped+) - a single instance shared within a {Scope} (such as a
    #   request). A new instance is created for each scope, and nested scopes share
    #   an instance already created by an ancestor scope.
    # - {TRANSIENT} (+:transient+) - a new instance is created on every resolution;
    #   nothing is retained.
    #
    # A component may only depend on components with an equal or longer lifecycle.
    # Attempting to capture a shorter-lived dependency (a "captive dependency")
    # raises a {CaptiveDependencyError} with the full dependency chain.
    #
    # @api public
    class Lifecycle
      include(Dry::Equalizer(:name))

      # All lifecycle names, ordered from longest to shortest lived
      #
      # @return [Array<Symbol>]
      #
      # @api public
      NAMES = %i[singleton scoped transient].freeze

      # Coerces a symbol or string (or an existing lifecycle) into a lifecycle
      #
      # @param value [Symbol, String, Lifecycle]
      #
      # @raise [InvalidLifecycleError] if the value is not a valid lifecycle name
      #
      # @return [Lifecycle]
      #
      # @api public
      def self.[](value)
        return value if value.is_a?(self)

        REGISTRY.fetch(value.to_s.to_sym) {
          raise InvalidLifecycleError.new(value)
        }
      end

      # @!attribute [r] name
      #   @return [Symbol] the lifecycle name (+:singleton+, +:scoped+, or
      #     +:transient+)
      attr_reader :name

      # @api private
      def initialize(name)
        @name = name
      end

      # Returns the lifetime rank. A lower number lives longer. A component may
      # only depend on dependencies whose rank is less than or equal to its own
      # (i.e. dependencies that live equally long or longer).
      #
      # @return [Integer]
      #
      # @api private
      def rank
        NAMES.index(name)
      end

      # @return [Boolean]
      #
      # @api private
      def singleton? = name.equal?(:singleton)

      # @return [Boolean]
      #
      # @api private
      def scoped? = name.equal?(:scoped)

      # @return [Boolean]
      #
      # @api private
      def transient? = name.equal?(:transient)

      # Whether a component with this lifecycle may safely depend on a component
      # with the +other+ lifecycle: the dependency must live equally long or
      # longer.
      #
      # @return [Boolean]
      #
      # @api private
      def can_depend_on?(other)
        self.class[other].rank <= rank
      end

      # @return [String]
      #
      # @api public
      def to_s
        name.to_s
      end

      # @return [Symbol]
      #
      # @api public
      def to_sym
        name
      end

      # @api private
      REGISTRY = NAMES.each_with_object({}) { |lifecycle_name, hsh|
        hsh[lifecycle_name] = new(lifecycle_name)
      }.freeze

      # A single instance shared across the whole container
      #
      # @return [Lifecycle]
      #
      # @api public
      SINGLETON = REGISTRY.fetch(:singleton)

      # A single instance per scope, shared by nested scopes once created
      #
      # @return [Lifecycle]
      #
      # @api public
      SCOPED = REGISTRY.fetch(:scoped)

      # A new instance on every resolution
      #
      # @return [Lifecycle]
      #
      # @api public
      TRANSIENT = REGISTRY.fetch(:transient)
    end
  end
end
