# frozen_string_literal: true

module Dry
  module System
    # Represents a single provider lifecycle action observed while a container is
    # preparing, starting, stopping or shutting down.
    #
    # Events are collected in {ProviderRegistrar#events} and preserve the complete
    # order in which the actions happened, including actions skipped because a
    # provider had already run the step (e.g. starting an already started provider or
    # shutting down a container a second time).
    #
    # @api public
    # @since 1.3.0
    LifecycleEvent = Struct.new(:action, :provider, :status, :error, keyword_init: true) do
      # @return [Boolean]
      #
      # @api public
      def run?
        status == :run
      end

      # @return [Boolean]
      #
      # @api public
      def skipped?
        status == :skipped
      end

      # @return [Boolean]
      #
      # @api public
      def failed?
        status == :failed
      end

      # @api private
      def to_s
        label = provider ? "#{action} #{provider}" : action.to_s
        suffix = error ? " (#{error.class}: #{error.message})" : ""
        "[#{status}] #{label}#{suffix}"
      end

      # @api private
      alias_method :inspect, :to_s
    end
  end
end
