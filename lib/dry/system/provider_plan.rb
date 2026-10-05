# frozen_string_literal: true

require "dry/system/errors"

module Dry
  module System
    # A ProviderPlan is an inspectable, ordered sequence of providers computed from
    # their declared +depends_on+ dependencies.
    #
    # Plans are built by {ProviderRegistrar#plan} before any lifecycle step runs, so
    # that dependency problems (missing providers, dependency cycles) are raised
    # before any side effects occur. The ordered providers can be inspected via
    # {#providers} and {#names}.
    #
    # Running the plan executes the providers' lifecycle steps in dependency order
    # ({#prepare}, {#start}) or reverse dependency order ({#shutdown}). Every
    # executed step is appended to {#events} as a +[step, provider_name]+ tuple,
    # giving a complete record of the execution order, including repeated runs.
    #
    # @example
    #   plan = MyApp.providers.plan(:persistence)
    #   plan.names # => [:settings, :logger, :persistence]
    #
    #   plan.start
    #   plan.events # => [[:start, :settings], [:start, :logger], [:start, :persistence]]
    #
    # @see ProviderRegistrar#plan
    #
    # @api public
    class ProviderPlan
      # Returns the plan's providers, ordered so that every provider appears after
      # the providers it depends on.
      #
      # @return [Array<Dry::System::Provider>]
      #
      # @api public
      attr_reader :providers

      # Returns the lifecycle steps executed by the plan, in order.
      #
      # Each event is a +[step, provider_name]+ tuple, e.g. +[:start, :persistence]+.
      # Events are appended every time the plan runs a step, so repeated {#start}
      # and {#shutdown} calls are all recorded.
      #
      # @return [Array<Array(Symbol, Symbol)>]
      #
      # @api public
      attr_reader :events

      # @api private
      def initialize(providers)
        @providers = providers
        @events = []
      end

      # Returns the names of the plan's providers, in dependency order.
      #
      # @return [Array<Symbol>]
      #
      # @api public
      def names
        providers.map(&:name)
      end

      # @api private
      def inspect
        "#<#{self.class.name} providers=#{names.inspect}>"
      end

      # Runs the +prepare+ lifecycle step for each provider, in dependency order.
      #
      # @return [self]
      #
      # @api public
      def prepare
        providers.each do |provider|
          record(:prepare, provider)
          provider.prepare
        end

        self
      end

      # Runs the +start+ lifecycle step for each provider, in dependency order.
      #
      # If a provider fails to start, the providers that were newly started by this
      # run (and only those) are stopped again, in reverse order, before the
      # original error is re-raised. Providers that were already started before
      # this run are left running. If any of these rollback stops also fail, a
      # {ProviderStopError} aggregating those errors is raised instead, with the
      # original start error as its +cause+.
      #
      # @return [self]
      #
      # @api public
      def start
        started = []

        begin
          providers.each do |provider|
            already_started = provider.started?

            record(:start, provider)
            provider.start

            started << provider unless already_started
          end
        rescue StandardError
          rollback(started)
          raise
        end

        self
      end

      # Runs the +stop+ lifecycle step for each provider, in reverse dependency
      # order.
      #
      # All providers are given the chance to stop, even if some fail. If any
      # provider fails to stop, a {ProviderStopError} aggregating all the errors
      # is raised after the remaining providers have been stopped.
      #
      # @return [self]
      #
      # @api public
      def shutdown
        errors = stop_each(providers.reverse)

        raise ProviderStopError, errors if errors.any?

        self
      end

      private

      # @api private
      def record(step, provider)
        events << [step, provider.name]
      end

      # Stops the providers started by the current {#start} run, in reverse order.
      #
      # @api private
      def rollback(started)
        errors = stop_each(started.reverse)

        raise ProviderStopError, errors if errors.any?
      end

      # Stops each of the given providers, recording events and collecting any
      # errors instead of raising them immediately.
      #
      # @return [Hash{Symbol => StandardError}] stop errors keyed by provider name
      #
      # @api private
      def stop_each(to_stop)
        to_stop.each_with_object({}) do |provider, errors|
          record(:stop, provider)

          begin
            provider.stop
          rescue StandardError => e
            errors[provider.name] = e
          end
        end
      end
    end
  end
end
