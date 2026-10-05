# frozen_string_literal: true

require "pathname"

require "dry/system/errors"
require "dry/system/constants"

module Dry
  module System
    # Default provider registrar implementation
    #
    # This is currently configured by default for every Dry::System::Container. The
    # provider registrar is responsible for loading provider files and exposing an API for
    # running the provider lifecycle steps.
    #
    # @api public
    # @since 1.1.0
    class ProviderRegistrar
      # @api private
      attr_reader :providers

      # @api private
      attr_reader :container

      # Returns the container exposed to providers as `target_container`.
      #
      # @return [Dry::System::Container]
      #
      # @api public
      # @since 1.1.0
      alias_method :target_container, :container

      # @api private
      def initialize(container)
        @providers = {}
        @container = container
        @loaded = Set.new
        @events = []
      end

      # @api private
      def freeze
        providers.freeze
        super
      end

      # Returns the lifecycle events collected across all prepare, start, stop and
      # shutdown operations, in execution order.
      #
      # The array is never cleared: it records repeated starts and repeated
      # shutdowns too. Inspect events with {LifecycleEvent#action}, {#provider} and
      # {LifecycleEvent#status}.
      #
      # @return [Array<Dry::System::LifecycleEvent>]
      #
      # @api public
      # @since 1.3.0
      attr_reader :events

      # Returns a side-effect free plan describing the provider (and its transitive
      # dependencies) and the order in which their steps will run.
      #
      # Use this to inspect the startup/shutdown order before triggering any side
      # effects.
      #
      # @param provider_names [Array<Symbol>] one or more registered provider names;
      #   pass no names (or nil) to plan all discoverable providers
      #
      # @return [Dry::System::Provider::Plan]
      #
      # @raise [ProviderNotFoundError] if a named provider is not registered
      # @raise [ProviderDependencyNotFoundError] if a dependency is not registered
      # @raise [ProviderDependencyCycleError] if the dependencies form a cycle
      #
      # @api public
      # @since 1.3.0
      def plan(*provider_names)
        names = provider_names.flatten.compact

        if names.empty?
          provider_files.each { |path| load_provider(path) }
          names = providers.keys
        end

        Provider::Plan.build(names, self)
      end

      # @see Container.register_provider
      # @api private
      def register_provider(name, from: nil, source: nil, depends_on: nil, if: true,
                            **provider_options, &)
        raise ProviderAlreadyRegisteredError, name if providers.key?(name)

        if from && source.is_a?(Class)
          raise ArgumentError, "You must supply a block when using a provider source"
        end

        if block_given? && source.is_a?(Class)
          raise ArgumentError, "You must supply only a `source:` option or a block, not both"
        end

        return self unless binding.local_variable_get(:if)

        provider =
          if from
            build_provider_from_source(
              name,
              source: source || name,
              group: from,
              options: provider_options,
              depends_on: depends_on,
              &
            )
          else
            build_provider(
              name,
              source: source,
              options: provider_options,
              depends_on: depends_on,
              &
            )
          end

        providers[provider.name] = provider

        self
      end

      # Returns a provider if it can be found or loaded, otherwise nil
      #
      # @return [Dry::System::Provider, nil]
      #
      # @api public
      def [](provider_name)
        provider_name = provider_name.to_sym

        if (provider = providers[provider_name])
          return provider
        end

        return if finalized?

        require_provider_file(provider_name)

        providers[provider_name]
      end

      # @api public
      alias_method :find_and_load_provider, :[]

      # @api private
      def key?(provider_name)
        providers.key?(provider_name)
      end

      # Returns all provider files within the configured provider_paths.
      #
      # Searches for files in the order of the configured provider_paths. In the case of multiple
      # identically-named boot files within different provider_paths, the file found first will be
      # returned, and other matching files will be discarded.
      #
      # This method is public to allow other tools extending dry-system (like dry-rails)
      # to access a canonical list of real, in-use provider files.
      #
      # @see Container.provider_paths
      #
      # @return [Array<Pathname>]
      # @api public
      def provider_files
        @provider_files ||= provider_paths.each_with_object([[], []]) { |path, (provider_files, loaded)|
          files = ::Dir["#{path}/#{RB_GLOB}"]

          files.each do |file|
            basename = ::File.basename(file)

            unless loaded.include?(basename)
              provider_files << Pathname(file)
              loaded << basename
            end
          end
        }.first
      end

      # Extension point for subclasses to customize their
      # provider source superclass. Expected to be a subclass
      # of Dry::System::Provider::Source
      #
      # @api public
      # @since 1.1.0
      def provider_source_class = Dry::System::Provider::Source

      # Extension point for subclasses to customize initialization
      # params for provider_source_class
      #
      # @api public
      # @since 1.1.0
      def provider_source_options = {}

      # @api private
      def finalize!
        provider_files.each do |path|
          load_provider(path)
        end

        run_plan(providers.keys) unless providers.empty?

        freeze
      end

      # @!method finalized?
      #   Returns true if the booter has been finalized
      #
      #   @return [Boolean]
      #   @api private
      alias_method :finalized?, :frozen?

      # @api private
      def shutdown
        record(:shutdown) do
          order = shutdown_order
          failures = stop_each(order)

          raise ProviderStopError.new(failures) if failures.any?
        end
        self
      end

      # @api private
      def prepare(provider_name)
        lifecycle_plan = plan(provider_name)

        lifecycle_plan.start_order.each do |name|
          advance(providers.fetch(name), :prepare)
        end
        self
      end

      # @api private
      def start(provider_name)
        run_plan(provider_name)
        self
      end

      # @api private
      def stop(provider_name)
        with_provider(provider_name) do |provider|
          stop_one(provider, raise_on_failure: true)
        end
        self
      end

      private

      # @api private
      def provider_paths
        provider_dirs = container.config.provider_dirs

        provider_dirs.map { |dir|
          dir = Pathname(dir)

          if dir.relative?
            container.root.join(dir)
          else
            dir
          end
        }
      end

      def build_provider(name, options:, source: nil, depends_on: nil, &)
        source_class = source || Provider::Source.for(
          name: name,
          superclass: provider_source_class,
          &
        )

        source_options =
          if source_class < provider_source_class
            provider_source_options
          else
            {}
          end

        Provider.new(
          **options,
          name: name,
          target_container: target_container,
          source_class: source_class,
          source_options: source_options,
          depends_on: depends_on
        )
      end

      def build_provider_from_source(name, source:, group:, options:, depends_on: nil, &)
        provider_source = System.provider_sources.resolve(name: source, group: group)

        source_options =
          if provider_source.source <= provider_source_class
            provider_source_options
          else
            {}
          end

        Provider.new(
          **provider_source.provider_options,
          **options,
          name: name,
          target_container: target_container,
          source_class: provider_source.source,
          source_options: source_options,
          depends_on: depends_on,
          &
        )
      end

      # Runs a plan for the given provider name(s): builds the plan (detecting
      # missing providers and cycles before any side effects), then prepares and
      # starts the providers in dependency order. If a step fails, only the
      # providers that this invocation actually started are stopped, in reverse
      # order; providers that were already running remain untouched.
      #
      # @return [Provider::Plan]
      #
      # @api private
      def run_plan(*provider_names)
        started_this_round = []
        lifecycle_plan = plan(*provider_names)

        lifecycle_plan.start_order.each do |name|
          provider = providers.fetch(name)

          advance(provider, :prepare)

          if advance(provider, :start) == :run
            started_this_round << provider
          end
        end

        lifecycle_plan
      rescue StandardError
        rollback(started_this_round)
        raise
      end

      # Stops exactly the providers started during the failed round, in reverse
      # order. Stop failures never prevent other providers from being stopped and
      # are recorded as events; the original start failure is re-raised by the
      # caller.
      #
      # @api private
      def rollback(providers_to_stop)
        events << LifecycleEvent.new(action: :rollback, status: :run)
        providers_to_stop.reverse_each do |provider|
          stop_one(provider, action: :rollback)
        end
      end

      # Runs a single lifecycle step on a provider and records the corresponding
      # event, including a failure event when the step raises.
      #
      # @return [Symbol] :run or :skipped
      #
      # @api private
      def advance(provider, action)
        already =
          case action
          when :prepare then provider.prepared?
          when :start then provider.started?
          when :stop then !provider.started? || provider.stopped?
          else false
          end

        if already
          record_step(provider, action, :skipped)
          return :skipped
        end

        begin
          provider.public_send(action)
          record_step(provider, action, :run)
          :run
        rescue StandardError => error
          record_step(provider, action, :failed, error)
          raise
        end
      end

      # Stops one provider and records the event (as either a `:stop` or a
      # `:rollback` action). Failed stops are collected and returned so callers can
      # continue stopping the remaining providers.
      #
      # @return [Hash{Symbol => Exception}]
      #
      # @api private
      def stop_one(provider, action: :stop, raise_on_failure: false)
        unless provider.started? && !provider.stopped?
          record_step(provider, action, :skipped)
          return {}
        end

        begin
          provider.stop
          record_step(provider, action, :run)
          {}
        rescue StandardError => error
          record_step(provider, action, :failed, error)
          raise if raise_on_failure
          {provider.name => error}
        end
      end

      # Stops the given providers in order, continuing after failures.
      #
      # @return [Hash{Symbol => Exception}]
      #
      # @api private
      def stop_each(names)
        names.each_with_object({}) do |name, failures|
          provider = providers[name]
          next unless provider

          failures.merge!(stop_one(provider))
        end
      end

      # Returns the names of all loaded providers in reverse dependency order,
      # suitable for shutdown. Providers that were never started (or are already
      # stopped) remain in the sequence so that repeated shutdowns still emit their
      # skipped events. Missing dependencies or cycles do not prevent shutdown.
      #
      # @return [Array<Symbol>]
      #
      # @api private
      def shutdown_order
        started = providers.keys

        ordered = []
        states = {}

        visit = lambda { |name|
          case states[name]
          when :done, :visiting
            next
          end

          states[name] = :visiting

          provider = providers[name]
          provider.depends_on.each do |dep_name|
            visit.call(dep_name) if started.include?(dep_name)
          end

          states[name] = :done
          ordered << name
        }

        started.each { |name| visit.call(name) }

        ordered.reverse
      end

      # @api private
      def record_step(provider, action, status, error = nil)
        events << LifecycleEvent.new(
          action: action, provider: provider.name, status: status, error: error
        )
      end

      # @api private
      def record(action)
        yield
        events << LifecycleEvent.new(action: action, provider: nil, status: :run)
      rescue StandardError => error
        events << LifecycleEvent.new(
          action: action, provider: nil, status: :failed, error: error
        )
        raise
      end

      def with_provider(provider_name)
        require_provider_file(provider_name) unless providers.key?(provider_name)

        provider = providers[provider_name]

        raise ProviderNotFoundError, provider_name unless provider

        yield(provider)
      end

      def load_provider(path)
        name = Pathname(path).basename(RB_EXT).to_s.to_sym

        load_provider_file(path) unless providers.key?(name)

        self
      end

      def require_provider_file(name)
        provider_file = find_provider_file(name)

        load_provider_file(provider_file) if provider_file
      end

      # Evaluates a provider file, at most once for this registrar.
      #
      # Uses `load` rather than `require` so that a provider file is evaluated once per registrar
      # rather than once per process. Evaluating the file adds its provider to this registrar alone.
      # This allows for a container to be unloaded and reloaded, and its providers to be registered
      # again.
      #
      # Tracks loaded files because `load`, unlike `require`, will evaluate a file more than once.
      # A file registering a provider under some other name would otherwise be evaluated on every
      # lookup of its own name, and raise {ProviderAlreadyRegisteredError} the second time.
      def load_provider_file(path)
        path = path.to_s

        return if @loaded.include?(path)

        @loaded << path

        Kernel.load path
      end

      def find_provider_file(name)
        provider_files.detect { |file| File.basename(file, RB_EXT) == name.to_s }
      end
    end
  end
end
