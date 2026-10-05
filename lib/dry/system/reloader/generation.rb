# frozen_string_literal: true

require "set"
require "monitor"

require "dry/core/constants"

module Dry
  module System
    class Reloader
      # A single, immutable generation of the application's component graph.
      #
      # A generation owns, exclusively:
      #
      # - a registry of its resolved components, and
      # - the provider instances it started.
      #
      # Components are always resolved through their own generation, and providers
      # always register into it. This means an object can never mix dependencies from
      # two generations: every object built in a generation only ever receives other
      # objects from that same generation.
      #
      # A generation is kept alive for as long as at least one {GenerationScope} is
      # open against it. Once a generation has been superseded and its final scope
      # closes, it is released: each provider it owns is stopped exactly once.
      #
      # @api public
      # @since 1.3.0
      class Generation
        include Dry::Core::Constants

        # @return [Integer] the monotonically increasing generation number
        #
        # @api public
        attr_reader :number

        # @return [Integer]
        #
        # @api public
        alias_method :generation_number, :number

        # Records, for each built component key, the set of keys that were resolved
        # while that component was being built. This captures the component's
        # dependencies without requiring them to be declared statically.
        #
        # @return [Hash{String => Set<String>}]
        #
        # @api private
        attr_reader :component_dependencies

        # Serializes a generation's own registry and provider mutations, including the
        # lazy component builds performed by in-flight scopes while a reload reads this
        # generation.
        #
        # @return [Monitor]
        #
        # @api private
        attr_reader :mutex

        # Builds the sentinel component key installed in the build stack while a
        # provider runs its lifecycle, so dependencies the provider resolves are
        # attributed to that provider (and not to an enclosing component build).
        def self.provider_sentinel(name)
          "\0provider:#{name}"
        end

        # Inverse of {.provider_sentinel}: returns the provider name encoded in an edge
        # owner, or nil when the owner is an ordinary component key.
        #
        # @return [Symbol, nil]
        #
        # @api private
        def self.provider_from_sentinel(owner)
          return unless owner.start_with?("\0provider:")
          owner.delete_prefix("\0provider:").to_sym
        end

        # @api private
        def initialize(number:, builder:, registry: nil, providers: nil,
                       component_dependencies: nil)
          @number = number
          @builder = builder

          @registry = registry || {}
          @providers = providers || {}
          @component_dependencies = component_dependencies || {}

          @build_stack = []

          @mutex = ::Monitor.new
          @references = 0
          @retired = false
          @released = false
          @on_release = []
        end

        # @return [Boolean]
        #
        # @api public
        def released?
          @mutex.synchronize { @released }
        end

        # @param key [String, Symbol]
        #
        # @return [Boolean]
        #
        # @api public
        def registered?(key)
          @mutex.synchronize { @registry.key?(key.to_s) }
        end

        # Resolves a component from this generation, building it on first use.
        #
        # Dependencies resolved while the component (or a provider it starts) is being
        # built are recorded to support precise partial rebuilds on reload.
        #
        # @param key [String, Symbol]
        #
        # @return [Object]
        #
        # @api public
        def resolve(key)
          key = key.to_s
          @mutex.synchronize do
            item = @registry[key]
            unless item
              record_edge!(key)
              build(key)
              item = @registry.fetch(key)
            end

            item.call
          end
        end

        alias_method :[], :resolve

        # Registers a component directly into this generation. This is the entry point
        # used by providers (as their `target_container`) and by component build blocks
        # that register more than a single object.
        #
        # @param key [String, Symbol]
        # @param contents [Object, nil]
        # @param options [Hash]
        #
        # @return [self]
        #
        # @api public
        def register(key, contents = nil, options = EMPTY_HASH, &block)
          if block
            item = block
            options = contents if contents.is_a?(::Hash)
          else
            item = contents
          end

          @mutex.synchronize do
            item = Dry::Core::Container::Item::Factory.new.call(item, options)
            @registry[key.to_s] = item
            self
          end
        end

        # Starts the named provider, building a fresh provider instance scoped to this
        # generation. Providers are never shared between generations.
        #
        # @return [Provider]
        #
        # @api private
        def start_provider(name)
          name = name.to_sym
          @mutex.synchronize do
            provider = @providers[name] and next provider

            @build_stack.push(self.class.provider_sentinel(name))
            begin
              provider = @builder.build_provider(self, name)
              @providers[name] = provider
              provider.start
            ensure
              @build_stack.pop
            end

            @builder.notify_provider_started(provider)
            provider
          end
        end

        # @return [Array(Hash, Array)] the dependency-edge records and a snapshot of
        # started providers, both read atomically
        #
        # @api private
        def reload_snapshot
          @mutex.synchronize do
            [deep_dup_dependencies(@component_dependencies), @providers.values]
          end
        end

        # Removes the given providers from this generation. Used when the providers are
        # carried into a successor generation and their ownership moves there; this
        # generation must not stop them when it is released.
        #
        # @return [void]
        #
        # @api private
        def remove_providers!(providers)
          @mutex.synchronize do
            providers.each { |provider| @providers.delete(provider.name) }
            nil
          end
        end

        # @return [Array<Provider>] the providers this generation currently owns
        #
        # @api private
        def owned_providers
          @mutex.synchronize { @providers.values }
        end

        # Builds the next generation, reusing every component and provider unaffected by
        # the reload. Affected components are rebuilt (along with their providers) using
        # the given builder, which provides the fresh source definitions.
        #
        # @param number [Integer]
        # @param builder [Object]
        # @param affected_keys [Set<String>]
        # @param affected_provider_names [Array<Symbol>]
        #
        # @return [Generation]
        #
        # @api private
        def build_successor(number, builder, affected_keys, affected_provider_names)
          # Only carry components that are both resolved in this generation and
          # unaffected by the reload. Anything never resolved here is simply absent from
          # the successor and is built entirely there on first use: this guarantees a
          # lazily-loaded component can never keep an old definition while silently
          # pulling a rebuilt dependency (which would mix two generations).
          carried_registry, carried_dependencies, carried_providers, affected_resolved_keys =
            @mutex.synchronize { successor_snapshot(affected_keys, affected_provider_names) }

          successor = self.class.new(
            number: number,
            builder: builder,
            registry: carried_registry,
            providers: carried_providers,
            component_dependencies: carried_dependencies
          )

          begin
            # Affected providers start first so rebuilt components observe them, then
            # every affected component previously resolved here is rebuilt. Any failure
            # surfaces the partially built successor to the caller, which discards it
            # and keeps this generation running.
            affected_provider_names.each { |name| successor.start_provider(name) }

            affected_resolved_keys.each do |key|
              successor.resolve(key)
            end
          rescue StandardError => error
            raise Reloader::SuccessorBuildError.new(successor, error)
          end

          successor
        end

        # Registers a callback fired exactly once when this generation is released.
        #
        # @return [void]
        #
        # @api private
        def on_release(&block)
          fire_now = @mutex.synchronize do
            if @released
              true
            else
              @on_release << block
              false
            end
          end

          block.call if fire_now
          nil
        end

        # @return [void]
        #
        # @api private
        def retain!
          @mutex.synchronize do
            raise GenerationReleasedError, @number if @released
            @references += 1
          end
          nil
        end

        # Closes one scope referencing this generation. A retired generation with no
        # remaining scopes is released and its providers are stopped.
        #
        # @return [void]
        #
        # @api private
        def release!
          callbacks = @mutex.synchronize do
            @references -= 1
            return nil unless @references.zero? && @retired
            @released = true
            @on_release.dup
          end

          callbacks.each(&:call)
          nil
        end

        # Marks the generation as superseded. Releases it immediately if no scopes are
        # open; otherwise it is released when the final scope closes.
        #
        # @return [void]
        #
        # @api private
        def retire!
          callbacks = @mutex.synchronize do
            @retired = true
            return nil unless @references.zero?
            @released = true
            @on_release.dup
          end

          callbacks.each(&:call)
          nil
        end

        private

        # @return [Array(Hash, Hash, Hash, Array<String>)]
        #
        # @api private
        def successor_snapshot(affected_keys, affected_provider_names)
          carried_keys = @registry.keys - affected_keys.to_a
          carried_registry = @registry.slice(*carried_keys)
          carried_dependencies = deep_dup_dependencies(@component_dependencies)
          carried_providers = @providers.reject { |name, _|
            affected_provider_names.include?(name)
          }
          affected_resolved_keys = @registry.keys & affected_keys.to_a

          [carried_registry, carried_dependencies, carried_providers, affected_resolved_keys]
        end

        def deep_dup_dependencies(dependencies)
          dependencies.transform_values { |deps| deps.dup }
        end

        # Records an edge from the component (or provider) currently being built to the
        # given resolved/registered key.
        def record_edge!(key)
          owner = @build_stack.last
          return unless owner && owner != key

          (@component_dependencies[owner] ||= Set.new) << key
        end

        def build(key)
          @build_stack.push(key)
          begin
            @builder.call(self, key)
          ensure
            @build_stack.pop
          end
        end
      end
    end
  end
end
