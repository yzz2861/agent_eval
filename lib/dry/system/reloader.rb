# frozen_string_literal: true

require "monitor"
require "set"

require "dry/system/errors"
require "dry/system/constants"
require "dry/system/provider"
require "dry/system/reloader/builder"
require "dry/system/reloader/generation"
require "dry/system/reloader/generation_scope"

module Dry
  module System
    # Coordinates explicit, generation-scoped reloading of a component graph, intended
    # for development servers.
    #
    # A reloader builds a fresh component graph on every reload while keeping the
    # previous graph available until all work using it has finished:
    #
    # - {#with_generation} (or {#open_generation}) opens a {GenerationScope} pinned to
    #   the generation that is current at that moment. In-flight requests continue to
    #   resolve from their pinned generation even while a reload installs a newer one.
    # - {#reload} rebuilds only the components that changed together with everything
    #   that actually depends on them, as observed at runtime. Components from two
    #   generations are never mixed: rebuilt providers get fresh instances, while their
    #   old instances keep running until the superseded generation's final scope closes.
    # - If the new graph fails to load or start, the reload is discarded and the
    #   previous generation keeps serving.
    #
    # @example
    #   reloader = Dry::System::Reloader.new do
    #     provider :db do
    #       start { register("db", DB.new) }
    #       stop { target["db"].close }
    #     end
    #
    #     component("users.create") { |gen| Users::Create.new(gen["db"]) }
    #   end
    #
    #   reloader.with_generation { |scope| scope["users.create"] } # generation 1
    #   reloader.reload(changed: "db")                          # generation 2
    #
    # @api public
    # @since 1.3.0
    class Reloader
      # Raised internally while building a successor generation so that the partially
      # built generation (and any providers it started) can be cleaned up by the
      # reloader without affecting the previous generation.
      #
      # @api private
      # @since 1.3.0
      class SuccessorBuildError < StandardError
        # @return [Generation] the partially built successor generation
        attr_reader :generation

        # @api private
        def initialize(generation, cause)
          @generation = generation
          super(cause.message)
        end
      end

      # @return [Integer] the number of the current generation (starting at 1)
      #
      # @api public
      attr_reader :generation_number

      # @api public
      def initialize(&block)
        @mutex = ::Monitor.new

        # Reference count for each committed, not-yet-released generation currently
        # holding each provider instance. A provider shared between generations (because
        # it was unaffected by a reload) has its ownership transferred to the successor
        # on commit, so its count is unchanged; fresh providers add a count. When the
        # count reaches zero (the final generation holding it is released), the provider
        # is stopped exactly once.
        @provider_refs = Hash.new(0)
        @stopped_providers = {}

        @builder = Builder.new
        @builder.on_provider_started = method(:provider_started)

        @generation_number = 1
        @current = build_generation(@generation_number, @builder)

        configure(&block) if block
      end

      # Defines providers and components. Definitions given here form the initial graph;
      # definitions given again inside {#reload} replace the earlier ones.
      #
      # @return [self]
      #
      # @api public
      def configure(&block)
        block.call(DefinitionDSL.new(@builder))
        self
      end

      # Registers a provider definition.
      #
      # @return [self]
      #
      # @api public
      def provider(name, **options, &block)
        @builder.register_provider(name, **options, &block)
        self
      end

      alias_method :register_provider, :provider

      # Registers a component build block. The block receives the generation and must
      # return the component instance, resolving its dependencies through the
      # generation so that usage is recorded for partial rebuilds.
      #
      # @return [self]
      #
      # @api public
      def component(key, &block)
        @builder.register_component(key, &block)
        self
      end

      alias_method :register_component, :component

      # Opens a scope pinned to the current generation. The caller is responsible for
      # closing it (prefer {#with_generation}).
      #
      # @return [GenerationScope]
      #
      # @api public
      def open_generation
        @mutex.synchronize do
          # Retire/reload and scope creation both happen under this mutex, so the
          # current generation can never be released between selecting it here and
          # retaining it inside the scope.
          GenerationScope.new(@current)
        end
      end

      alias_method :generation, :open_generation

      # Opens a scope, yields it, and closes it after the block (even on failure).
      #
      # @return [Object] the block's return value
      #
      # @api public
      def with_generation
        scope = open_generation
        scope.wrap { yield(scope) }
      end

      # Resolves a component from the current generation, without opening a scope. Use
      # {#with_generation} for work that must remain on a fixed generation across a
      # reload.
      #
      # @return [Object]
      #
      # @api public
      def resolve(key)
        @mutex.synchronize { @current }.resolve(key)
      end

      alias_method :[], :resolve

      # @return [Generation] the current generation
      #
      # @api private
      def current_generation
        @mutex.synchronize { @current }
      end

      # Shuts down the current generation, stopping every provider it still owns. Open
      # scopes keep their own generations alive and release them when they close.
      #
      # @return [self]
      #
      # @api public
      def shutdown!
        @mutex.synchronize do
          current = @current
          @current = nil
          current&.retire!
        end
        self
      end

      # Rebuilds the component graph, installing a new generation on success.
      #
      # Only components whose definitions changed (given either through the block or via
      # `changed:`), together with every component and provider that depends on them,
      # are rebuilt. Everything unaffected is carried into the new generation.
      #
      # If the new graph fails to build or a provider fails to start, the new graph is
      # discarded: the previous generation remains current and continues serving.
      #
      # @param changed [String, Symbol, Array<String, Symbol>] component keys known to
      #   have changed, even when their build blocks are otherwise identical
      #
      # @raise [ReloadFailedError] if the new graph could not be built or started
      #
      # @return [Integer] the new generation number
      #
      # @api public
      def reload(changed: nil, &block)
        @mutex.synchronize do
          previous = @current
          previous_builder = @builder

          candidate_builder = previous_builder.dup
          DefinitionDSL.new(candidate_builder).instance_eval(&block) if block

          seed_keys = Array(changed).map(&:to_s) +
            candidate_builder.changed_component_keys(previous_builder)
          seed_providers = candidate_builder.changed_provider_names(previous_builder)

          affected_keys, affected_providers = affected_closure(
            previous, seed_keys, seed_providers, candidate_builder
          )

          successor = begin
            previous.build_successor(
              @generation_number + 1,
              candidate_builder,
              affected_keys,
              affected_providers.to_a
            )
          rescue SuccessorBuildError => build_error
            discard_successor(previous, build_error.generation)
            raise ReloadFailedError.new(build_error)
          end

          commit_successor(previous, successor, candidate_builder)

          @generation_number
        end
      end

      # @api private
      def provider_started(provider)
        @mutex.synchronize do
          @provider_refs[provider] += 1
        end
        nil
      end

      private

      # @api private
      def build_generation(number, builder)
        Generation.new(number: number, builder: builder).tap do |generation|
          generation.on_release { generation_released(generation) }
        end
      end

      # @api private
      def generation_released(generation)
        @mutex.synchronize do
          generation.owned_providers.each do |provider|
            refs = (@provider_refs[provider] -= 1)
            stop_provider!(provider) if refs.zero?
          end
        end
        nil
      end

      # @api private
      def commit_successor(previous, successor, candidate_builder)
        successor_providers = successor.owned_providers
        shared_providers = successor_providers & previous.owned_providers

        # Fresh providers become owned by the newly committed successor. Carried
        # (shared) providers merely move ownership from the previous generation to the
        # successor: they keep running for any scopes still resolving their carried
        # components from the old generation, and their reference count is unchanged.
        # Fresh providers already counted 1 when they started (while the successor was
        # being built), so no further bookkeeping is needed here.
        previous.remove_providers!(shared_providers)

        successor.on_release { generation_released(successor) }

        @builder = candidate_builder
        @current = successor
        @generation_number = successor.number

        previous.retire!
      end

      # @api private
      def discard_successor(previous, candidate)
        # Stop only providers freshly started by the failed candidate. Providers carried
        # from the previous generation remain owned and running there.
        fresh = candidate.owned_providers - previous.owned_providers
        fresh.each do |provider|
          @provider_refs.delete(provider)
          stop_provider!(provider)
        rescue StandardError
          nil
        end
        nil
      end

      # Stops a provider instance at most once. Provider#stop itself is short-circuited
      # only until it has stopped once; guarding here also makes shutdown idempotent if
      # a generation is released twice (e.g. retired before its final scope closes).
      #
      # @return [void]
      #
      # @api private
      def stop_provider!(provider)
        @mutex.synchronize do
          return if @stopped_providers[provider]
          @stopped_providers[provider] = true
          provider.stop
        end
        nil
      end

      # Computes the fixed point of affected component keys and provider names.
      #
      # Owners recorded for a dependency edge are either component keys or per-provider
      # sentinels; a changed key therefore rebuilds dependent components and restarts
      # dependent providers. Restarting a provider rebuilds every key it provides.
      #
      # @return [Array(Set<String>, Set<Symbol>)]
      #
      # @api private
      def affected_closure(generation, seed_keys, seed_providers, builder)
        dependencies, started_providers = generation.reload_snapshot
        providers_by_name = started_providers.to_h { |provider| [provider.name, provider] }

        reverse_deps = Hash.new { |hash, key| hash[key] = [] }
        dependencies.each do |owner, deps|
          deps.each { |dep_key| reverse_deps[dep_key] << owner }
        end

        keys = Set.new(seed_keys)
        providers = Set.new(seed_providers.map(&:to_sym))

        loop do
          grew = false

          pending = keys.to_a
          until pending.empty?
            key = pending.shift

            reverse_deps.fetch(key, []).each do |owner|
              if (provider_name = Generation.provider_from_sentinel(owner))
                unless providers.include?(provider_name)
                  providers << provider_name
                  grew = true
                end
              elsif !keys.include?(owner)
                keys << owner
                pending << owner
                grew = true
              end
            end
          end

          providers.each do |name|
            provider = providers_by_name[name]
            next unless provider

            provider.provider_container._container.keys.each do |provided_key|
              unless keys.include?(provided_key)
                keys << provided_key
                grew = true
              end
            end
          end

          keys.each do |key|
            root_key = key.split(KEY_SEPARATOR, 2).first.to_sym
            if builder.provider?(root_key) && !providers.include?(root_key)
              providers << root_key
              grew = true
            end
          end

          break unless grew
        end

        [keys, providers]
      end

      # Block-level DSL used by {#initialize}, {#configure}, and {#reload}.
      #
      # @api public
      # @since 1.3.0
      class DefinitionDSL
        # @api private
        def initialize(builder)
          @builder = builder
        end

        # Registers or replaces a provider definition.
        #
        # @return [void]
        #
        # @api public
        def provider(name, **options, &block)
          @builder.register_provider(name, **options, &block)
        end

        alias_method :register_provider, :provider

        # Registers or replaces a component definition.
        #
        # @return [void]
        #
        # @api public
        def component(key, &block)
          @builder.register_component(key, &block)
        end

        alias_method :register_component, :component
      end
    end
  end
end
