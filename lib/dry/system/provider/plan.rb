# frozen_string_literal: true

module Dry
  module System
    class Provider
      # A viewable, side-effect free plan describing the providers involved in a
      # lifecycle operation and the order in which their steps should run.
      #
      # A plan is built before any `prepare` or `start` side effects occur, which
      # allows missing provider dependencies and dependency cycles to be detected
      # up front. Providers are listed in `start_order` (each provider appears after
      # every provider it depends on) and in the reverse, `stop_order`.
      #
      # @api public
      # @since 1.3.0
      class Plan
        include Enumerable

        # Returns the provider names explicitly requested for the operation.
        #
        # @return [Array<Symbol>]
        #
        # @api public
        attr_reader :roots

        # Returns all provider names taking part in the operation, roots and their
        # transitive dependencies, in start order.
        #
        # @return [Array<Symbol>]
        #
        # @api public
        attr_reader :names

        # Returns the provider names ordered so that every dependency comes before
        # its dependents.
        #
        # @return [Array<Symbol>]
        #
        # @api public
        attr_reader :start_order

        # Builds a plan for the given root provider names.
        #
        # The resolver must respond to `#call(name)` or `#[](name)` and return a
        # registered {Provider} or nil if no provider with that name exists.
        #
        # @param root_names [Array<Symbol>] the providers the operation starts from
        # @param resolver [#call] loads or looks up providers
        #
        # @return [Plan]
        #
        # @raise [ProviderDependencyNotFoundError] if a dependency is not registered
        # @raise [ProviderDependencyCycleError] if the dependencies form a cycle
        #
        # @api public
        def self.build(root_names, resolver)
          new(root_names, resolver).send(:build!)
        end

        # @api private
        def initialize(root_names, resolver)
          @roots = Array(root_names).map(&:to_sym)
          @resolver = resolver
          @names = []
          @start_order = []
        end

        # Returns the provider names in the order in which their `stop` steps should
        # run, i.e. the reverse of the start order.
        #
        # @return [Array<Symbol>]
        #
        # @api public
        def stop_order
          start_order.reverse
        end

        # @return [Boolean]
        #
        # @api public
        def include?(name)
          names.include?(name.to_sym)
        end

        # Returns the resolved {Provider} for each entry in {#start_order}.
        #
        # @return [Array<Provider>]
        #
        # @api public
        def providers
          start_order.map { |name| resolve(name) }
        end

        # Iterates over the providers in {#start_order}.
        #
        # @api public
        def each(&)
          providers.each(&)
        end

        # @return [String]
        #
        # @api public
        def to_s
          start_order.map(&:to_s).join(" -> ")
        end

        # @api private
        def inspect
          "#<Dry::System::Provider::Plan #{to_s}>"
        end

        private

        def resolve(name)
          if resolver.respond_to?(:call)
            resolver.call(name)
          else
            resolver[name]
          end
        end

        attr_reader :resolver

        # @api private
        def build!
          states = {}
          stack = []
          missing = {}
          cycles = []

          visit = lambda { |name, from_roots: false|
            provider = resolve(name)

            unless provider
              unless from_roots
                (missing[stack.last] ||= []) << name
              end
              next
            end

            if stack.include?(name)
              start_index = stack.index(name)
              cycles << (stack[start_index..] + [name])
              next
            end

            case states[name]
            when :done
              next
            when :visiting
              start_index = stack.index(name)
              cycles << (stack[start_index..] + [name])
              next
            end

            states[name] = :visiting
            stack << name

            provider.depends_on.each do |dep_name|
              visit.call(dep_name.to_sym)
            end

            stack.pop
            states[name] = :done
            start_order << name unless start_order.include?(name)
          }

          roots.each { |name| visit.call(name, from_roots: true) }

          if (root = missing_root)
            raise ProviderNotFoundError, root
          end

          if missing.any?
            name, deps = missing.first
            raise ProviderDependencyNotFoundError.new(name, missing: deps.uniq)
          end

          if (cycle = cycles.uniq.first)
            raise ProviderDependencyCycleError, cycle
          end

          @names = start_order.dup

          self
        end

        # @api private
        def missing_root
          roots.detect { |name| resolve(name).nil? }
        end
      end
    end
  end
end
