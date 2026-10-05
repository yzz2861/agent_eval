# frozen_string_literal: true

require "concurrent/hash"
require "thread"

module Dry
  module System
    # Runs blocks within a stable component graph generation.
    #
    # While a generation is active, resolving components always uses the graph that was
    # current when the scope started. Reloading builds a replacement graph and makes it
    # available to new scopes without stopping providers used by older scopes.
    class GenerationScope
      Generation = Struct.new(:number, :container, :scope_count, keyword_init: true)
      DEFAULT_BUILDER = ->(source, changed_keys) {
        source.reload_component_graph(changed_keys)
      }

      class Scope
        attr_reader :generation

        def initialize(owner, generation)
          @owner = owner
          @generation = generation
        end

        def container
          generation.container
        end

        def resolve(...) = container.resolve(...)
        alias_method :[], :resolve

        def release
          @owner.release_scope(self)
        end
      end

      def initialize(container, &builder)
        @mutex = Mutex.new
        @root_container = container
        @default_builder = builder
        @next_number = 1
        @scopes = {}
        @current = Generation.new(number: 1, container: container, scope_count: 0)
        @generations = Hash.new { |generations, number| generations[number] = [] }
        @generations[@current.number] << @current
      end

      def current
        @mutex.synchronize { @current }
      end

      def use
        scope = enter
        @root_container.activate_component_graph(scope.container) do
          yield(scope)
        end
      ensure
        scope&.release
      end

      alias_method :with, :use

      def reload!(*changed_keys, &custom_builder)
        keys = changed_keys.flatten.map(&:to_s)
        generation = @mutex.synchronize { build_generation!(keys, custom_builder) }

        @mutex.synchronize do
          previous = @current
          @current = generation
          @generations[generation.number] << generation
          reuse_generation_providers!(generation, previous)
          previous
        end.tap do |previous|
          release_if_unused(previous)
        end

        generation.container
      end

      def shutdown!
        generations = @mutex.synchronize { @generations.values.flatten }
        generations.sort_by(&:number).each { |generation| shutdown(generation) }

        self
      end

      def enter
        thread = Thread.current

        @mutex.synchronize do
          generation = @current
          generation.scope_count += 1
          scope = Scope.new(self, generation)
          (@scopes[thread] ||= []).push(scope)
          scope
        end
      end

      def release_scope(scope)
        thread = Thread.current
        generation = nil

        @mutex.synchronize do
          active = @scopes[thread]&.last
          return self unless active

          return self unless active.equal?(scope)

          generation = scope.generation
          generation.scope_count -= 1
          @scopes[thread].pop

          @scopes.delete(thread) if @scopes[thread]&.empty?
        end

        release_if_unused(generation)
        self
      end

      private

      def build_generation!(changed_keys, custom_builder = nil)
        source = @current.container
        container = nil

        begin
          builder = custom_builder || @default_builder || DEFAULT_BUILDER
          container = builder.call(source, changed_keys)
          number = next_number

          Generation.new(number: number, container: container, scope_count: 0)
        rescue StandardError => error
          shutdown_failed_generation!(container, source)
          raise error
        end
      end

      def next_number
        @next_number += 1
      end

      def reuse_generation_providers!(generation, previous)
        generation.container.providers.started_providers.each do |provider|
          next unless previous.container.providers.started_providers.any? { |candidate|
            candidate.equal?(provider)
          }

          provider.reuse!
        end
      end

      def shutdown_failed_generation!(container, source)
        return unless container

        container.providers.started_providers.each do |provider|
          shared = source.providers.started_providers.any? { |candidate| candidate.equal?(provider) }
          if shared
            provider.restore_reuse!
          else
            provider.stop unless provider.stopped?
          end
        end
      end

      def release_if_unused(generation)
        retire = @mutex.synchronize do
          generation.scope_count.zero? && generation != @current
        end

        shutdown(generation) if retire
      end

      def shutdown(generation)
        tracked = @mutex.synchronize { @generations[generation.number].include?(generation) }
        return false unless tracked

        others = @mutex.synchronize do
          @generations.values.flatten.reject { |other| other.equal?(generation) }
        end

        generation.container.providers.started_providers.each do |provider|
          shared_with_older = others.any? do |other|
            other.number < generation.number &&
              other.container.providers.started_providers.any? { |candidate| candidate.equal?(provider) }
          end
          shared_with_newer = others.any? do |other|
            other.number > generation.number &&
              other.container.providers.started_providers.any? { |candidate| candidate.equal?(provider) }
          end

          if shared_with_older && !shared_with_newer
            provider.unreuse!
          elsif !shared_with_older
            provider.release!
          end
        end

        @mutex.synchronize { @generations[generation.number].delete(generation) }
        true
      end
    end
  end
end
