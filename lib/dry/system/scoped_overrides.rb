# frozen_string_literal: true

require "set"
require "dry/core/constants"

module Dry
  module System
    # @api private
    class ScopedOverrides
      include Core::Constants

      attr_reader :container, :registry, :parent_scope, :dependencies

      def initialize(container:, parent_registry:, parent_registrar:, parent_scope:)
        @container = container
        @parent_scope = parent_scope
        @parent_registrar = parent_registrar
        @registry = parent_registry.dup
        source_dependencies =
          if parent_scope
            parent_scope.dependencies
          else
            container.component_dependencies
          end
        @dependencies = source_dependencies.dup
        @dependencies.default_proc = proc { |hash, key| hash[key] = [] }
        @subsystems = build_subsystems
      end

      def activate(overrides)
        overrides.each_key do |key|
          component_keys_for(key).each { |component_key| reset_component(component_key) }
        end

        overrides.each do |key, value|
          register_override(key.to_s, value)
        end
      end

      def remember_dependency(parent_key, child_key)
        return false if dependencies.fetch(child_key, EMPTY_ARRAY).include?(parent_key)

        dependencies[child_key] << parent_key
        true
      end

      def begin_construction
        registry.each_with_object({}) do |(key, item), snapshot|
          snapshot[key] = item.dup
        end
      end

      def rollback_construction(snapshot)
        return unless snapshot

        registry.each_key do |key|
          if snapshot.key?(key)
            registry[key] = snapshot.fetch(key)
          else
            registry.delete(key)
          end
        end
      end

      def discard
        registry.clear
        self
      end

      def shutdown
        subsystem(:@providers)&.shutdown
        self
      end

      def subsystem(name)
        @subsystems[name]
      end

      private

      def build_subsystems
        {
          :@providers => @parent_registrar.scoped_copy(container)
        }
      end

      def component_keys_for(key)
        remaining = [key.to_s]
        component_keys = Set.new

        while (component_key = remaining.shift)
          next unless component_keys.add?(component_key)

          remaining.concat(dependencies.fetch(component_key, EMPTY_ARRAY))
        end

        component_keys
      end

      def reset_component(key)
        item = registry[key] or return
        registry[key] = Dry::Core::Container::Item::Factory.new.call(item.item, **item.options)
      end

      def register_override(key, value)
        registry[key] = Dry::Core::Container::Item::Factory.new.call(value, call: false)
      end
    end
  end
end
