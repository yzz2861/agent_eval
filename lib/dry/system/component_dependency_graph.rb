# frozen_string_literal: true

require "set"
require "thread"

module Dry
  module System
    # Tracks dependencies observed while components are resolved.
    #
    # @api private
    class ComponentDependencyGraph
      attr_reader :dependencies

      def initialize
        @mutex = Mutex.new
        @stacks = Hash.new { |stacks, thread| stacks[thread] = [] }
        @dependencies = Hash.new { |edges, key| edges[key] = Set.new }
      end

      def resolve(key)
        stack = @stacks[Thread.current]
        parent = stack.last

        @mutex.synchronize { dependencies[parent] << key.to_s } if parent

        stack << key.to_s

        begin
          yield
        ensure
          stack.pop
        end
      end

      def affected(changed_keys, provider_items = {})
        seeds = changed_keys.map(&:to_s).to_set
        provider_items.each do |provider_name, keys|
          changed_provider = seeds.include?(provider_name.to_s) ||
            keys.any? { |key| seeds.include?(key.to_s) }
          next unless changed_provider

          seeds << provider_name.to_s
          keys.each { |key| seeds << key.to_s }
        end

        dependent_keys(seeds)
      end

      private

      def dependent_keys(seeds)
        affected = seeds.dup
        pending = seeds.to_a

        while (key = pending.shift)
          reverse_dependencies(key).each do |dependency|
            next if affected.include?(dependency)

            affected << dependency
            pending << dependency
          end
        end

        affected
      end

      def reverse_dependencies(key)
        dependencies.each_with_object(Set.new) do |(component, dependencies), keys|
          keys << component if dependencies.include?(key.to_s)
        end
      end
    end
  end
end
