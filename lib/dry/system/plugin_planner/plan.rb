# frozen_string_literal: true

module Dry
  module System
    class PluginPlanner
      # The result of planning: a fixed, deterministic set of plugin
      # descriptors in dependency order (dependencies before dependents).
      #
      # A plan is inert: nothing is required or executed until #load! is
      # called explicitly.
      #
      # @api public
      class Plan
        include Enumerable

        # @return [Array<PluginPlanner::Descriptor>] selected descriptors in
        #   dependency order
        #
        # @api public
        attr_reader :selections

        # @api private
        def initialize(assignments)
          @assignments = assignments
          @selections = topological_order(assignments)
        end

        # Yields each selected descriptor in dependency order.
        #
        # @api public
        def each(&block)
          selections.each(&block)
        end

        # @return [PluginPlanner::Descriptor, nil]
        #
        # @api public
        def [](name)
          @assignments[name.to_sym]
        end

        # @api public
        def include?(name)
          @assignments.key?(name.to_sym)
        end

        # @return [Gem::Version, nil]
        #
        # @api public
        def version_of(name)
          self[name]&.version
        end

        # @return [Hash{Symbol => Gem::Version}]
        #
        # @api public
        def to_h
          @assignments.transform_values(&:version)
        end

        # Loads the planned plugins, in dependency order, via the given
        # loader. The loader is called once per selected descriptor.
        #
        # @param loader [#call, nil] callable receiving each descriptor
        #
        # @return [self]
        #
        # @raise [ArgumentError] when no loader is given
        #
        # @api public
        def load!(loader = nil, &block)
          loader ||= block
          raise ArgumentError, "a loader (callable or block) is required" unless loader

          selections.each { |descriptor| loader.call(descriptor) }

          self
        end

        private

        # Kahn's algorithm over required dependencies (plus optional
        # dependencies that happen to be selected), with ties broken by
        # sorted name to keep the order deterministic.
        #
        # @api private
        def topological_order(assignments)
          dependents = Hash.new { |hash, key| hash[key] = [] }
          in_degree = Hash.new(0)

          assignments.each do |name, descriptor|
            in_degree[name] += 0

            (descriptor.dependencies.keys | descriptor.optional_dependencies.keys).each do |dep_name|
              next unless assignments.key?(dep_name)

              dependents[dep_name] << name
              in_degree[name] += 1
            end
          end

          ready = in_degree.select { |_, degree| degree.zero? }.keys.sort_by(&:to_s)
          ordered = []

          until ready.empty?
            name = ready.shift
            ordered << assignments[name]

            dependents[name].each do |dependent|
              in_degree[dependent] -= 1
              ready << dependent if in_degree[dependent].zero?
            end
            ready.sort_by!(&:to_s)
          end

          if ordered.size < assignments.size
            cyclic = (assignments.keys - ordered.map(&:name)).sort_by(&:to_s)
            raise PluginPlanUnresolvableError,
                  "cyclic plugin dependencies between: #{cyclic.join(', ')}"
          end

          ordered
        end
      end
    end
  end
end
