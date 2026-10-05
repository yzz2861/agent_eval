# frozen_string_literal: true

module Dry
  module System
    class PluginPlanner
      # Data-only description of a single plugin version available for
      # selection, as offered by the plugin repository.
      #
      # Descriptors carry no executable code: the planner only reads their
      # attributes while solving, so planning never runs plugin code.
      #
      # @api public
      class Descriptor
        # Coerces a requirement given as a string, array of strings,
        # Gem::Requirement or nil into a Gem::Requirement.
        #
        # @api private
        def self.coerce_requirement(value)
          case value
          when nil then Gem::Requirement.default
          when Gem::Requirement then value
          when Array then Gem::Requirement.new(*value.map(&:to_s))
          else Gem::Requirement.new(value.to_s)
          end
        end

        # @return [Symbol]
        #
        # @api public
        attr_reader :name

        # @return [Gem::Version]
        #
        # @api public
        attr_reader :version

        # Required dependencies: the named plugins must be part of the plan,
        # in a version satisfying the given requirement.
        #
        # @return [Hash{Symbol => Gem::Requirement}]
        #
        # @api public
        attr_reader :dependencies

        # Optional dependencies: the named plugins are *not* pulled into the
        # plan, but when they are selected anyway (for another reason), their
        # version must satisfy the given requirement.
        #
        # @return [Hash{Symbol => Gem::Requirement}]
        #
        # @api public
        attr_reader :optional_dependencies

        # Arbitrary caller-owned payload (e.g. whatever the loader needs to
        # actually load the plugin). Never touched by the planner.
        #
        # @return [Object]
        #
        # @api public
        attr_reader :metadata

        # @api public
        def initialize(name:, version:, dependencies: {}, optional_dependencies: {}, metadata: nil)
          @name = name.to_sym
          @version = Gem::Version.new(version.to_s)
          @dependencies = self.class.coerce_dependencies(dependencies)
          @optional_dependencies = self.class.coerce_dependencies(optional_dependencies)
          @metadata = metadata
        end

        # @api private
        def self.coerce_dependencies(dependencies)
          dependencies.to_h { |name, requirement|
            [name.to_sym, coerce_requirement(requirement)]
          }
        end

        # @api public
        def ==(other)
          other.is_a?(Descriptor) && name == other.name && version == other.version
        end
        alias_method :eql?, :==

        # @api public
        def hash
          [name, version].hash
        end

        # @api public
        def to_s
          "#{name} (#{version})"
        end
      end
    end
  end
end
