# frozen_string_literal: true

require "dry/system/errors"

module Dry
  module System
    # Plans a set of plugin versions to load, chosen from a caller-provided
    # (limited) set of candidates, such that every dependency and version
    # constraint is satisfied.
    #
    # The planner works purely over {PluginPlanner::Descriptor} data objects:
    # it never requires files or executes plugin code while solving. Loading
    # happens only afterwards, explicitly, via {PluginPlanner::Plan#load!}.
    #
    # Selection is deterministic: plugins are resolved in sorted name order
    # and the highest version satisfying all constraints is always preferred.
    # Versions outside the declared constraints are never selected.
    #
    # @example
    #   planner = Dry::System::PluginPlanner.new(candidates: descriptors)
    #   plan = planner.plan("web" => ">= 1.0", "auth" => "~> 2.1")
    #   plan.load! { |descriptor| MyPluginRepo.load(descriptor) }
    #
    # @api public
    class PluginPlanner
      # Plans a set of plugins in one step. See #plan.
      #
      # @api public
      def self.plan(candidates:, requirements:)
        new(candidates: candidates).plan(requirements)
      end

      # @return [Hash{Symbol => Array<PluginPlanner::Descriptor>}] candidates
      #   grouped by plugin name, each list sorted by version (highest first)
      #
      # @api public
      attr_reader :candidates

      # @param candidates [Array<PluginPlanner::Descriptor>] the limited set
      #   of candidate plugin versions the plan may choose from
      #
      # @api public
      def initialize(candidates:)
        @candidates = candidates.group_by(&:name).transform_values { |descriptors|
          descriptors.uniq(&:version).sort_by(&:version).reverse
        }
      end

      # Selects a set of plugin versions satisfying the given requirements
      # and all declared dependencies.
      #
      # @param requirements [Hash{Symbol, String => String, Array, Gem::Requirement}, Array]
      #   the application's declared plugins and their allowed version
      #   ranges, e.g. {web: "~> 1.2"}; an array of names allows any version
      #
      # @return [PluginPlanner::Plan]
      #
      # @raise [PluginPlanUnresolvableError] when no selection satisfies every
      #   constraint; the message describes the conflicting constraint chain
      #
      # @api public
      def plan(requirements)
        solver = Solver.new(
          candidates: candidates,
          requirements: normalize_requirements(requirements)
        )
        Plan.new(solver.solve)
      rescue Solver::Conflict => conflict
        raise PluginPlanUnresolvableError, conflict.message
      end

      # Plans and then loads the selected plugins, in dependency order.
      #
      # @see Plan#load!
      #
      # @api public
      def load(requirements, loader = nil, &block)
        plan(requirements).load!(loader, &block)
      end

      private

      # @api private
      def normalize_requirements(requirements)
        requirements = requirements.to_h { |name| [name, nil] } if requirements.is_a?(Array)

        requirements.to_h { |name, requirement|
          [name.to_sym, Descriptor.coerce_requirement(requirement)]
        }
      end
    end
  end
end
