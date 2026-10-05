# frozen_string_literal: true

module Dry
  module System
    class PluginPlanner
      # Deterministic backtracking solver over a limited candidate set.
      #
      # Selection rules:
      #
      # - plugin names are resolved in sorted order
      # - versions are tried highest first
      # - a version is only ever chosen when it satisfies every constraint
      #   gathered so far; constraints are never relaxed, so the solver can
      #   never silently downgrade to an out-of-range version
      #
      # Required dependencies force their target into the plan; optional
      # dependencies only constrain their target when it is selected anyway.
      #
      # @api private
      class Solver
        EMPTY_ARRAY = [].freeze
        EMPTY_HASH = {}.freeze

        # A single version constraint imposed on a plugin name, along with
        # the source that imposed it (:application or a Descriptor).
        #
        # @api private
        class Constraint
          attr_reader :requirement, :source

          def initialize(requirement:, source:)
            @requirement = requirement
            @source = source
          end

          def satisfied_by?(version)
            requirement.satisfied_by?(version)
          end

          def describe(name)
            "#{source_label} requires #{name} #{requirement_label}"
          end

          private

          def source_label
            source == :application ? "application" : source.to_s
          end

          def requirement_label
            requirement.requirements.map { |op, version| "#{op} #{version}" }.join(", ")
          end
        end

        # Raised internally when a search branch cannot satisfy all
        # constraints. Carries enough context to render a minimal,
        # understandable conflict chain.
        #
        # @api private
        class Conflict < StandardError
          def initialize(name:, constraints:, reasons:, available_versions:)
            @name = name
            @constraints = constraints
            @reasons = reasons
            @available_versions = available_versions
            super(build_message)
          end

          private

          def build_message
            lines = ["no version of `#{@name}` satisfies all constraints:"]

            @constraints.each { |constraint| lines << "  - #{constraint.describe(@name)}" }

            @constraints.map(&:source).uniq.each do |source|
              next if source == :application

              reasons = @reasons[source.name]
              next unless reasons

              chain = reasons.map { |constraint| constraint.describe(source.name) }.join("; ")
              lines << "    (#{source} selected to satisfy: #{chain})"
            end

            if @available_versions.empty?
              lines << "  (no candidate versions of `#{@name}` were provided)"
            else
              lines << "  (available versions of `#{@name}`: #{@available_versions.join(', ')})"
            end

            lines.join("\n")
          end
        end

        def initialize(candidates:, requirements:)
          @candidates = candidates
          @requirements = requirements
        end

        # @return [Hash{Symbol => PluginPlanner::Descriptor}] the selected
        #   descriptor for each plugin name in the plan
        #
        # @api private
        def solve
          required = new_constraint_map
          @requirements.each do |name, requirement|
            required[name] << Constraint.new(requirement: requirement, source: :application)
          end

          search(
            assigned: {},
            required: required,
            optional: new_constraint_map,
            reasons: {}
          )
        end

        private

        def search(assigned:, required:, optional:, reasons:)
          name = next_name(assigned, required)
          return assigned unless name

          constraints = required[name] + optional.fetch(name, EMPTY_ARRAY)
          feasible = feasible_candidates(name, constraints)

          raise conflict(name, constraints, reasons) if feasible.empty?

          first_conflict = nil

          feasible.each do |descriptor|
            begin
              return search(
                **apply(assigned, required, optional, reasons, name, descriptor)
              )
            rescue Conflict => error
              first_conflict ||= error
            end
          end

          raise first_conflict
        end

        # Returns the branch state for +name+ resolved to +descriptor+, or
        # raises Conflict when the descriptor's dependencies clash with an
        # already-selected plugin.
        #
        # @api private
        def apply(assigned, required, optional, reasons, name, descriptor)
          reasons = reasons.merge(name => required[name] + optional.fetch(name, EMPTY_ARRAY))

          descriptor.dependencies.each do |dep_name, requirement|
            check_assigned!(assigned, dep_name, requirement, descriptor, required, optional, reasons)
          end
          descriptor.optional_dependencies.each do |dep_name, requirement|
            check_assigned!(assigned, dep_name, requirement, descriptor, required, optional, reasons)
          end

          new_required = dup_constraints(required)
          new_optional = dup_constraints(optional)

          descriptor.dependencies.each do |dep_name, requirement|
            new_required[dep_name] << Constraint.new(requirement: requirement, source: descriptor)
          end
          descriptor.optional_dependencies.each do |dep_name, requirement|
            new_optional[dep_name] << Constraint.new(requirement: requirement, source: descriptor)
          end

          {
            assigned: assigned.merge(name => descriptor),
            required: new_required,
            optional: new_optional,
            reasons: reasons
          }
        end

        # @api private
        def check_assigned!(assigned, dep_name, requirement, descriptor, required, optional, reasons)
          return unless assigned.key?(dep_name)
          return if requirement.satisfied_by?(assigned[dep_name].version)

          constraint = Constraint.new(requirement: requirement, source: descriptor)
          existing = required.fetch(dep_name, EMPTY_ARRAY) + optional.fetch(dep_name, EMPTY_ARRAY)

          raise conflict(dep_name, existing + [constraint], reasons)
        end

        # @api private
        def next_name(assigned, required)
          (required.keys - assigned.keys).min_by(&:to_s)
        end

        # @api private
        def feasible_candidates(name, constraints)
          @candidates.fetch(name, EMPTY_ARRAY).select { |descriptor|
            constraints.all? { |constraint| constraint.satisfied_by?(descriptor.version) }
          }
        end

        # @api private
        def conflict(name, constraints, reasons)
          Conflict.new(
            name: name,
            constraints: constraints,
            reasons: reasons,
            available_versions: @candidates.fetch(name, EMPTY_ARRAY).map(&:version)
          )
        end

        # @api private
        def new_constraint_map
          Hash.new { |hash, key| hash[key] = [] }
        end

        # @api private
        def dup_constraints(map)
          map.each_with_object(new_constraint_map) { |(key, constraints), copy|
            copy[key] = constraints.dup
          }
        end
      end
    end
  end
end
