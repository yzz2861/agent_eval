# frozen_string_literal: true

require "dry/system/errors"

module Dry
  module System
    module Plugins
      class Planner
        Candidate = Struct.new(
          :name, :version, :dependencies, :optional_dependencies, :descriptor,
          keyword_init: true
        )

        Constraint = Struct.new(
          :source, :target, :requirement, :optional, :path,
          keyword_init: true
        )

        Pending = Struct.new(:name, :path, :required_by, keyword_init: true)

        Conflict = Struct.new(
          :name, :path, :constraints, :candidates, :selected_version, :circular,
          keyword_init: true
        )

        class Plan
          include Enumerable

          attr_reader :candidates, :names

          def initialize(candidates, names)
            @candidates = candidates
            @names = names
          end

          def each(&block)
            return to_enum unless block

            names.each { |name| yield candidates.fetch(name) }
          end

          def to_a
            map(&:descriptor)
          end

          def load(loader = nil, &block)
            loader ||= block

            each do |candidate|
              if loader
                loader.call(candidate.descriptor)
              elsif candidate.descriptor.respond_to?(:load)
                candidate.descriptor.load
              else
                raise ArgumentError, "a loader block is required to load #{candidate.name.inspect}"
              end
            end

            self
          end
        end

        def initialize(candidates, allowed: nil)
          @candidates = normalize_candidates(candidates)
          @allowed = normalize_constraints(allowed)
        end

        def plan(*requests, **options)
          requests = requests.flatten
          allowed = options.delete(:allowed)
          requests.concat(options.map { |name, requirement| {name => requirement} })
          raise ArgumentError, "at least one plugin must be requested" if requests.empty?

          allowed = allowed.nil? ? @allowed : normalize_constraints(allowed)
          requested = normalize_requests(requests)
          pending = requested.keys.sort.map do |name|
            requirement = requested.fetch(name).first
            constraint = Constraint.new(
              source: "application",
              target: name,
              requirement: combine_requirements(
                requirement,
                allowed.fetch(name, Gem::Requirement.default)
              ),
              optional: false,
              path: [name]
            )
            Pending.new(name: name, path: [name], required_by: {"application" => [constraint]})
          end

          result = resolve(pending, {}, [], allowed)
          raise PluginResolutionError, circular_message(result) if result.is_a?(Conflict) && result.circular
          raise PluginResolutionError, format_conflict(result) if result.is_a?(Conflict)

          Plan.new(result, load_order(result).freeze)
        end

        def load(*requests, **options, &block)
          allowed = options.fetch(:allowed, nil)
          loader = options.fetch(:loader, nil)
          request_options = options.except(:allowed, :loader)
          plan(*requests, allowed: allowed, **request_options).load(loader || block)
        end

        private

        def normalize_candidates(candidates)
          unless candidates.respond_to?(:each)
            raise ArgumentError, "candidates must be enumerable"
          end

          candidates.each_with_index.each_with_object({}) do |(descriptor, index), grouped|
            name = read(descriptor, :name).to_s
            version = Gem::Version.new(read(descriptor, :version).to_s)
            candidate = Candidate.new(
              name: name,
              version: version,
              dependencies: read_dependencies(descriptor, :dependencies, false),
              optional_dependencies: read_dependencies(descriptor, :optional_dependencies, true),
              descriptor: descriptor
            )

            grouped[name] ||= []
            if grouped[name].any? { |entry, _index| entry.version == version }
              raise ArgumentError, "duplicate candidate #{name.to_sym.inspect} for version #{version}"
            end

            grouped[name] << [candidate, index]
          end.transform_values do |entries|
            entries.sort { |(left, left_index), (right, right_index)|
              (right.version <=> left.version).nonzero? || left_index <=> right_index
            }.map(&:first).freeze
          end
        end

        def normalize_constraints(constraints)
          return {} if constraints.nil?
          unless constraints.respond_to?(:each_pair)
            raise ArgumentError, "allowed versions must be a hash"
          end

          constraints.each_with_object({}) do |(name, requirement), normalized|
            normalized[name.to_s] = Gem::Requirement.create(requirement)
          end
        end

        def normalize_requests(requests)
          requests.each_with_index.each_with_object({}) do |(request, index), normalized|
            name, requirement = request_name_and_requirement(request)
            if normalized.key?(name)
              raise ArgumentError, "plugin #{name.to_sym.inspect} was requested more than once"
            end

            normalized[name] = [requirement, index]
          end
        end

        def request_name_and_requirement(request)
          case request
          when Symbol, String
            [request.to_s, Gem::Requirement.default]
          when Hash
            unless request.size == 1
              raise ArgumentError, "a requested plugin must contain one name and version constraint"
            end

            name, requirement = request.first
            [name.to_s, Gem::Requirement.create(requirement)]
          else
            unless request.respond_to?(:name)
              raise ArgumentError, "a requested plugin must be a name or name/version pair"
            end

            requirement = request.respond_to?(:version_requirement) ? request.version_requirement : nil
            [request.name.to_s, Gem::Requirement.create(requirement)]
          end
        end

        def read_dependencies(descriptor, method_name, optional_default)
          dependencies = read(descriptor, method_name, default: [])

          case dependencies
          when nil
            {}
          when Hash
            dependencies.each_with_object({}) do |(name, requirement), normalized|
              add_dependency(normalized, name.to_s, requirement, optional_default)
            end
          when Array
            dependencies.each_with_object({}) do |dependency, normalized|
              case dependency
              when Symbol, String
                add_dependency(normalized, dependency.to_s, nil, optional_default)
              when Hash
                dependency.each do |name, requirement|
                  add_dependency(normalized, name.to_s, requirement, optional_default)
                end
              else
                unless dependency.respond_to?(:name)
                  raise ArgumentError, "plugin dependencies must be names or name/version pairs"
                end

                requirement = dependency.respond_to?(:version_requirement) ? dependency.version_requirement : nil
                optional = dependency.respond_to?(:optional?) ? dependency.optional? : optional_default
                add_dependency(normalized, dependency.name.to_s, requirement, optional)
              end
            end
          else
            raise ArgumentError, "#{method_name} must be an array or hash"
          end
        end

        def add_dependency(dependencies, name, requirement, optional)
          if dependencies.key?(name) && dependencies.fetch(name).last != optional
            raise ArgumentError, "plugin #{name.to_sym.inspect} is both required and optional"
          end

          previous = dependencies.fetch(name, [Gem::Requirement.default, optional]).first
          combined = combine_requirements(previous, Gem::Requirement.create(requirement))
          dependencies[name] = [combined, optional]
        end

        def read(object, name, default: nil)
          if object.respond_to?(name)
            object.public_send(name)
          elsif object.respond_to?(:[])
            value = object[name]
            value = object[name.to_s] if value.nil?
            value.nil? ? default : value
          else
            default
          end
        end

        def resolve(pending, selections, constraints, allowed)
          return selections if pending.empty?

          current = pending.first
          remaining = pending.drop(1)
          current_constraints = constraints_for(current, selections, constraints, allowed)
          candidates = @candidates.fetch(current.name, [])
          applicable = candidates.select do |candidate|
            current_constraints.all? { |constraint| constraint.requirement.satisfied_by?(candidate.version) }
          end

          if applicable.empty?
            return Conflict.new(
              name: current.name,
              path: current.path,
              constraints: current_constraints,
              candidates: candidates,
              selected_version: nil
            )
          end

          failures = []

          applicable.each do |candidate|
            next_pending = remaining.map do |pending|
              pending.dup.tap do |copied|
                copied.required_by = pending.required_by.transform_values(&:dup)
              end
            end
            next_constraints = constraints.dup
            conflict = apply_candidate(candidate, current, next_pending, selections, next_constraints)

            if conflict
              failures << conflict
              next
            end

            result = resolve(
              next_pending,
              selections.merge(current.name => candidate),
              next_constraints,
              allowed
            )
            return result unless result.is_a?(Conflict)

            failures << result
          end

          failures.find { |failure| failure.is_a?(PluginResolutionError) } ||
            failures.min_by { |failure| [failure.path.size, failure.name] } ||
            Conflict.new(
              name: current.name,
              path: current.path,
              constraints: current_constraints,
              candidates: candidates,
              selected_version: nil
            )
        end

        def constraints_for(pending, selections, constraints, allowed)
          active = []
          application_requirements = pending.required_by.fetch("application", []).map(&:requirement)
          application_requirements << allowed.fetch(pending.name) if allowed.key?(pending.name)

          unless application_requirements.empty?
            requirement = combine_requirements(*application_requirements)
            unless requirement == Gem::Requirement.default
              active << Constraint.new(
                source: "application",
                target: pending.name,
                requirement: requirement,
                optional: false,
                path: pending.path
              )
            end
          end

          active.concat(pending.required_by.reject { |source, _| source == "application" }.values.flatten)
          active.concat(constraints.select do |constraint|
            constraint.target == pending.name && constraint_active?(constraint, pending, selections)
          end)
          active.uniq { |constraint| [constraint.source, constraint.requirement, constraint.optional] }
        end

        def constraint_active?(constraint, pending, selections)
          selections.key?(constraint.source) ||
            constraint.optional && pending.required_by.key?(constraint.source)
        end

        def apply_candidate(candidate, current, pending, selections, constraints)
          candidate.dependencies.each do |name, (requirement, _optional)|
            path = current.path + [name]
            return circular_conflict(path) if path.size != path.uniq.size

            constraint = Constraint.new(
              source: candidate.name,
              target: name,
              requirement: requirement,
              optional: false,
              path: path
            )

            if selections.key?(name)
              unless requirement.satisfied_by?(selections.fetch(name).version)
                return selected_conflict(name, path, constraint, selections.fetch(name))
              end
            elsif (existing_pending = pending.find { |item| item.name == name })
              existing_pending.path = path if path.size < existing_pending.path.size
              existing_pending.required_by[candidate.name] ||= []
              existing_pending.required_by[candidate.name] << constraint
            else
              pending << Pending.new(
                name: name,
                path: path,
                required_by: {candidate.name => [constraint]}
              )
            end

            constraints << constraint
          end

          candidate.optional_dependencies.each do |name, (requirement, _optional)|
            constraint = Constraint.new(
              source: candidate.name,
              target: name,
              requirement: requirement,
              optional: true,
              path: current.path + [name]
            )
            constraints << constraint

            if selections.key?(name) && !requirement.satisfied_by?(selections.fetch(name).version)
              return selected_conflict(name, current.path + [name], constraint, selections.fetch(name))
            end
          end

          nil
        end

        def selected_conflict(name, path, constraint, selected)
          Conflict.new(
            name: name,
            path: path,
            constraints: [constraint],
            candidates: [selected],
            selected_version: selected.version
          )
        end

        def circular_conflict(path)
          Conflict.new(
            name: path.last,
            path: path,
            constraints: [],
            candidates: [],
            selected_version: nil,
            circular: true
          )
        end

        def combine_requirements(*requirements)
          normalized = requirements.map do |requirement|
            requirement.is_a?(Gem::Requirement) ? requirement : Gem::Requirement.create(requirement)
          end
          Gem::Requirement.new(
            normalized.flat_map do |requirement|
              requirement.requirements.map { |operator, version| "#{operator} #{version}" }
            end
          )
        end

        def load_order(selections)
          edges = selections.values.flat_map do |candidate|
            candidate.dependencies.keys
              .select { |name| selections.key?(name) }
              .map { |name| [candidate.name, name] }
          end
          remaining = selections.keys.sort
          ordered = []

          until remaining.empty?
            ready = remaining.select { |name| edges.none? { |source, _| source == name } }
            ordered.concat(ready.sort)
            remaining -= ready
            edges.reject! { |_, destination| ready.include?(destination) }
          end

          ordered
        end

        def format_conflict(conflict)
          source = format_constraints(conflict.constraints)
          chain = format_path(explanation_path(conflict))

          if conflict.candidates.empty?
            "plugin #{conflict.name.to_sym.inspect} has no candidates (#{chain})"
          elsif conflict.selected_version
            "plugin #{conflict.name.to_sym.inspect} #{conflict.selected_version} does not satisfy #{source} (#{chain})"
          else
            available = conflict.candidates.map { |candidate| candidate.version }.map(&:to_s).join(", ")
            "plugin #{conflict.name.to_sym.inspect} has no version satisfying #{source}; " \
              "available: #{available} (#{chain})"
          end
        end

        def circular_message(conflict)
          "circular plugin dependency: #{format_path(conflict.path)}"
        end

        def format_path(path)
          path.map { |name| name.to_sym.inspect }.join(" -> ")
        end

        def format_constraints(constraints)
          constraints
            .group_by { |constraint| [constraint.source, constraint.optional] }
            .map do |(source, optional), group|
            requirements = group.map { |constraint| constraint.requirement.to_s }.uniq.join(", ")
            source_label = source == "application" ? "the application" : source.to_sym.inspect
            kind = optional ? "optional constraint from" : "required by"
            "#{requirements} #{kind} #{source_label}"
          end.join(" and ")
        end

        def explanation_path(conflict)
          optional = conflict.constraints.find(&:optional)
          return optional.path if optional&.path

          dependency = conflict.constraints
            .reject { |constraint| constraint.source == "application" }
            .min_by { |constraint| constraint.path&.size || Float::INFINITY }
          dependency&.path || conflict.path
        end
      end
    end
  end
end
