# frozen_string_literal: true

require "pathname"
require "dry/system/constants"

module Dry
  module System
    # Audits a container's component dir configuration for component key and Ruby
    # constant collisions, without executing any component source files.
    #
    # As projects grow, two different files can be mapped to the same component key or
    # Ruby constant (e.g. "foo/bar.rb" and "foo.bar.rb", or "foo_bar.rb" and
    # "FooBar.rb"). The audit expands every configured component dir, namespace and
    # auto-registration (exclusion) rule and reports the collisions that real auto
    # registration would produce.
    #
    # The audit derives all keys and constant paths through the very same objects used
    # by auto registration itself ({ComponentDir#each_component}, {Component#key},
    # {Component#const_path} and the container's inflector), so its results always
    # match runtime behavior. Source files are only ever read (for magic comments),
    # never executed.
    #
    # Collisions are reported in two categories:
    #
    # - **Definite conflicts** ({Report#conflicts}): two or more files will certainly
    #   collide, based purely on static configuration.
    # - **Undetermined collisions** ({Report#undetermined}): whether the collision
    #   actually occurs depends on runtime custom logic, such as a proc-based
    #   auto_register policy, a custom component loader or an instance proc.
    #
    # @example
    #   report = Dry::System::ConfigAudit.new(MyContainer).call
    #
    #   unless report.clean?
    #     puts report
    #   end
    #
    # @api public
    class ConfigAudit
      # A single component source file as seen by the audit, along with the
      # configuration rules that produced its key and constant
      #
      # @api public
      class Entry
        # @return [Dry::System::Component] the audited component
        attr_reader :component

        # @return [Dry::System::ComponentDir] the component dir containing the file
        attr_reader :component_dir

        # @return [Symbol] :registered, :excluded or :undetermined
        attr_reader :registration

        # @return [Symbol] :standard or :undetermined
        attr_reader :constant_derivation

        # @api private
        def initialize(component:, component_dir:, registration:, constant_derivation:)
          @component = component
          @component_dir = component_dir
          @registration = registration
          @constant_derivation = constant_derivation
        end

        # @return [Pathname] the full path to the component's source file
        def file_path
          component.file_path
        end

        # @return [String] the component's source file path, relative to the
        #   container's root
        def relative_file_path
          Pathname(file_path).relative_path_from(component_dir.container.root).to_s
        end

        # @return [String] the component's final container key
        def key
          component.key
        end

        # @return [String] the component's const path
        def const_path
          component.const_path
        end

        # Returns the Ruby constant name the component's const path maps to, derived
        # with the component's own inflector (the same derivation {Loader.constant}
        # performs before constantizing)
        #
        # @return [String]
        def constant_name
          component.inflector.camelize(const_path)
        end

        # @return [Boolean]
        def registered?
          registration == :registered
        end

        # @return [Boolean]
        def excluded?
          registration == :excluded
        end

        # @return [Boolean]
        def undetermined_registration?
          registration == :undetermined
        end

        # @return [Boolean]
        def undetermined_constant_derivation?
          constant_derivation == :undetermined
        end

        # Returns a human-readable description of every transformation rule that
        # produced this entry's key and constant
        #
        # @return [Array<String>]
        def rules
          [
            "component dir #{component_dir.path.inspect}",
            namespace_rule,
            "file #{path_in_dir.inspect} maps to key #{key.inspect}",
            "const path #{const_path.inspect} camelizes to constant #{constant_name.inspect}",
            auto_register_rule
          ]
        end

        # @api private
        def constant_derivation_reason
          if component.options[:instance]
            "uses an instance proc, so the loader never resolves its constant"
          else
            "uses custom loader #{component.options[:loader].inspect}, "               "whose constant derivation cannot be determined statically"
          end
        end

        private

        def path_in_dir
          dir_full_path = component_dir.container.root.join(component_dir.path.to_s)
          Pathname(file_path).relative_path_from(dir_full_path).to_s
        end

        def namespace_rule
          namespace = component.namespace
          detail = "key: #{namespace.key.inspect}, const: #{namespace.const.inspect}"

          if namespace.root?
            "root namespace (#{detail})"
          else
            "namespace #{namespace.path.inspect} (#{detail})"
          end
        end

        def auto_register_rule
          option = component.options[:auto_register]

          source =
            if option.eql?(component_dir.config.auto_register)
              "component dir #{component_dir.path.inspect} configuration"
            else
              "magic comment in source file"
            end

          if option.respond_to?(:call)
            "auto_register: proc (evaluated at runtime, from #{source})"
          else
            "auto_register: #{option.inspect} (from #{source})"
          end
        end
      end

      # A collision between two or more component source files mapping to the same
      # container key or Ruby constant
      #
      # @api public
      class Collision
        # @return [Symbol] :key or :constant
        attr_reader :type

        # @return [String] the colliding key or constant name
        attr_reader :value

        # @return [Array<Entry>] the colliding entries
        attr_reader :entries

        # @return [Array<String>] reasons the collision could not be determined
        #   statically (empty for definite conflicts)
        attr_reader :reasons

        # @api private
        def initialize(type:, value:, entries:, reasons: [])
          @type = type
          @value = value
          @entries = entries
          @reasons = reasons
        end

        # @return [Boolean] true if this is a container key collision
        def key?
          type == :key
        end

        # @return [Boolean] true if this is a Ruby constant collision
        def constant?
          type == :constant
        end

        # @return [Array<Pathname>] the source files on both sides of the collision
        def files
          entries.map(&:file_path).uniq
        end

        # @api private
        def to_s
          lines = ["#{type} #{value.inspect} is mapped by #{files.length} files:"]

          entries.each do |entry|
            lines << "  - #{entry.relative_file_path}"
            entry.rules.each { |rule| lines << "      #{rule}" }
          end

          reasons.each { |reason| lines << "  undetermined: #{reason}" }

          lines.join("
")
        end
      end

      # The result of a {ConfigAudit}
      #
      # @api public
      class Report
        # @return [Array<Collision>] collisions certain to occur at runtime
        attr_reader :conflicts

        # @return [Array<Collision>] collisions that depend on runtime custom logic
        #   and cannot be determined statically
        attr_reader :undetermined

        # @api private
        def initialize(conflicts:, undetermined:)
          @conflicts = conflicts
          @undetermined = undetermined
        end

        # @return [Array<Collision>] all collisions, definite and undetermined
        def collisions
          conflicts + undetermined
        end

        # @return [Boolean] true if no collisions were found
        def clean?
          conflicts.empty? && undetermined.empty?
        end

        # @api private
        def to_s
          return "no collisions found" if clean?

          sections = []

          unless conflicts.empty?
            sections << (["definite conflicts:"] + conflicts.map(&:to_s)).join("
  ")
          end

          unless undetermined.empty?
            sections << (
              ["undetermined collisions (depend on runtime custom logic):"] +
              undetermined.map(&:to_s)
            ).join("
  ")
          end

          sections.join("

")
        end
      end

      # @return [Dry::System::Container] the container being audited
      attr_reader :container

      def initialize(container)
        @container = container
      end

      # Runs the audit and returns its report
      #
      # Enumerates the container's component dirs and builds components exactly as
      # {AutoRegistrar} does, then groups them by derived key and constant name.
      #
      # @return [Report]
      def call
        entries = container.component_dirs.flat_map { |component_dir|
          component_dir.each_component.map { |component|
            Entry.new(
              component: component,
              component_dir: component_dir,
              registration: registration_status(component, component_dir.config),
              constant_derivation: constant_derivation(component)
            )
          }
        }

        conflicts, undetermined = collisions(entries, :key, &:key)
        const_conflicts, const_undetermined = collisions(entries, :constant, &:constant_name)

        Report.new(
          conflicts: conflicts + const_conflicts,
          undetermined: undetermined + const_undetermined
        )
      end

      private

      # Whether auto registration would register the component, based on static
      # configuration only (dir-level policy and magic comments)
      def registration_status(component, dir_config)
        # AutoRegistrar skips dirs with a falsey auto_register policy entirely
        return :excluded unless dir_config.auto_register

        option = component.options[:auto_register]

        if option.respond_to?(:call)
          :undetermined
        elsif option
          :registered
        else
          :excluded
        end
      end

      # Whether the component's constant is derived by the standard {Loader.constant}
      # logic (and can therefore be determined statically)
      def constant_derivation(component)
        return :undetermined if component.options[:instance]

        loader = component.options[:loader]

        if loader.is_a?(Class) && loader <= Dry::System::Loader
          :standard
        else
          :undetermined
        end
      end

      # Groups entries by the given value and splits colliding groups into definite
      # conflicts and undetermined collisions
      def collisions(entries, type)
        participants = entries.reject(&:excluded?)
        groups = participants.group_by { |entry| yield entry }

        definite = []
        undetermined = []

        groups.each do |value, group|
          next unless group.map(&:file_path).uniq.length > 1

          certain = group.select { |entry| certain?(entry, type) }

          if certain.map(&:file_path).uniq.length > 1
            definite << Collision.new(type: type, value: value, entries: group)
          else
            undetermined << Collision.new(
              type: type,
              value: value,
              entries: group,
              reasons: undetermined_reasons(group, type)
            )
          end
        end

        [definite.sort_by(&:value), undetermined.sort_by(&:value)]
      end

      def certain?(entry, type)
        entry.registered? && (type == :key || !entry.undetermined_constant_derivation?)
      end

      def undetermined_reasons(group, type)
        group.each_with_object([]) { |entry, reasons|
          if entry.undetermined_registration?
            reasons <<
              "#{entry.relative_file_path}: auto_register policy is a proc evaluated at runtime"
          end

          if type == :constant && entry.undetermined_constant_derivation?
            reasons << "#{entry.relative_file_path}: #{entry.constant_derivation_reason}"
          end
        }
      end
    end
  end
end
