# frozen_string_literal: true

module Dry
  module System
    # Audits a container's component dir configuration without loading or executing
    # any component source files.
    #
    # The audit expands the configured component dirs, their namespaces and their
    # exclusion rules (auto_register policies and magic comments) to compute the final
    # container key and constant name for every component file, then reports any
    # collisions between files mapping to the same key or constant.
    #
    # Name derivation is shared with real auto-registration: components are built via
    # {ComponentDir#each_component} (the same enumeration used by {AutoRegistrar}),
    # and constant names are derived with the same inflector camelization used by
    # {Loader.constant}. No source file is ever required or executed.
    #
    # Collisions are reported as either:
    #
    # - **definite** - determined entirely by static configuration, or
    # - **indeterminate** - dependent on runtime custom logic (a callable
    #   auto_register policy, a custom instance proc or a custom loader), which
    #   cannot be evaluated without executing user code.
    #
    # @example
    #   report = MyApp.audit_config
    #   report.collisions? # => true
    #   puts report
    #
    # @see Container.audit_config
    #
    # @api public
    class ConfigAuditor
      # A single component file expanded from the container's configuration
      #
      # @api public
      class Entry
        # @!attribute [r] component
        #   @return [Dry::System::Component] the component for the file
        #   @api public
        attr_reader :component

        # @!attribute [r] component_dir
        #   @return [Dry::System::ComponentDir] the component dir containing the file
        #   @api public
        attr_reader :component_dir

        # @!attribute [r] constant_name
        #   @return [String] the fully qualified constant name derived for the file
        #   @api public
        attr_reader :constant_name

        # @!attribute [r] registration
        #   @return [Symbol] how the file's registration is determined:
        #     :registered (statically enabled), :excluded (statically disabled),
        #     :shadowed (key already registered in the container) or
        #     :dynamic (decided by a runtime auto_register proc)
        #   @api public
        attr_reader :registration

        # @!attribute [r] constant_resolution
        #   @return [Symbol] :default when the constant is resolved by the standard
        #     loader from the derived const path, or :custom when a custom
        #     instance proc or loader makes the resolution runtime-dependent
        #   @api public
        attr_reader :constant_resolution

        # @!attribute [r] rules
        #   @return [Array<String>] human-readable descriptions of the transformation
        #     rules (component dir, namespace mapping, inflector) that produced the
        #     key and constant for this file
        #   @api public
        attr_reader :rules

        # @api private
        def initialize(component:, component_dir:, constant_name:, registration:,
                       constant_resolution:, rules:)
          @component = component
          @component_dir = component_dir
          @constant_name = constant_name
          @registration = registration
          @constant_resolution = constant_resolution
          @rules = rules
        end

        # @see Component#key
        # @api public
        def key
          component.key
        end

        # @see Component#const_path
        # @api public
        def const_path
          component.const_path
        end

        # @see Component#file_path
        # @api public
        def file_path
          component.file_path
        end

        # @see Component#namespace
        # @api public
        def namespace
          component.namespace
        end

        # @api public
        def registered?
          registration == :registered
        end

        # @api public
        def excluded?
          registration == :excluded
        end

        # @api public
        def shadowed?
          registration == :shadowed
        end

        # @api public
        def dynamic?
          registration == :dynamic
        end
      end

      # A collision between two or more component files mapping to the same container
      # key or constant name
      #
      # @api public
      class Collision
        KIND_KEY = :key
        KIND_CONSTANT = :constant

        STATUS_DEFINITE = :definite
        STATUS_INDETERMINATE = :indeterminate

        # @!attribute [r] kind
        #   @return [Symbol] :key or :constant
        #   @api public
        attr_reader :kind

        # @!attribute [r] value
        #   @return [String] the colliding key or constant name
        #   @api public
        attr_reader :value

        # @!attribute [r] entries
        #   @return [Array<Entry>] the colliding files, with their transformation rules
        #   @api public
        attr_reader :entries

        # @!attribute [r] status
        #   @return [Symbol] :definite or :indeterminate
        #   @api public
        attr_reader :status

        # @api private
        def initialize(kind:, value:, entries:, status:)
          @kind = kind
          @value = value
          @entries = entries
          @status = status
        end

        # Returns true if the collision is determined entirely by static configuration
        #
        # @return [Boolean]
        #
        # @api public
        def definite?
          status == STATUS_DEFINITE
        end

        # Returns true if the collision depends on runtime custom logic (a callable
        # auto_register policy, custom instance proc or custom loader) and cannot be
        # determined statically
        #
        # @return [Boolean]
        #
        # @api public
        def indeterminate?
          !definite?
        end

        # Returns the source files on both sides of the collision
        #
        # @return [Array<Pathname>]
        #
        # @api public
        def files
          entries.map(&:file_path)
        end
      end

      # The result of a configuration audit
      #
      # @api public
      class Report
        # @!attribute [r] entries
        #   @return [Array<Entry>] every component file expanded from the configuration
        #   @api public
        attr_reader :entries

        # @!attribute [r] collisions
        #   @return [Array<Collision>] all detected collisions
        #   @api public
        attr_reader :collisions

        # @!attribute [r] skipped_component_dirs
        #   @return [Array<String>] paths of component dirs excluded from
        #     auto-registration entirely (dir-level auto_register = false)
        #   @api public
        attr_reader :skipped_component_dirs

        # @api private
        def initialize(entries:, collisions:, skipped_component_dirs:)
          @entries = entries
          @collisions = collisions
          @skipped_component_dirs = skipped_component_dirs
        end

        # @return [Boolean] whether any collisions were detected
        #
        # @api public
        def collisions?
          collisions.any?
        end

        # @return [Array<Collision>] collisions determined by static configuration
        #
        # @api public
        def definite_collisions
          collisions.select(&:definite?)
        end

        # @return [Array<Collision>] collisions dependent on runtime custom logic
        #
        # @api public
        def indeterminate_collisions
          collisions.select(&:indeterminate?)
        end

        # Returns a human-readable summary of the audit, listing both files and the
        # transformation rules involved for every collision
        #
        # @return [String]
        #
        # @api public
        def to_s
          return "No collisions found across #{entries.length} component files" unless collisions?

          collisions.map { |collision|
            lines = ["#{collision.kind} collision on #{collision.value.inspect} (#{collision.status}):"]

            collision.entries.each do |entry|
              lines << "  #{entry.file_path}"
              entry.rules.each { |rule| lines << "    - #{rule}" }
            end

            lines.join("\n")
          }.join("\n")
        end
      end

      # @api private
      attr_reader :container

      # @api private
      def initialize(container)
        @container = container
      end

      # Runs the audit and returns its report
      #
      # @return [Report]
      #
      # @api public
      def call
        entries = []
        skipped_component_dirs = []

        container.component_dirs.each do |component_dir|
          # Matches AutoRegistrar#finalize!: dirs with auto_register disabled are not
          # auto-registered at all
          if component_dir.auto_register?
            component_dir.each_component do |component|
              entries << build_entry(component_dir, component)
            end
          else
            skipped_component_dirs << component_dir.path
          end
        end

        Report.new(
          entries: entries,
          collisions: collisions(entries),
          skipped_component_dirs: skipped_component_dirs
        )
      end

      private

      def build_entry(component_dir, component)
        constant_name = component.inflector.camelize(component.const_path)

        Entry.new(
          component: component,
          component_dir: component_dir,
          constant_name: constant_name,
          registration: registration_for(component),
          constant_resolution: constant_resolution_for(component),
          rules: rules_for(component_dir, component, constant_name)
        )
      end

      # Mirrors the checks in AutoRegistrar#register_component?, without evaluating
      # any callable policy
      def registration_for(component)
        auto_register = component.options[:auto_register]

        if auto_register == false
          :excluded
        elsif container.registered?(component.key)
          :shadowed
        elsif auto_register.respond_to?(:call)
          :dynamic
        else
          :registered
        end
      end

      def constant_resolution_for(component)
        loader = component.options[:loader]

        if component.options[:instance].respond_to?(:call)
          :custom
        elsif loader.is_a?(Class) && loader <= Dry::System::Loader
          :default
        else
          :custom
        end
      end

      def rules_for(component_dir, component, constant_name)
        namespace = component.namespace
        dir_path = container.root.join(component_dir.path)
        relative_path = component.file_path.relative_path_from(dir_path)

        [
          "file #{relative_path} under component dir #{component_dir.path.inspect}",
          namespace_rule(namespace),
          "key #{component.key.inspect}",
          "const path #{component.const_path.inspect} camelized to constant #{constant_name.inspect}"
        ]
      end

      def namespace_rule(namespace)
        target = namespace.root? ? "root namespace" : "namespace #{namespace.path.inspect}"

        "#{target} (key: #{namespace.key.inspect}, const: #{namespace.const.inspect})"
      end

      def collisions(entries)
        key_collisions(entries) + constant_collisions(entries)
      end

      def key_collisions(entries)
        registrable = entries.reject { |entry| entry.excluded? || entry.shadowed? }

        registrable.group_by(&:key).filter_map { |key, group|
          next if group.length < 2

          status =
            if group.count(&:registered?) >= 2
              Collision::STATUS_DEFINITE
            else
              Collision::STATUS_INDETERMINATE
            end

          Collision.new(kind: Collision::KIND_KEY, value: key, entries: group, status: status)
        }
      end

      def constant_collisions(entries)
        entries.group_by(&:constant_name).filter_map { |constant_name, group|
          next if group.length < 2

          status =
            if group.all? { |entry| entry.constant_resolution == :default }
              Collision::STATUS_DEFINITE
            else
              Collision::STATUS_INDETERMINATE
            end

          Collision.new(kind: Collision::KIND_CONSTANT, value: constant_name, entries: group, status: status)
        }
      end
    end
  end
end
