# frozen_string_literal: true

module Dry
  module System
    # Base error for problems with a build-time component manifest
    #
    # @api public
    ComponentManifestError = Class.new(StandardError)

    # Error raised when a component manifest file cannot be read or parsed
    #
    # @api public
    ComponentManifestNotFoundError = Class.new(ComponentManifestError) do
      def initialize(path)
        super("Component manifest not found: #{path.inspect}")
      end
    end

    # Error raised when a component manifest is malformed or uses an unsupported format
    #
    # @api public
    ComponentManifestInvalidError = Class.new(ComponentManifestError)

    # Error raised when a component manifest was built for a different container root
    #
    # @api public
    ComponentManifestRootMismatchError = Class.new(ComponentManifestError) do
      def initialize(expected_root:, actual_root:)
        super(
          "Component manifest root mismatch: " \
          "manifest was built for #{expected_root.inspect}, " \
          "container root is #{actual_root.inspect}"
        )
      end
    end

    # Error raised when a component manifest is stale relative to the naming
    # configuration (component dirs, namespaces or inflector rules)
    #
    # @api public
    ComponentManifestNamingVersionError = Class.new(ComponentManifestError) do
      def initialize(expected_version:, actual_version:)
        super(
          "Component manifest naming version mismatch: " \
          "manifest #{expected_version.inspect} does not match current configuration " \
          "#{actual_version.inspect}; regenerate the manifest after changing inflector " \
          "rules or component dir namespaces"
        )
      end
    end

    # Error raised when a component's source file lies outside the manifest's root
    #
    # @api public
    ComponentManifestBoundaryError = Class.new(ComponentManifestError) do
      def initialize(path, root)
        super(
          "Component manifest entry #{path.inspect} resolves outside the container " \
          "root #{root.to_s.inspect}"
        )
      end
    end

    # Error raised when a component's source file digest no longer matches the digest
    # recorded in the manifest
    #
    # @api public
    ComponentManifestDigestError = Class.new(ComponentManifestError) do
      def initialize(path)
        super(
          "Component manifest digest mismatch for #{path.inspect}: the file was " \
          "modified after the manifest was built; rebuild and publish a new manifest"
        )
      end
    end

    # Error raised when a component's expected constant name no longer matches the name
    # resolved from the current inflector and namespaces
    #
    # @api public
    ComponentManifestConstNameError = Class.new(ComponentManifestError) do
      def initialize(key:, expected_const_name:, actual_const_name:)
        super(
          "Component manifest constant name mismatch for #{key.inspect}: " \
          "manifest expects #{expected_const_name.inspect} but current naming " \
          "configuration resolves to #{actual_const_name.inspect}; regenerate the " \
          "manifest after changing inflector rules or namespaces"
        )
      end
    end

    # Error raised when import is called on an already finalized container
    #
    # @api public
    ContainerAlreadyFinalizedError = Class.new(StandardError)

    # Error raised when a component dir is added to configuration more than once
    #
    # @api public
    ComponentDirAlreadyAddedError = Class.new(StandardError) do
      def initialize(dir)
        super("Component directory #{dir.inspect} already added")
      end
    end

    # Error raised when a configured component directory could not be found
    #
    # @api public
    ComponentDirNotFoundError = Class.new(StandardError) do
      def initialize(dir)
        super("Component dir '#{dir}' not found")
      end
    end

    # Error raised when a namespace for a component dir is added to configuration more
    # than once
    #
    # @api public
    NamespaceAlreadyAddedError = Class.new(StandardError) do
      def initialize(path)
        path_label = path ? "path #{path.inspect}" : "root path"

        super("Namespace for #{path_label} already added")
      end
    end

    # Error raised when attempting to register provider using a name that has already been
    # registered
    #
    # @api public
    ProviderAlreadyRegisteredError = Class.new(ArgumentError) do
      def initialize(provider_name)
        super("Provider #{provider_name.inspect} has already been registered")
      end
    end

    # Error raised when a named provider could not be found
    #
    # @api public
    ProviderNotFoundError = Class.new(ArgumentError) do
      def initialize(name)
        super("Provider #{name.inspect} not found")
      end
    end

    # Error raised when a named provider source could not be found
    #
    # @api public
    ProviderSourceNotFoundError = Class.new(StandardError) do
      def initialize(name:, group:, keys:)
        msg = "Provider source not found: #{name.inspect}, group: #{group.inspect}"

        key_list = keys.map { |key| "- #{key[:name].inspect}, group: #{key[:group].inspect}" }
        msg += "Available provider sources:\n\n#{key_list}"

        super(msg)
      end
    end

    # Error raised when trying to use a plugin that does not exist.
    #
    # @api public
    PluginNotFoundError = Class.new(StandardError) do
      def initialize(plugin_name)
        super("Plugin #{plugin_name.inspect} does not exist")
      end
    end

    # Exception raise when a plugin dependency failed to load
    #
    # @api public
    PluginDependencyMissing = Class.new(StandardError) do
      # @api private
      def initialize(plugin, message, gem = nil)
        details = gem ? "#{message} - add #{gem} to your Gemfile" : message
        super("dry-system plugin #{plugin.inspect} failed to load its dependencies: #{details}")
      end
    end

    # Exception raised when auto-registerable component is not loadable
    #
    # @api public
    ComponentNotLoadableError = Class.new(NameError) do
      # @api private
      def initialize(component, error,
                     corrections: DidYouMean::ClassNameChecker.new(error).corrections)
        full_class_name = [error.receiver, error.name].join("::")

        message = [
          "Component '#{component.key}' is not loadable.",
          "Looking for #{full_class_name}."
        ]

        if corrections.any?
          case_correction = corrections.find { |correction| correction.casecmp?(full_class_name) }
          if case_correction
            acronyms_needed = case_correction.split("::").difference(full_class_name.split("::"))
            stringified_acronyms_needed = acronyms_needed.map { |acronym|
              "'#{acronym}'"
            } .join(", ")
            message <<
              <<~ERROR_MESSAGE

                You likely need to add:

                    acronym(#{stringified_acronyms_needed})

                to your container's inflector, since we found a #{case_correction} class.
              ERROR_MESSAGE
          else
            message << DidYouMean.formatter.message_for(corrections)
          end
        end

        super(message.join("\n"))
      end
    end
  end
end
