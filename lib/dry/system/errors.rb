# frozen_string_literal: true

module Dry
  module System
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

    # Error raised when a provider declares a dependency on another provider that is
    # not registered.
    #
    # @api public
    ProviderDependencyNotFoundError = Class.new(ArgumentError) do
      # @api private
      def initialize(name, missing:)
        missing_list = Array(missing).map(&:inspect).join(", ")

        super(
          "Provider #{name.inspect} depends on provider(s) that are not registered: " \
          "#{missing_list}"
        )
      end
    end

    # Error raised when the explicit provider dependencies contain a cycle.
    #
    # @api public
    ProviderDependencyCycleError = Class.new(StandardError) do
      # @api private
      def initialize(cycle)
        chain = Array(cycle).map(&:to_s)
        chain << chain.first if chain.length > 1 && chain.last != chain.first

        super("Provider dependency cycle detected: #{chain.join(" -> ")}")
      end
    end

    # Error raised when one or more provider `stop` lifecycle steps raise while a
    # container is shutting down (or while providers started in a failed round are
    # being rolled back). All remaining providers are still given a chance to stop,
    # and every individual failure is collected here.
    #
    # @api public
    ProviderStopError = Class.new(StandardError) do
      # Returns a hash of provider name to the exception raised by its `stop` step.
      #
      # @return [Hash{Symbol => Exception}]
      #
      # @api public
      attr_reader :failures

      # @api private
      def initialize(failures)
        @failures = failures

        failure_list = failures.map { |name, error| "- #{name}: #{error.class}: #{error.message}" }

        super("Provider stop failed for #{failures.keys.map(&:inspect).join(", ")}:\n#{failure_list.join("\n")}")
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
