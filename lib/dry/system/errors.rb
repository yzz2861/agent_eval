# frozen_string_literal: true

module Dry
  module System
    # Error raised when import is called using a namespace that has already been
    # registered on the importing container
    #
    # @api public
    ImportNamespaceConflictError = Class.new(StandardError) do
      def initialize(namespace)
        ns = namespace.nil? ? "nil (root)" : namespace.inspect
        super("Import namespace #{ns} has already been registered")
      end
    end

    # Error raised when a borrowed component key is not included in the source
    # container's configured exports
    #
    # @api public
    BorrowNotExportedError = Class.new(StandardError) do
      def initialize(key:, source:, exports:)
        source_name = source.config.name ? source.config.name.inspect : source.inspect
        msg = +"Cannot borrow key #{key.inspect} from #{source_name}: it is not "
        msg << if exports
                 "included in the source container's exports (#{Array(exports).inspect})"
               else
                 "exported; the source container does not configure any exports"
               end
        super(msg)
      end
    end

    # Error raised when a borrowed component cannot be resolved because the source
    # container has not yet been started (finalized)
    #
    # @api public
    BorrowSourceNotStartedError = Class.new(StandardError) do
      def initialize(source)
        source_name = source.config.name ? source.config.name.inspect : source.inspect
        super("Cannot resolve borrowed component: source container #{source_name} has not been started")
      end
    end

    # Error raised when a borrowed component cannot be resolved because the source
    # container has been shut down
    #
    # @api public
    BorrowSourceShutdownError = Class.new(StandardError) do
      def initialize(source)
        source_name = source.config.name ? source.config.name.inspect : source.inspect
        super("Cannot resolve borrowed component: source container #{source_name} has been shut down")
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
