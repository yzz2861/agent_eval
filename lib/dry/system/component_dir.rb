# frozen_string_literal: true

require "pathname"
require "dry/system/constants"

module Dry
  module System
    # A configured component directory within the container's root. Provides access to the
    # component directory's configuration, as well as methods for locating component files
    # within the directory
    #
    # @see Dry::System::Config::ComponentDir
    # @api private
    class ComponentDir
      # @!attribute [r] config
      #   @return [Dry::System::Config::ComponentDir] the component directory configuration
      #   @api private
      attr_reader :config

      # @!attribute [r] container
      #   @return [Dry::System::Container] the container managing the component directory
      #   @api private
      attr_reader :container

      # @api private
      # @!attribute [r] manifest
      #   @return [Dry::System::ComponentManifest, nil] the build-time component manifest
      #   @api private
      attr_reader :manifest

      # @api private
      def initialize(config:, container:, manifest: nil)
        @config = config
        @container = container
        @manifest = manifest
      end

      # Returns a component for the given key if a matching source file is found within
      # the component dir
      #
      # This searches according to the component dir's configured namespaces, in order of
      # definition, with the first match returned as the component.
      #
      # @param key [String] the component's key
      # @return [Dry::System::Component, nil] the component, if found
      #
      # @api private
      def component_for_key(key)
        if manifest
          entry = manifest.entries_for_dir(path).detect { |candidate| candidate.key == key }

          return build_manifest_component(entry) if entry
          return nil unless manifest.fallback_scan?
        end

        scan_component_for_key(key)
      end

      def each_component
        return enum_for(:each_component) unless block_given?

        if manifest
          manifest.entries_for_dir(path).each do |entry|
            yield build_manifest_component(manifest.verify_entry!(entry))
          end

          return unless manifest.fallback_scan?

          manifest_keys = manifest.entries_for_dir(path).map(&:key)

          each_file do |file_path, namespace|
            component = component_for_path(file_path, namespace)
            yield component unless manifest_keys.include?(component.key)
          end
        else
          each_file do |file_path, namespace|
            yield component_for_path(file_path, namespace)
          end
        end
      end

      private

      def scan_component_for_key(key)
        config.namespaces.each do |namespace|
          identifier = Identifier.new(key)

          next unless identifier.start_with?(namespace.key)

          if (file_path = find_component_file(identifier, namespace))
            return build_component(identifier, namespace, file_path)
          end
        end

        nil
      end

      def each_file
        return enum_for(:each_file) unless block_given?

        raise ComponentDirNotFoundError, full_path unless Dir.exist?(full_path)

        config.namespaces.each do |namespace|
          files(namespace).each do |file|
            yield file, namespace
          end
        end
      end

      def files(namespace)
        if namespace.path?
          ::Dir[::File.join(full_path, namespace.path, "**", RB_GLOB)]
        else
          non_root_paths = config.namespaces.to_a.reject(&:root?).map(&:path)

          ::Dir[::File.join(full_path, "**", RB_GLOB)].reject { |file_path|
            Pathname(file_path).relative_path_from(full_path).to_s.start_with?(*non_root_paths)
          }
        end
      end

      # Returns the full path of the component directory
      #
      # @return [Pathname]
      def full_path
        container.root.join(path)
      end

      # Returns a component for a full path to a Ruby source file within the component dir
      #
      # @param path [String] the full path to the file
      # @return [Dry::System::Component] the component
      def component_for_path(path, namespace)
        key = Pathname(path).relative_path_from(full_path).to_s
          .sub(RB_EXT, EMPTY_STRING)
          .scan(WORD_REGEX)
          .join(KEY_SEPARATOR)

        identifier = Identifier.new(key)
          .namespaced(
            from: namespace.path&.gsub(PATH_SEPARATOR, KEY_SEPARATOR),
            to: namespace.key
          )

        build_component(identifier, namespace, path)
      end

      def find_component_file(identifier, namespace)
        # To properly find the file within a namespace with a key, we should strip the key
        # from beginning of our given identifier
        if namespace.key
          identifier = identifier.namespaced(from: namespace.key, to: nil)
        end

        file_name = "#{identifier.key_with_separator(PATH_SEPARATOR)}#{RB_EXT}"

        component_file =
          if namespace.path?
            full_path.join(namespace.path, file_name)
          else
            full_path.join(file_name)
          end

        component_file if component_file.exist?
      end

      def build_component(identifier, namespace, file_path)
        options = {
          inflector: container.config.inflector,
          **component_options,
          **MagicCommentsParser.(file_path)
        }

        Component.new(
          identifier,
          namespace: namespace,
          file_path: file_path,
          **options
        )
      end

      def build_manifest_component(entry)
        # Verify the root boundary and the source file digest before the component's
        # source file is parsed or required
        file_path = manifest.resolve(manifest.verify_entry!(entry))

        identifier = Identifier.new(entry.key)
        namespace = entry.build_namespace

        Component.new(
          identifier,
          namespace: namespace,
          file_path: file_path,
          inflector: container.config.inflector,
          **component_options,
          **MagicCommentsParser.(file_path)
        ).tap do |component|
          current_const_name = component.inflector.camelize(component.const_path)

          if current_const_name != entry.const_name
            raise ComponentManifestConstNameError.new(
              key: entry.key,
              expected_const_name: entry.const_name,
              actual_const_name: current_const_name
            )
          end
        end
      end

      def component_options
        {
          auto_register: auto_register,
          loader: loader,
          instance: instance,
          memoize: memoize
        }
      end

      def method_missing(name, ...)
        if config.respond_to?(name)
          config.public_send(name, ...)
        else
          super
        end
      end

      def respond_to_missing?(name, include_all = false)
        config.respond_to?(name) || super
      end
    end
  end
end
