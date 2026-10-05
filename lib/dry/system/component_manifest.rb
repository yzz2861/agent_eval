# frozen_string_literal: true

require "digest"
require "json"
require "pathname"

require "dry/system/component"
require "dry/system/constants"
require "dry/system/identifier"

module Dry
  module System
    # @api private
    class ComponentManifest
      FORMAT_VERSION = 1
      COMPONENT_FIELDS = %w[
        component_dir key relative_path require_path const_path const_name digest
      ].freeze

      attr_reader :format_version
      attr_reader :root_path
      attr_reader :naming_config_version
      attr_reader :components

      def self.build(container)
        components = container.component_dirs.flat_map { |component_dir|
          component_dir.each_component_from_files.map { |component|
            relative_path = component.file_path.relative_path_from(container.root).to_s
            next if container.config.component_manifest_path == relative_path

            const_path = component.const_path

            {
              "component_dir" => component_dir.path,
              "key" => component.key,
              "relative_path" => relative_path,
              "require_path" => component.require_path,
              "const_path" => const_path,
              "const_name" => component.inflector.camelize(const_path),
              "digest" => digest(component.file_path)
            }
          }
        }.compact

        new(
          root_path: container.root.expand_path.to_s,
          naming_config_version: naming_config_version_for(container),
          components: components
        )
      end

      def self.load(path)
        data = JSON.parse(File.read(path))

        new(
          format_version: data.fetch("format_version"),
          root_path: data.fetch("root_path"),
          naming_config_version: data.fetch("naming_config_version"),
          components: data.fetch("components")
        )
      rescue JSON::ParserError, KeyError => error
        raise ComponentManifestMalformedError.new(path: path, cause: error)
      rescue ComponentManifestError
        raise
      rescue StandardError => error
        raise ComponentManifestMalformedError.new(path: path, cause: error)
      end

      def self.digest(path)
        Digest::SHA256.file(path.to_s).hexdigest
      end

      def self.naming_config_version_for(container)
        inflector = container.config.inflector
        inflections = inflector.instance_variable_get(:@inflections)
        acronyms = inflections&.instance_variable_get(:@acronyms)&.instance_variable_get(:@rules) || {}
        namespaces = container.component_dirs.map { |component_dir|
          [
            component_dir.path,
            component_dir.config.namespaces.to_a.map { |namespace|
              [namespace.path, namespace.key, namespace.const]
            }
          ]
        }
        payload = [inflector.class.name, acronyms.sort, namespaces]

        Digest::SHA256.hexdigest(JSON.generate(payload))
      end

      def initialize(format_version: FORMAT_VERSION, root_path:, naming_config_version:, components:)
        unless format_version == FORMAT_VERSION
          raise ComponentManifestFormatVersionError.new(format_version, FORMAT_VERSION)
        end

        unless root_path.is_a?(String) && !root_path.empty?
          raise ComponentManifestMalformedError.new(
            path: nil,
            cause: ArgumentError.new("root_path must be a string")
          )
        end

        unless naming_config_version.is_a?(String) && !naming_config_version.empty?
          raise ComponentManifestMalformedError.new(
            path: nil,
            cause: ArgumentError.new("naming_config_version must be a string")
          )
        end

        unless components.is_a?(Array) && components.all?(Hash)
          raise ComponentManifestMalformedError.new(
            path: nil,
            cause: ArgumentError.new("components must be an array of hashes")
          )
        end

        @format_version = format_version
        @root_path = root_path
        @naming_config_version = naming_config_version
        @components = components.map { |component|
          component.transform_keys(&:to_s).tap { |entry|
            missing_fields = COMPONENT_FIELDS.reject { |field| entry[field].is_a?(String) }
            next if missing_fields.empty?

            raise ComponentManifestMalformedError.new(
              path: nil,
              cause: ArgumentError.new("missing component manifest fields: #{missing_fields.join(", ")}")
            )
          }.freeze
        }.freeze
        @verified = false
      end

      def each(&)
        components.each(&)
      end

      def find(component_dir_path, key)
        components.find { |component|
          component["component_dir"] == component_dir_path && component["key"] == key
        }
      end

      def verify!(container)
        verify_root!(container.root)
        verify_naming_config!(container)
        verify_components!(container)
        @verified = true
        self
      end

      def build_component(component_dir, entry)
        component_for(component_dir, entry)
      end

      def component_for(component_dir, entry)
        verify!(component_dir.container) unless @verified
        component_for_unverified(component_dir, entry)
      end

      def to_h
        {
          "format_version" => format_version,
          "root_path" => root_path,
          "naming_config_version" => naming_config_version,
          "components" => components
        }
      end

      def to_json(*args)
        JSON.pretty_generate(to_h, *args)
      end

      def write(path)
        File.write(path, to_json)
        self
      end

      private

      def verify_root!(root)
        current_root = root.expand_path
        manifest_root = Pathname(root_path).expand_path

        return if current_root == manifest_root

        raise ComponentManifestRootMismatchError.new(manifest_root, current_root)
      end

      def verify_naming_config!(container)
        current_version = self.class.naming_config_version_for(container)

        return if current_version == naming_config_version

        raise ComponentManifestNamingConfigError.new(naming_config_version, current_version)
      end

      def verify_components!(container)
        component_dirs = container.component_dirs.map { |dir| [dir.path, dir] }.to_h

        components.each do |entry|
          component_dir = component_dirs[entry.fetch("component_dir")]

          unless component_dir
            raise ComponentManifestComponentDirError.new(
              entry.fetch("key"), entry.fetch("component_dir")
            )
          end

          root = container.root.expand_path
          verify_component_dir_boundary!(root, component_dir)
          verified_entry(component_dir, root, entry)
        end
      end

      def component_for_unverified(component_dir, entry)
        root = component_dir.container.root.expand_path
        verify_component_dir_boundary!(root, component_dir)
        verified_entry(component_dir, root, entry)
        file_path = resolve_component_path(root, entry)
        component = component_dir.build_manifest_component(entry, file_path, component_dir.container.config.inflector)
        component
      end

      def verified_entry(component_dir, root, entry)
        file_path = resolve_component_path(root, entry)
        verify_boundary!(root, file_path)
        verify_require_path!(component_dir, entry, file_path)
        verify_file!(entry, file_path)
        verify_realpath_boundary!(root, file_path)
        verify_digest!(entry, file_path)
        verify_const_path!(component_dir, entry, file_path)
        verify_key!(component_dir, entry, file_path)
        verify_const_name!(component_dir, entry, file_path, component_dir.container.config.inflector)
      end

      def resolve_component_path(root, entry)
        relative_path = Pathname(entry.fetch("relative_path"))
        joined_path = root.join(relative_path)

        if relative_path.absolute? || relative_path.each_filename.to_a.include?("..")
          raise ComponentManifestBoundaryError.new(root, joined_path)
        end

        joined_path
      end

      def verify_boundary!(root, path)
        return if path.expand_path.to_s.start_with?("#{root}#{File::SEPARATOR}")

        raise ComponentManifestBoundaryError.new(root, path)
      end

      def verify_component_dir_boundary!(root, component_dir)
        path = component_dir.full_path.expand_path
        return if path == root || path.to_s.start_with?("#{root}#{File::SEPARATOR}")

        raise ComponentManifestBoundaryError.new(root, path)
      end

      def verify_realpath_boundary!(root, path)
        realpath = path.realpath
        return if realpath.to_s.start_with?("#{root}#{File::SEPARATOR}")

        raise ComponentManifestBoundaryError.new(root, path)
      rescue SystemCallError
        raise ComponentManifestBoundaryError.new(root, path)
      end

      def verify_require_path!(component_dir, entry, file_path)
        expected_path = file_path.relative_path_from(component_dir.full_path.expand_path).sub(RB_EXT, EMPTY_STRING).to_s
        require_path = entry.fetch("require_path")

        return if require_path == expected_path && !Pathname(require_path).each_filename.to_a.include?('..')

        raise ComponentManifestRequirePathError.new(entry.fetch("key"), require_path)
      end

      def verify_file!(entry, path)
        return if path.file?

        raise ComponentManifestComponentMissingError.new(entry.fetch("key"), path)
      end

      def verify_digest!(entry, path)
        current_digest = self.class.digest(path)
        expected_digest = entry.fetch("digest")

        return if current_digest == expected_digest

        raise ComponentManifestDigestMismatchError.new(
          entry.fetch("key"), path, expected_digest, current_digest
        )
      end

      def verify_const_name!(component_dir, entry, file_path, inflector)
        const_name = inflector.camelize(entry.fetch("const_path"))

        return if const_name == entry.fetch("const_name")

        raise ComponentManifestConstantNameError.new(entry.fetch("key"), entry.fetch("const_name"), const_name)
      end

      def verify_const_path!(component_dir, entry, file_path)
        relative_path = file_path.relative_path_from(component_dir.full_path.expand_path).to_s
        namespace = component_dir.namespace_for_relative_path(relative_path)
        const_path = component_dir.const_path_for_relative_path(relative_path, namespace)

        return if const_path == entry.fetch("const_path")

        raise ComponentManifestNamingConfigError.new(entry.fetch("const_path"), const_path)
      end

      def verify_key!(component_dir, entry, file_path)
        relative_path = file_path.relative_path_from(component_dir.full_path.expand_path).to_s
        namespace = component_dir.namespace_for_relative_path(relative_path)
        expected_key = component_dir.key_for_relative_path(relative_path, namespace)

        return if expected_key == entry.fetch("key")

        raise ComponentManifestNamingConfigError.new(entry.fetch("key"), expected_key)
      end
    end
  end
end
