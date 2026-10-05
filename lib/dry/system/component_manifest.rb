# frozen_string_literal: true

require "json"
require "digest"
require "pathname"
require "set"

require "dry/system/errors"
require "dry/system/constants"

module Dry
  module System
    # A build-time manifest listing the components shipped in a package.
    #
    # The manifest records only static metadata for each component (its key, path
    # relative to the container root, expected constant name and a digest of the source
    # file). It never serializes component instances or executes any component or
    # provider.
    #
    # Before a listed component is required, the manifest is checked against the current
    # container: the root boundary, the naming configuration version and the individual
    # file digest must all match. These checks all happen before the component's source
    # file is required.
    #
    # @api public
    class ComponentManifest
      # @api private
      FORMAT_VERSION = 1

      # @api private
      DIGEST_ALGORITHM = "sha256"

      # Modes controlling how unlisted components are handled.
      #
      # - :manifest (strict): only components listed in the manifest are visible. No
      #   directory scanning is performed.
      # - :fallback_scan: listed components come from the manifest, while unlisted
      #   components are located by scanning the component dirs as usual.
      #
      # @api public
      MODES = %i[manifest fallback_scan].freeze

      # @!attribute [r] root
      #   @return [String] real path of the container root the manifest was built against
      #   @api public
      attr_reader :root

      # @!attribute [r] naming_version
      #   @return [String] digest of the naming configuration used to build the manifest
      #   @api public
      attr_reader :naming_version

      # @!attribute [r] mode
      #   @return [Symbol] mode for handling unlisted components
      #   @api public
      attr_reader :mode

      # @!attribute [r] generated_at
      #   @return [String] ISO-8601 timestamp of when the manifest was built
      #   @api public
      attr_reader :generated_at

      # @!attribute [r] entries
      #   @return [Hash{String => Entry}] entries keyed by component key
      #   @api public
      attr_reader :entries

      # @api private
      def initialize(root:, naming_version:, entries:, mode: :manifest, generated_at: nil,
                     digest_algorithm: DIGEST_ALGORITHM, format_version: FORMAT_VERSION)
        unless format_version == FORMAT_VERSION
          raise ComponentManifestInvalidError,
                "Unsupported component manifest format version " \
                "#{format_version.inspect} (expected #{FORMAT_VERSION})"
        end

        unless MODES.include?(mode)
          raise ComponentManifestInvalidError,
                "Unknown component manifest mode #{mode.inspect} " \
                "(expected one of #{MODES.map(&:inspect).join(", ")})"
        end

        @root = root
        @naming_version = naming_version
        @mode = mode
        @generated_at = generated_at
        @digest_algorithm = digest_algorithm
        @entries = entries
      end

      # @return [Boolean] true when unlisted components may be located by scanning
      # @api private
      def fallback_scan?
        mode == :fallback_scan
      end

      # @return [Entry, nil] the entry for the given component key
      # @api private
      def [](key)
        entries[key.to_s]
      end

      # Returns the entries belonging to a component dir, in manifest order
      #
      # @api private
      def entries_for_dir(dir_path)
        entries.values.select { |entry| entry.dir == dir_path.to_s }
      end

      # Checks the manifest's container-wide invariants against the given container.
      #
      # Raises before any component source file is required.
      #
      # @api private
      def verify!(container)
        verify_root!(container)
        verify_naming_version!(container)
        self
      end

      # Verifies an individual entry's source file: it must remain inside the root and
      # its digest must match. Raises before the file is required.
      #
      # @return [Entry] the verified entry
      # @api private
      def verify_entry!(entry)
        full_path = resolve(entry)

        unless within_root?(full_path)
          raise ComponentManifestBoundaryError.new(entry.path, root_path)
        end

        unless full_path.file?
          raise ComponentManifestDigestError.new(entry.path)
        end

        resolved_path =
          begin
            full_path.realpath
          rescue SystemCallError
            full_path
          end

        unless within_root?(resolved_path)
          raise ComponentManifestBoundaryError.new(entry.path, root_path)
        end

        unless digest(resolved_path) == entry.digest
          raise ComponentManifestDigestError.new(entry.path)
        end

        entry
      end

      # Resolves an entry to a full source file path inside the container root
      #
      # @api private
      def resolve(entry)
        root_path.join(entry.path)
      end

      # @return [Hash] a JSON-ready representation of the manifest
      # @api private
      def to_h
        {
          "format_version" => FORMAT_VERSION,
          "digest_algorithm" => @digest_algorithm,
          "root" => root,
          "naming_version" => naming_version,
          "mode" => mode.to_s,
          "generated_at" => generated_at,
          "components" => entries.values.map(&:to_h)
        }
      end

      # Builds a manifest for the container by enumerating its component dirs.
      #
      # This reads each source file only to calculate its digest and parse magic
      # comments; nothing is required, constantized, instantiated or started.
      #
      # @param container [Class] the configured container
      # @param component_dirs [Array<ComponentDir>] dirs to enumerate
      # @param mode [Symbol] mode persisted to the manifest
      #
      # @return [ComponentManifest]
      #
      # @api private
      def self.build(container, component_dirs: container.component_dirs(manifest: nil), mode: :manifest)
        unless MODES.include?(mode)
          raise ComponentManifestInvalidError,
                "Unknown component manifest mode #{mode.inspect} " \
                "(expected one of #{MODES.map(&:inspect).join(", ")})"
        end

        root = real_root(container)
        entries = {}

        component_dirs.each do |component_dir|
          component_dir.each_component do |component|
            scanned_path = component.file_path.expand_path(root)
            full_path =
              begin
                scanned_path.realpath
              rescue SystemCallError
                scanned_path
              end
            relative_path = relative_path(full_path, root)

            unless within?(full_path, root)
              raise ComponentManifestBoundaryError.new(relative_path, root)
            end

            entries[component.key] = Entry.new(
              key: component.key,
              dir: component_dir.path,
              namespace: namespace_payload(component.namespace),
              path: relative_path,
              const_name: component.inflector.camelize(component.const_path),
              digest: digest_of(full_path)
            )
          end
        end

        new(
          root: root.to_s,
          naming_version: naming_version_for(container),
          entries: entries,
          mode: mode,
          generated_at: Time.now.utc.iso8601
        )
      end

      # Loads and parses a manifest from a JSON file
      #
      # @api private
      def self.load(path)
        unless File.file?(path)
          raise ComponentManifestNotFoundError.new(path.to_s)
        end

        from_h(JSON.parse(File.read(path)))
      rescue JSON::ParserError => error
        raise ComponentManifestInvalidError,
              "Invalid component manifest at #{path.to_s.inspect}: #{error.message}"
      end

      # @api private
      def self.from_h(data)
        unless data.is_a?(Hash) && data["components"].is_a?(Array)
          raise ComponentManifestInvalidError,
                "Component manifest is missing a components list"
        end

        entries = {}
        data["components"].each do |raw|
          entry = Entry.from_h(raw)
          entries[entry.key] = entry
        end

        new(
          root: data.fetch("root"),
          naming_version: data.fetch("naming_version"),
          entries: entries,
          mode: (data["mode"] || "manifest").to_sym,
          generated_at: data["generated_at"],
          digest_algorithm: data["digest_algorithm"] || DIGEST_ALGORITHM,
          format_version: Integer(data.fetch("format_version", FORMAT_VERSION))
        )
      rescue KeyError => error
        raise ComponentManifestInvalidError,
              "Component manifest is missing #{error.message}"
      end

      # Calculates a fingerprint of the configuration that determines component key and
      # constant naming: the component dirs with their namespaces plus the inflector's
      # rules. Changing any of these invalidates the manifest.
      #
      # @api private
      def self.naming_version_for(container)
        payload = {
          "version" => FORMAT_VERSION,
          "dirs" => container.config.component_dirs.to_a.map { |dir|
            {
              "path" => dir.path,
              "namespaces" => dir.namespaces.to_a.map { |namespace|
                {
                  "path" => namespace.path,
                  "key" => namespace.key,
                  "const" => namespace.const
                }
              }
            }
          },
          "inflector" => inflector_rules(container.config.inflector)
        }

        Digest::SHA256.hexdigest(JSON.generate(payload))
      end

      # @api private
      def self.inflector_rules(inflector)
        inflections = inflector.instance_variable_get(:@inflections)

        %i[plurals singulars humans uncountables acronyms].map { |name|
          rules = inflections.instance_variable_get(:"@#{name}")

          serialized =
            case rules
            when Dry::Inflector::Rules
              rules.instance_variable_get(:@rules).map { |pattern, replacement|
                [pattern.source, pattern.options, replacement]
              }
            when Set
              rules.to_a
            when Dry::Inflector::Acronyms
              rules.instance_variable_get(:@rules)
            else
              rules
            end

          [name.to_s, serialized]
        }.to_h
      end

      # Static metadata for a single component
      #
      # @api public
      class Entry
        # @!attribute [r] key
        #   @return [String] component key
        # @!attribute [r] dir
        #   @return [String] component dir path, relative to the container root
        # @!attribute [r] path
        #   @return [String] source file path, relative to the container root
        # @!attribute [r] const_name
        #   @return [String] expected camelized constant name
        # @!attribute [r] digest
        #   @return [String] source file digest
        attr_reader :key, :dir, :path, :const_name, :digest

        # @!attribute [r] namespace
        #   @return [Hash{String => String,nil}] namespace path/key/const payload
        attr_reader :namespace

        # @api private
        def initialize(key:, dir:, namespace:, path:, const_name:, digest:)
          @key = key
          @dir = dir
          @namespace = namespace
          @path = path
          @const_name = const_name
          @digest = digest
        end

        # @return [Config::Namespace] the namespace reconstructed from manifest metadata
        # @api private
        def build_namespace
          Config::Namespace.new(
            path: namespace["path"],
            key: namespace["key"],
            const: namespace["const"]
          )
        end

        # @api private
        def to_h
          {
            "key" => key,
            "dir" => dir,
            "namespace" => namespace,
            "path" => path,
            "const_name" => const_name,
            "digest" => digest
          }
        end

        # @api private
        def self.from_h(data)
          required = %w[key dir namespace path const_name digest]

          unless data.is_a?(Hash) && required.all? { |field| data.key?(field) }
            raise ComponentManifestInvalidError,
                  "Component manifest entry is missing one of #{required.join(", ")}"
          end

          new(
            key: data.fetch("key"),
            dir: data.fetch("dir"),
            namespace: data.fetch("namespace"),
            path: data.fetch("path"),
            const_name: data.fetch("const_name"),
            digest: data.fetch("digest")
          )
        end
      end

      class << self
        private

        def real_root(container)
          Pathname(container.root).realpath
        end

        def namespace_payload(namespace)
          {"path" => namespace.path, "key" => namespace.key, "const" => namespace.const}
        end

        def relative_path(full_path, root)
          full_path.relative_path_from(root).to_s
        end

        def within?(path, root)
          path = path.expand_path(root)
          root = root.expand_path

          path.to_s.start_with?("#{root}#{File::SEPARATOR}") || path == root
        end

        def digest_of(path)
          Digest::SHA256.file(path.to_s).hexdigest
        end
      end

      private

      def verify_root!(container)
        actual_root = self.class.send(:real_root, container).to_s

        if actual_root != root
          raise ComponentManifestRootMismatchError.new(
            expected_root: root, actual_root: actual_root
          )
        end
      end

      def verify_naming_version!(container)
        actual_version = self.class.naming_version_for(container)

        if actual_version != naming_version
          raise ComponentManifestNamingVersionError.new(
            expected_version: naming_version, actual_version: actual_version
          )
        end
      end

      def digest(path)
        self.class.send(:digest_of, path)
      end

      def root_path
        @root_path ||= Pathname(root)
      end

      def within_root?(path)
        self.class.send(:within?, path, root_path)
      end
    end
  end
end
