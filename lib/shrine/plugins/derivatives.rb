# frozen_string_literal: true

require "digest"

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/derivatives
    module Derivatives
      LOG_SUBSCRIBER = -> (event) do
        Shrine.logger.info "Derivatives (#{event.duration}ms) – #{{
          processor:         event[:processor],
          processor_options: event[:processor_options],
          uploader:          event[:uploader],
        }.inspect}"
      end

      def self.load_dependencies(uploader, **)
        uploader.plugin :default_url
      end

      def self.configure(uploader, log_subscriber: LOG_SUBSCRIBER, versions_compatibility: false, **opts)
        uploader.opts[:derivatives] ||= { processors: {}, processor_settings: {}, storage: proc { store_key }, mutex: true }
        uploader.opts[:derivatives].merge!(opts)

        # instrumentation plugin integration
        uploader.subscribe(:derivatives, &log_subscriber) if uploader.respond_to?(:subscribe)

        uploader::Attacher.include(VersionsCompatibility) if versions_compatibility
      end

      module AttachmentMethods
        def define_entity_methods(name)
          super if defined?(super)

          define_method(:"#{name}_derivatives") do |*args|
            send(:"#{name}_attacher").get_derivatives(*args)
          end
        end

        def define_model_methods(name)
          super if defined?(super)

          define_method(:"#{name}_derivatives!") do |*args, **options|
            send(:"#{name}_attacher").create_derivatives(*args, **options)
          end
        end
      end

      module AttacherClassMethods
        # Registers a derivatives processor on the attacher class.
        #
        #     Attacher.derivatives_processor :thumbnails do |original|
        #       # ...
        #     end
        #
        # By default, Shrine will convert the source IO object into a file
        # before it's passed to the processor block. You can set `download:
        # false` to pass the source IO object to the processor block as is.
        #
        #     Attacher.derivatives_processor :thumbnails, download: false do |original|
        #       # ...
        #     end
        #
        # This can be useful if you'd like to defer or avoid a possibly
        # expensive download operation for processor logic that does not
        # require it.
        #
        # A processor can declare an explicit recipe version and a list of
        # other derivative nodes it depends on. This makes it eligible for
        # incremental rebuilds via Attacher#rebuild_derivatives: the node is
        # rebuilt only when the source changes, its recipe version changes,
        # or one of its dependencies produces different results.
        #
        #     Attacher.derivatives_processor :large, version: 2 do |original|
        #       { large: processor.resize_to_limit!(800, 800) }
        #     end
        #
        #     Attacher.derivatives_processor :small, version: 1, depends: [:large] do |original, large:|
        #       { small: processor.source(large[:large]).resize_to_limit!(300, 300) }
        #     end
        def derivatives_processor(name = :default, download: true, version: nil, depends: nil, &block)
          if block
            settings = { download: download }
            settings[:version]    = version.to_s if version
            settings[:depends]    = Array(depends).map(&:to_sym) if depends

            shrine_class.derivatives_options[:processors][name.to_sym] = block
            shrine_class.derivatives_options[:processor_settings][name.to_sym] = settings
          else
            shrine_class.derivatives_options[:processors].fetch(name.to_sym) do
              fail Error, "derivatives processor #{name.inspect} not registered" unless name == :default
            end
          end
        end
        alias derivatives derivatives_processor

        # Returns settings for the given derivatives processor.
        #
        #     Attacher.derivatives_processor_settings(:thumbnails) #=> { download: true }
        def derivatives_processor_settings(name)
          shrine_class.derivatives_options[:processor_settings][name.to_sym] || {}
        end

        # Specifies default storage to which derivatives will be uploaded.
        #
        #     Attacher.derivatives_storage :other_store
        #     # or
        #     Attacher.derivatives_storage do |name|
        #       if name == :thumbnail
        #         :thumbnail_store
        #       else
        #         :store
        #       end
        #     end
        def derivatives_storage(storage_key = nil, &block)
          if storage_key || block
            shrine_class.derivatives_options[:storage] = storage_key || block
          else
            shrine_class.derivatives_options[:storage]
          end
        end
      end

      module AttacherMethods
        attr_reader :derivatives, :derivatives_manifest

        # Adds the ability to accept derivatives.
        def initialize(derivatives: {}, derivatives_manifest: {}, **options)
          super(**options)

          @derivatives          = derivatives
          @derivatives_manifest = derivatives_manifest
          @derivatives_mutex = Mutex.new if shrine_class.derivatives_options[:mutex]
        end

        # Convenience method for accessing derivatives.
        #
        #     photo.image_derivatives[:thumb] #=> #<Shrine::UploadedFile>
        #     # can be shortened to
        #     photo.image(:thumb) #=> #<Shrine::UploadedFile>
        def get(*path)
          return super if path.empty?

          get_derivatives(*path)
        end

        # Convenience method for accessing derivatives.
        #
        #     photo.image_derivatives.dig(:thumbnails, :large)
        #     # can be shortened to
        #     photo.image_derivatives(:thumbnails, :large)
        def get_derivatives(*path)
          return derivatives if path.empty?

          path = derivative_path(path)

          derivatives.dig(*path)
        end

        # Allows generating a URL to the derivative by passing the derivative
        # name.
        #
        #     attacher.add_derivatives({ thumb: thumb })
        #     attacher.url(:thumb) #=> "https://example.org/thumb.jpg"
        def url(*path, **options)
          return super if path.empty?

          path = derivative_path(path)

          url   = derivatives.dig(*path)&.url(**options)
          url ||= default_url(**options, derivative: path)
          url
        end

        # In addition to promoting the main file, also promotes any cached
        # derivatives. This is useful when these derivatives are being created
        # as part of a direct upload.
        #
        #     attacher.assign(io)
        #     attacher.add_derivative(:thumb, file, storage: :cache)
        #     attacher.promote
        #     attacher.stored?(attacher.derivatives[:thumb]) #=> true
        def promote(**options)
          super
          promote_derivatives(**options)
          create_derivatives if create_derivatives_on_promote?
        end

        # Uploads any cached derivatives to permanent storage.
        def promote_derivatives(**options)
          stored_derivatives = map_derivative(derivatives) do |path, derivative|
            if cached?(derivative)
              upload_derivative(path, derivative, **options)
            else
              derivative
            end
          end

          set_derivatives(stored_derivatives) unless derivatives == stored_derivatives
        end

        # In addition to deleting the main file it also deletes any derivatives.
        #
        #     attacher.add_derivatives({ thumb: thumb })
        #     attacher.derivatives[:thumb].exists? #=> true
        #     attacher.destroy
        #     attacher.derivatives[:thumb].exists? #=> false
        def destroy
          super
          delete_derivatives
        end

        # Calls processor and adds returned derivatives.
        #
        #     Attacher.derivatives_processor :my_processor do |original|
        #       # ...
        #     end
        #
        #     attacher.create_derivatives(:my_processor)
        def create_derivatives(*args, storage: nil, **options)
          files = process_derivatives(*args, **options)
          add_derivatives(files, storage: storage)
        end

        # Rebuilds derivative nodes according to the graph declared with
        # `version:` and `depends:` on their processors.
        #
        # A node is rebuilt only when it is affected since the last rebuild,
        # i.e. when:
        #
        #   * it has never been built for the current source,
        #   * the source file identity changed,
        #   * the processor's recipe version changed, or
        #   * one of its dependencies was rebuilt and produced new results.
        #
        # Dependencies are processed in topological order, and rebuilt nodes
        # receive each dependency's uploaded derivatives hash as a keyword
        # argument named after the dependency.
        #
        #     Attacher.derivatives_processor :large, version: 1 do |original|
        #       { large: StringIO.new(original.read.upcase) }
        #     end
        #
        #     Attacher.derivatives_processor :small, version: 1, depends: [:large] do |original, large:|
        #       { small: StringIO.new(large[:large].read.downcase) }
        #     end
        #
        #     attacher.attach(StringIO.new("content"))
        #     attacher.rebuild_derivatives
        #     #=> { large: ..., small: ... }
        #
        # Only the requested nodes (and their transitive dependencies) are
        # considered; by default every registered processor is considered.
        # Returns a Hash of newly built derivatives (empty when nothing was
        # affected). New results are published as a group: previously stored
        # derivatives stay available until the whole batch is ready, and if a
        # processor fails, the files uploaded during this run are deleted
        # while existing derivatives are left untouched.
        def rebuild_derivatives(*node_names, source: nil, force: false, storage: nil, **options)
          node_names = derivative_node_names if node_names.empty?
          node_names = node_names.map(&:to_sym)

          source    ||= file!
          source_id   = derivative_source_identity(source)
          staged      = {}
          order       = derivative_node_order(node_names)

          rebuilt      = []
          new_manifest = {}

          build_node = -> (node_name, settings) do
            dependencies = settings[:depends] || []
            inputs       = derivative_dependency_inputs(staged, dependencies)

            node_files = begin
              process_derivatives(node_name, source, **inputs, **options)
            ensure
              inputs.each_value { |outputs| rewind_derivative_uploads(outputs) }
            end
            uploaded  = upload_derivatives(node_files, storage: storage)

            staged[node_name] = uploaded
            rebuilt          << node_name
            new_manifest[node_name.to_s] = {
              "source"    => source_id,
              "version"   => (settings[:version] || "").to_s,
              "depends"   => derivative_dependency_signatures(dependencies, new_manifest),
              "outputs"   => derivative_output_paths(uploaded),
              "signature" => derivative_output_signature(uploaded),
            }

            uploaded
          end

          order.each do |node_name|
            settings      = self.class.derivatives_processor_settings(node_name)
            dependencies  = settings[:depends] || []
            direct_dirty =
              (force && node_names.include?(node_name)) ||
                !derivative_manifest_fresh?(node_name, settings, source_id)

            if direct_dirty
              build_node.call(node_name, settings)
            else
              stale_dependency = dependencies.any? do |dependency|
                next false unless rebuilt.include?(dependency)

                expected = derivatives_manifest.dig(node_name.to_s, "depends", dependency.to_s)
                current  = new_manifest.dig(dependency.to_s, "signature")

                expected != current
              end

              build_node.call(node_name, settings) if stale_dependency
            end
          end

          publish_derivative_rebuild(staged, rebuilt, new_manifest)
        rescue => error
          cleanup_staged_derivatives(staged)
          raise error
        end

        # Computes the rebuild set without executing any processors, based on
        # the source file identity, declared recipe versions and the results
        # the nodes were built from.
        #
        #     attacher.derivative_rebuild_plan
        #     #=> { nodes: [:large, :small], rebuild: [:large] }
        #
        # Cascading rebuilds caused by changed dependency results can only be
        # observed after those dependencies are rebuilt; the returned plan
        # covers the directly affected nodes.
        def derivative_rebuild_plan(*node_names, source: nil, force: false)
          node_names = derivative_node_names if node_names.empty?
          node_names = node_names.map(&:to_sym)

          source ||= file!

          order   = derivative_node_order(node_names)
          rebuild = order.select do |node_name|
            settings = self.class.derivatives_processor_settings(node_name)

            (force && node_names.include?(node_name)) ||
              !derivative_manifest_fresh?(
                node_name, settings, derivative_source_identity(source),
              )
          end

          { nodes: order, rebuild: rebuild }
        end

        # Uploads given hash of files and adds uploaded files to the
        # derivatives hash.
        #
        #     attacher.derivatives #=>
        #     # {
        #     #   thumb: #<Shrine::UploadedFile>,
        #     # }
        #     attacher.add_derivatives({ cropped: cropped })
        #     attacher.derivatives #=>
        #     # {
        #     #   thumb: #<Shrine::UploadedFile>,
        #     #   cropped: #<Shrine::UploadedFile>,
        #     # }
        def add_derivatives(files, **options)
          new_derivatives = upload_derivatives(files, **options)
          merge_derivatives(new_derivatives)
          new_derivatives
        end

        # Uploads a given file and adds it to the derivatives hash.
        #
        #     attacher.derivatives #=>
        #     # {
        #     #   thumb: #<Shrine::UploadedFile>,
        #     # }
        #     attacher.add_derivative(:cropped, cropped)
        #     attacher.derivatives #=>
        #     # {
        #     #   thumb: #<Shrine::UploadedFile>,
        #     #   cropped: #<Shrine::UploadedFile>,
        #     # }
        def add_derivative(name, file, **options)
          add_derivatives({ name => file }, **options)
          derivatives[name]
        end

        # Uploads given hash of files.
        #
        #     hash = attacher.upload_derivatives({ thumb: thumb })
        #     hash[:thumb] #=> #<Shrine::UploadedFile>
        def upload_derivatives(files, **options)
          map_derivative(files) do |path, file|
            upload_derivative(path, file, **options)
          end
        end

        # Uploads the given file and deletes it afterwards.
        #
        #     hash = attacher.upload_derivative(:thumb, thumb)
        #     hash[:thumb] #=> #<Shrine::UploadedFile>
        def upload_derivative(path, file, storage: nil, **options)
          path      = derivative_path(path)
          storage ||= derivative_storage(path)

          file.open    if file.is_a?(Tempfile)       # refresh file descriptor
          file.binmode if file.respond_to?(:binmode) # ensure binary mode

          upload(file, storage, derivative: path, delete: true, action: :derivatives, **options)
        end

        # Downloads the attached file and calls the specified processor.
        #
        #     Attacher.derivatives_processor :thumbnails do |original|
        #       processor = ImageProcessing::MiniMagick.source(original)
        #
        #       {
        #         small:  processor.resize_to_limit!(300, 300),
        #         medium: processor.resize_to_limit!(500, 500),
        #         large:  processor.resize_to_limit!(800, 800),
        #       }
        #     end
        #
        #     attacher.process_derivatives(:thumbnails)
        #     #=> { small: #<File:...>, medium: #<File:...>, large: #<File:...> }
        def process_derivatives(processor_name = :default, source = nil, **options)
          # handle receiving only source file without a processor
          unless processor_name.respond_to?(:to_sym)
            source         = processor_name
            processor_name = :default
          end

          source ||= file!

          processor_settings = self.class.derivatives_processor_settings(processor_name) || {}

          if processor_settings[:download]
            shrine_class.with_file(source) do |file|
              _process_derivatives(processor_name, file, **options)
            end
          else
            _process_derivatives(processor_name, source, **options)
          end
        end

        # Deep merges given uploaded derivatives with current derivatives.
        #
        #     attacher.derivatives #=> { one: #<Shrine::UploadedFile> }
        #     attacher.merge_derivatives({ two: uploaded_file })
        #     attacher.derivatives #=> { one: #<Shrine::UploadedFile>, two: #<Shrine::UploadedFile> }
        def merge_derivatives(new_derivatives)
          derivatives_synchronize do
            merged_derivatives = deep_merge_derivatives(derivatives, new_derivatives)
            set_derivatives(merged_derivatives)
          end
        end

        # Removes derivatives with specified name from the derivatives hash.
        #
        #     attacher.derivatives
        #     #=> { one: #<Shrine::UploadedFile>, two: #<Shrine::UploadedFile>, three: #<Shrine::UploadedFile> }
        #
        #     attacher.remove_derivatives(:two, :three)
        #     #=> [#<Shrine::UploadedFile>, #<Shrine::UploadedFile>] (removed derivatives)
        #
        #     attacher.derivatives
        #     #=> { one: #<Shrine::UploadedFile> }
        #
        # Nested derivatives are also supported:
        #
        #     attacher.derivatives
        #     #=> { nested: { one: #<Shrine::UploadedFile>, two: #<Shrine::UploadedFile>, three: #<Shrine::UploadedFile> } }
        #
        #     attacher.remove_derivatives([:nested, :two], [:nested, :three])
        #     #=> [#<Shrine::UploadedFile>, #<Shrine::UploadedFile>] (removed derivatives)
        #
        #     attacher.derivatives
        #     #=> { nested: { one: #<Shrine::UploadedFile> } }
        #
        # The :delete option can be passed for deleting removed derivatives:
        #
        #     attacher.derivatives
        #     #=> { one: #<Shrine::UploadedFile>, two: #<Shrine::UploadedFile>, three: #<Shrine::UploadedFile> }
        #
        #     two, three = attacher.remove_derivatives(:two, :three, delete: true)
        #
        #     two.exists?   #=> false
        #     three.exists? #=> false
        def remove_derivatives(*paths, delete: false)
          removed_derivatives = paths.map do |path|
            path = Array(path)

            if path.one?
              derivatives.delete(path.first)
            else
              derivatives.dig(*path[0..-2]).delete(path[-1])
            end
          end

          set_derivatives derivatives

          delete_derivatives(removed_derivatives) if delete

          removed_derivatives
        end

        # Removes derivative with specified name from the derivatives hash.
        #
        #     attacher.derivatives #=> { one: #<Shrine::UploadedFile>, two: #<Shrine::UploadedFile> }
        #     attacher.remove_derivative(:one) #=> #<Shrine::UploadedFile> (removed derivative)
        #     attacher.derivatives #=> { two: #<Shrine::UploadedFile> }
        #
        # Nested derivatives are also supported:
        #
        #     attacher.derivatives #=> { nested: { one: #<Shrine::UploadedFile>, two: #<Shrine::UploadedFile> } }
        #     attacher.remove_derivative([:nested, :one]) #=> #<Shrine::UploadedFile> (removed derivative)
        #     attacher.derivatives #=> { nested: { one: #<Shrine::UploadedFile> } }
        #
        # The :delete option can be passed for deleting removed derivative:
        #
        #     attacher.derivatives #=> { one: #<Shrine::UploadedFile>, two: #<Shrine::UploadedFile> }
        #     derivative = attacher.remove_derivatives(:two, delete: true)
        #     derivative.exists? #=> false
        def remove_derivative(path, **options)
          remove_derivatives(path, **options).first
        end

        # Deletes given hash of uploaded files.
        #
        #     attacher.delete_derivatives({ thumb: uploaded_file })
        #     uploaded_file.exists? #=> false
        def delete_derivatives(derivatives = self.derivatives)
          map_derivative(derivatives) { |_, derivative| derivative.delete }
        end

        # Sets the given hash of uploaded files as derivatives.
        #
        #     attacher.set_derivatives({ thumb: uploaded_file })
        #     attacher.derivatives #=> { thumb: #<Shrine::UploadedFile> }
        def set_derivatives(derivatives)
          self.derivatives = derivatives
          set file # trigger model write
          derivatives
        end

        # Adds derivative data into the hash.
        #
        #     attacher.attach(io)
        #     attacher.add_derivatives({ thumb: thumb })
        #     attacher.data
        #     #=>
        #     # {
        #     #   "id" => "...",
        #     #   "storage" => "store",
        #     #   "metadata" => { ... },
        #     #   "derivatives" => {
        #     #     "thumb" => {
        #     #       "id" => "...",
        #     #       "storage" => "store",
        #     #       "metadata" => { ... },
        #     #     }
        #     #   }
        #     # }
        def data
          result = super

          if derivatives.any?
            result ||= {}
            result["derivatives"] = map_derivative(derivatives, transform_keys: :to_s) do |_, derivative|
              derivative.data
            end
          end

          if derivatives_manifest.any?
            result ||= {}
            result["derivatives_manifest"] = JSON.parse(JSON.generate(derivatives_manifest))
          end

          result
        end

        # Loads derivatives from data generated by `Attacher#data`.
        #
        #     attacher.load_data({
        #       "id" => "...",
        #       "storage" => "store",
        #       "metadata" => {},
        #       "derivatives" => {
        #         "thumb" => {
        #           "id" => "...",
        #           "storage" => "store",
        #           "metadata" => {},
        #         }
        #       }
        #     })
        #     attacher.file        #=> #<Shrine::UploadedFile>
        #     attacher.derivatives #=> { thumb: #<Shrine::UploadedFile> }
        def load_data(data)
          data ||= {}
          data   = data.dup

          derivatives_data  = data.delete("derivatives") || data.delete(:derivatives) || {}
          manifest_data     = data.delete("derivatives_manifest") || data.delete("derivatives_manifest".to_sym) || {}
          @derivatives       = shrine_class.derivatives(derivatives_data)
          @derivatives_manifest = manifest_data

          data = nil if data.empty?

          super(data)
        end

        # Clears derivatives when attachment changes.
        #
        #     attacher.derivatives #=> { thumb: #<Shrine::UploadedFile> }
        #     attacher.change(file)
        #     attacher.derivatives #=> {}
        #
        #     # With keep_derivatives: true
        #     attacher.change(file)
        #     attacher.derivatives #=> { thumb: #<Shrine::UploadedFile> }
        def change(*)
          result = super
          unless shrine_class.derivatives_options[:keep_derivatives]
            @derivatives_manifest = {}
            set_derivatives({})
          end
          result
        end

        # Sets a hash of derivatives.
        #
        #     attacher.derivatives = { thumb: Shrine.uploaded_file(data) }
        #     attacher.derivatives #=> { thumb: #<Shrine::UploadedFile ...> }
        def derivatives=(derivatives)
          unless derivatives.is_a?(Hash)
            fail ArgumentError, "expected derivatives to be a Hash, got #{derivatives.inspect}"
          end

          @derivatives = derivatives
        end

        # Iterates through nested derivatives and maps results.
        #
        #     attacher.map_derivative(derivatives) do |path, file|
        #       # ...
        #     end
        def map_derivative(derivatives, **options, &block)
          shrine_class.map_derivative(derivatives, **options, &block)
        end

        private

        # All processors that have been registered as graph nodes.
        def derivative_node_names
          shrine_class.derivatives_options[:processors].keys
        end

        # Returns the nodes in dependency-first topological order, restricted
        # to the requested nodes and their transitive dependencies.
        def derivative_node_order(node_names)
          selected = {}

          select_node = lambda do |node_name|
            unless shrine_class.derivatives_options[:processors].key?(node_name)
              fail Error, "derivatives processor #{node_name.inspect} not registered"
            end

            return if selected[node_name]

            selected[node_name] = true

            dependencies = self.class.derivatives_processor_settings(node_name)[:depends] || []
            dependencies.each { |dependency| select_node.call(dependency) }
          end

          node_names.each { |node_name| select_node.call(node_name) }

          order   = []
          visited = {}

          visit_node = lambda do |node_name, stack:|
            case visited[node_name]
            when :in_progress
              cycle = [*stack, node_name].map(&:inspect).join(" -> ")
              fail Error, "cyclic derivative node dependency detected: #{cycle}"
            when :done
              return
            end

            visited[node_name] = :in_progress

            dependencies = self.class.derivatives_processor_settings(node_name)[:depends] || []
            dependencies.each do |dependency|
              visit_node.call(dependency, stack: [*stack, node_name])
            end

            visited[node_name] = :done
            order << node_name
          end

          selected.each_key { |node_name| visit_node.call(node_name, stack: []) }

          order
        end

        # Stable identity of the file a set of derivatives is based on.
        def derivative_source_identity(source)
          if source.respond_to?(:storage_key) && source.respond_to?(:id)
            "#{source.storage_key}/#{source.id}"
          else
            Digest::SHA1.hexdigest(source.read.to_s).tap { source.rewind if source.respond_to?(:rewind) }
          end
        end

        # Whether a node's manifest entry still matches the current source and
        # recipe and points to the same dependency results.
        def derivative_manifest_fresh?(node_name, settings, source_id)
          entry = derivatives_manifest[node_name.to_s]

          return false unless entry.is_a?(Hash)
          return false unless entry["source"]  == source_id
          return false unless entry["version"] == (settings[:version] || "").to_s

          (settings[:depends] || []).each do |dependency|
            return false unless entry.dig("depends", dependency.to_s) ==
              derivatives_manifest.dig(dependency.to_s, "signature")
          end

          true
        end

        # Builds the keyword arguments carrying each dependency's uploaded
        # derivatives hash.
        def derivative_dependency_inputs(staged, dependencies)
          dependencies.each_with_object({}) do |dependency, inputs|
            outputs = staged[dependency] || extract_node_derivatives(dependency)

            unless outputs
              fail Error, "derivative node #{dependency.inspect} has no results to depend on"
            end

            inputs[dependency] = rewind_derivative_uploads(outputs)
          end
        end

        # Rewinds uploaded derivatives before handing them to a dependent
        # processor, so a freshly built dependency is readable even though
        # its IO was consumed during the upload.
        def rewind_derivative_uploads(object)
          map_derivative(object) do |_, derivative|
            derivative.close if derivative.respond_to?(:opened?) && derivative.opened?
            derivative
          end
        end

        # Reads a node's previously published derivatives from the hash using
        # the output paths recorded in its manifest entry.
        def extract_node_derivatives(node_name)
          paths = derivatives_manifest.dig(node_name.to_s, "outputs")

          return nil unless paths.is_a?(Array) && paths.any?

          paths.each_with_object({}) do |path, extracted|
            lookup_path = path.map { |key| key.is_a?(String) ? key.to_sym : key }
            value = derivatives.dig(*lookup_path)
            next unless value

            set_derivative_path(extracted, lookup_path, value)
          end
        end

        # Assigns a value at the given path within a nested hash.
        def set_derivative_path(hash, path, value)
          key = path.first

          if path.one?
            hash[key] = value
          else
            set_derivative_path(hash[key] ||= {}, path[1..], value)
          end
        end

        # Lists the leaf paths contained in a node's output hash. Paths are
        # stored as arrays so that nested derivatives survive serialization.
        def derivative_output_paths(uploaded)
          paths = []

          collect_leaves = lambda do |object, path|
            if object.is_a?(Hash)
              object.each { |key, value| collect_leaves.call(value, [*path, key]) }
            elsif object.is_a?(Array)
              object.each_with_index { |value, index| collect_leaves.call(value, [*path, index]) }
            else
              paths << path
            end
          end

          collect_leaves.call(uploaded, [])
          paths.map { |path| path.map { |key| key.is_a?(Symbol) ? key.to_s : key } }
        end

        # Signatures of the dependencies a newly built node consumed.
        def derivative_dependency_signatures(dependencies, new_manifest)
          dependencies.each_with_object({}) do |dependency, signatures|
            signature =
              new_manifest.dig(dependency.to_s, "signature") ||
              derivatives_manifest.dig(dependency.to_s, "signature")

            signatures[dependency.to_s] = signature
          end
        end

        # Deterministic, content-based signature of a node's uploaded
        # derivatives. Re-processing a node that produces identical content
        # therefore doesn't force its dependents to rebuild.
        def derivative_output_signature(uploaded)
          leaves = []

          collect_leaves = lambda do |object, path|
            if object.is_a?(Hash)
              object.each { |key, value| collect_leaves.call(value, [*path, key.to_s]) }
            elsif object.is_a?(Array)
              object.each_with_index { |value, index| collect_leaves.call(value, [*path, index.to_s]) }
            else
              leaves << [path, object.storage_key.to_s, derivative_file_digest(object)]
            end
          end

          collect_leaves.call(uploaded, [])

          Digest::SHA1.hexdigest(leaves.map(&:inspect).join("\n"))
        end

        # Streams an uploaded derivative into a content digest without
        # loading it into memory.
        def derivative_file_digest(derivative)
          digest = Digest::SHA1.new

          if derivative.respond_to?(:stream)
            writer = Object.new
            writer.define_singleton_method(:write) { |chunk| digest.update(chunk); chunk.bytesize }
            derivative.stream(writer)
          else
            digest.update(derivative.read)
          end

          digest.hexdigest
        end

        # Publishes a finished batch as a group: removes the node paths being
        # replaced, merges the newly uploaded derivatives and writes the
        # updated manifest together with them.
        def publish_derivative_rebuild(staged, rebuilt, new_manifest)
          return {} if rebuilt.empty?

          derivatives_synchronize do
            merged_derivatives = deep_merge_derivatives({}, derivatives)

            rebuilt.each do |node_name|
              paths = new_manifest.dig(node_name.to_s, "outputs") || []
              paths.each do |path|
                lookup_path = path.map { |key| key.is_a?(String) ? key.to_sym : key }

                if lookup_path.one?
                  merged_derivatives.delete(lookup_path.first)
                else
                  parent = merged_derivatives.dig(*lookup_path[0..-2])
                  parent.delete(lookup_path.last) if parent.is_a?(Hash)
                end
              end
            end

            staged.each_value do |uploaded|
              merged_derivatives = deep_merge_derivatives(merged_derivatives, uploaded)
            end

            merged_manifest = derivatives_manifest.merge(new_manifest)

            @derivatives_manifest = merged_manifest
            set_derivatives(merged_derivatives)
          end

          rebuilt.each_with_object({}) do |node_name, published|
            published.replace(deep_merge_derivatives(published, staged[node_name]))
          end
        end

        # Deletes derivatives uploaded during a failed rebuild run. Existing
        # derivatives and their references are never touched.
        def cleanup_staged_derivatives(staged)
          staged.each_value do |uploaded|
            map_derivative(uploaded) { |_, derivative| derivative.delete }
          end
        end

        # Calls the derivatives processor with the source file and options.
        def _process_derivatives(processor_name, source, **options)
          processor = self.class.derivatives_processor(processor_name)

          return {} unless processor

          result = instrument_derivatives(processor_name, source, options) do
            instance_exec(source, **options, &processor)
          end

          unless result.is_a?(Hash)
            fail Error, "expected derivatives processor #{processor_name.inspect} to return a Hash, got #{result.inspect}"
          end

          result
        end

        # Sends a `derivatives.shrine` event for instrumentation plugin.
        def instrument_derivatives(processor_name, source, processor_options, &block)
          return yield unless shrine_class.respond_to?(:instrument)

          shrine_class.instrument(:derivatives, {
            processor:         processor_name,
            processor_options: processor_options,
            io:                source,
            attacher:          self,
          }, &block)
        end

        # Returns symbolized array or single key.
        def derivative_path(path)
          path = Array(path).map { |key| key.is_a?(String) ? key.to_sym : key }
          path = path.first if path.one?
          path
        end

        # Storage to which derivatives will be uploaded to by default.
        def derivative_storage(path)
          storage = self.class.derivatives_storage
          storage = instance_exec(path, &storage) if storage.respond_to?(:call)
          storage
        end

        # Deep merge nested hashes/arrays.
        def deep_merge_derivatives(o1, o2)
          if o1.is_a?(Hash) && o2.is_a?(Hash)
            o1.merge(o2) { |_, v1, v2| deep_merge_derivatives(v1, v2) }
          elsif o1.is_a?(Array) && o2.is_a?(Array)
            o1 + o2
          else
            o2
          end
        end

        # Whether to automatically create derivatives on promotion
        def create_derivatives_on_promote?
          shrine_class.derivatives_options[:create_on_promote]
        end

        def derivatives_synchronize
          if @derivatives_mutex
            @derivatives_mutex.synchronize { yield }
          else
            yield
          end
        end
      end

      module ClassMethods
        # Converts data into a Hash of derivatives.
        #
        #     Shrine.derivatives('{"thumb":{"id":"foo","storage":"store","metadata":{}}}')
        #     #=> { thumb: #<Shrine::UploadedFile id="foo" storage=:store metadata={}> }
        #
        #     Shrine.derivatives({ "thumb" => { "id" => "foo", "storage" => "store", "metadata" => {} } })
        #     #=> { thumb: #<Shrine::UploadedFile id="foo" storage=:store metadata={}> }
        #
        #     Shrine.derivatives({ thumb: { id: "foo", storage: "store", metadata: {} } })
        #     #=> { thumb: #<Shrine::UploadedFile id="foo" storage=:store metadata={}> }
        def derivatives(object)
          if object.is_a?(String)
            derivatives JSON.parse(object)
          elsif object.is_a?(Hash) || object.is_a?(Array)
            map_derivative(
              object,
              transform_keys: :to_sym,
              leaf: -> (value) { value.is_a?(Hash) && (value["id"] || value[:id]).is_a?(String) },
            ) { |_, value| uploaded_file(value) }
          else
            fail ArgumentError, "cannot convert #{object.inspect} to derivatives"
          end
        end

        # Iterates over a nested collection, yielding on each part of the path.
        # If the block returns a truthy value, that branch is terminated
        def map_derivative(object, path = [], transform_keys: :to_sym, leaf: nil, &block)
          return enum_for(__method__, object) unless block_given?

          if leaf && leaf.call(object)
            yield path, object
          elsif object.is_a?(Hash)
            object.inject({}) do |hash, (key, value)|
              key = key.send(transform_keys)

              hash.merge! key => map_derivative(
                value, [*path, key],
                transform_keys: transform_keys, leaf: leaf,
                &block
              )
            end
          elsif object.is_a?(Array)
            object.map.with_index do |value, idx|
              map_derivative(
                value, [*path, idx],
                transform_keys: transform_keys, leaf: leaf,
                &block
              )
            end
          else
            yield path, object
          end
        end

        # Returns derivatives plugin options.
        def derivatives_options
          opts[:derivatives]
        end
      end

      module FileMethods
        def [](*keys)
          if keys.any? { |key| key.is_a?(Symbol) }
            fail Error, "Shrine::UploadedFile#[] doesn't accept symbol metadata names. Did you happen to call `record.attachment[:derivative_name]` when you meant to call `record.attachment(:derivative_name)`?"
          else
            super
          end
        end
      end

      # Adds compatibility with how the versions plugin stores processed files.
      module VersionsCompatibility
        def load_data(data)
          return super if data.nil?
          return super if data["derivatives"] || data[:derivatives]
          return super if (data["id"] || data[:id]).is_a?(String)

          data     = data.dup
          original = data.delete("original") || data.delete(:original) || {}

          super original.merge("derivatives" => data)
        end
      end
    end

    register_plugin(:derivatives, Derivatives)
  end
end
