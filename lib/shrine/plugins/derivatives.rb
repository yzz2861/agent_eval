# frozen_string_literal: true

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
        # Pass `version:` with an explicit recipe version to participate in
        # incremental rebuilds performed by `Attacher#rebuild_derivatives`:
        # changing the version forces this processor and all of its consumers
        # to be rebuilt.
        #
        #     Attacher.derivatives_processor :thumbnail, version: 3 do |original|
        #       # ...
        #     end
        #
        # Use `depends_on:` to declare derivative nodes produced by other
        # processors; the corresponding files are passed to the block as
        # keyword arguments (nested paths joined with underscores) and are
        # guaranteed to be processed first.
        #
        #     Attacher.derivatives_processor :web, version: 1, depends_on: [[:thumbnails, :large]] do |original, thumbnails_large:|
        #       # ...
        #     end
        def derivatives_processor(name = :default, version: nil, depends_on: nil, download: true, &block)
          if block
            shrine_class.derivatives_options[:processors][name.to_sym] = block
            shrine_class.derivatives_options[:processor_settings][name.to_sym] = {
              download:    download,
              version:     version,
              depends_on:  Array(depends_on).map { |path| Array(path) },
            }
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
        attr_reader :derivatives

        # Adds the ability to accept derivatives.
        def initialize(derivatives: {}, **options)
          super(**options)

          @derivatives         = derivatives
          @derivation_manifest = {}
          @derivatives_mutex   = Mutex.new if shrine_class.derivatives_options[:mutex]
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

        # Incrementally rebuilds registered derivatives based on the attached
        # file's identity, each processor's explicit recipe version and the
        # results of processors it depends on.
        #
        #     Attacher.derivatives_processor :intermediate, version: 1 do |original|
        #       { intermediate: StringIO.new(original.read.upcase) }
        #     end
        #
        #     Attacher.derivatives_processor :derived, version: 1, depends_on: :intermediate do |original, intermediate:|
        #       { derived: StringIO.new(intermediate.read.reverse) }
        #     end
        #
        #     attacher.rebuild_derivatives
        #     # rebuilds only :intermediate and :derived if the source changed,
        #     # only :derived if its recipe version changed, and nothing when
        #     # everything is still up to date.
        #
        # Newly built derivatives replace the old results atomically: until the
        # whole rebuild set is ready, the previously published derivatives stay
        # available. If processing fails, files uploaded during the failed run
        # are cleaned up while the old derivative references are preserved.
        def rebuild_derivatives(*processor_names, storage: nil, **options)
          processor_names = processor_names.map(&:to_sym)

          source          = file!
          source_identity = derivation_source_identity(source)

          runnable = derivation_run_plan(processor_names, source_identity)

          return {} if runnable.empty?

          processed_files  = {}
          staged_files     = []
          transient_files  = []
          processed_entries = {}

          begin
            source_block = -> (source_file) do
              run_derivation_processors(
                runnable, source_file, source_identity, options,
                processed_entries, processed_files, transient_files
              )
            end

            if runnable.any? { |name| self.class.derivatives_processor_settings(name)[:download] }
              shrine_class.with_file(source) { |file| source_block.call(file) }
            else
              source_block.call(source)
            end

            runnable.each do |name|
              files = processed_files.fetch(name)

              derivation_leaves(files).each do |_, file|
                file.rewind if file.respond_to?(:rewind)
              end

              uploaded = upload_derivatives(files, storage: storage)
              staged_files.concat(derivation_leaves(uploaded))
              processed_files[name] = uploaded
            end
          rescue => error
            transient_files.each { |file| File.delete(file.path) if file.respond_to?(:path) && File.exist?(file.path) }
            staged_files.each(&:delete)
            raise error
          end

          transient_files.each { |file| File.delete(file.path) if file.respond_to?(:path) && File.exist?(file.path) }

          publish_derivations(runnable, processed_entries, processed_files)

          runnable.inject({}) { |result, name| result.merge(processed_files.fetch(name)) }
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

          if @derivation_manifest.any?
            result ||= {}
            result["derivation_manifest"] = serialize_derivation_manifest(@derivation_manifest)
          end

          if derivatives.any?
            result ||= {}
            result["derivatives"] = map_derivative(derivatives, transform_keys: :to_s) do |_, derivative|
              derivative.data
            end
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

          manifest_data = data.delete("derivation_manifest") || data.delete(:derivation_manifest)
          @derivation_manifest = deserialize_derivation_manifest(manifest_data)

          derivatives_data = data.delete("derivatives") || data.delete(:derivatives) || {}
          @derivatives     = shrine_class.derivatives(derivatives_data)

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
            set_derivatives({})
            @derivation_manifest = {}
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

        # Computes which registered processors have to be rebuilt. A processor
        # is stale when it has never been run for the current source, when its
        # recipe version changed, when the source identity changed, or when a
        # processor producing one of its dependencies is rebuilt. Returns the
        # stale processors in dependency execution order.
        def derivation_run_plan(requested_names, source_identity)
          settings_map = shrine_class.derivatives_options[:processor_settings]

          requested_names = settings_map.keys.select { |name| self.class.derivatives_processor(name) } if requested_names.empty?

          requested_names.each do |name|
            next if self.class.derivatives_processor(name)

            fail Error, "derivatives processor #{name.inspect} not registered"
          end

          producers = derivation_dependency_producers

          # expand the rebuild scope with processors that produce dependencies
          included  = requested_names.dup
          pending   = requested_names.dup

          until pending.empty?
            name = pending.shift
            settings = settings_map[name]

            next unless settings

            settings[:depends_on].each do |dependency|
              producer = producers[dependency] ||= derivation_infer_producer(dependency, settings_map)

              if producer && !included.include?(producer)
                included << producer
                pending   << producer
              end
            end
          end

          stale = included.each_with_object({}) do |name, result|
            result[name] = derivation_processor_stale?(name, source_identity, settings_map)
          end

          # a consumer is stale whenever one of its node producers is stale
          loop do
            propagated = false

            included.each do |name|
              next if stale[name]

              consumer_stale = settings_map[name][:depends_on].any? do |dependency|
                producer = producers[dependency]
                producer && stale[producer]
              end

              if consumer_stale
                stale[name] = true
                propagated   = true
              end
            end

            break unless propagated
          end

          runnable  = included.select { |name| stale[name] }
          ordered   = []
          remaining = runnable.dup

          until remaining.empty?
            next_batch = remaining.select do |name|
              settings_map[name][:depends_on].all? do |dependency|
                producer = producers[dependency]
                producer.nil? || !runnable.include?(producer) || ordered.include?(producer)
              end
            end

            if next_batch.empty?
              fail Error, "cannot resolve derivatives dependencies for #{remaining.map(&:inspect).join(", ")} (missing producer or cyclic dependency)"
            end

            ordered.concat(next_batch)
            remaining -= next_batch
          end

          ordered
        end

        # Maps dependency paths to the processors currently known to produce
        # them, based on stored manifest records.
        def derivation_dependency_producers
          producers = {}

          @derivation_manifest.each do |producer, entry|
            entry[:outputs].each { |path| producers[path] = producer }
          end

          producers
        end

        # On the first run there is no stored manifest, so a dependency node is
        # assumed to be produced by a processor named after its first path
        # segment when such a processor exists.
        def derivation_infer_producer(dependency, settings_map)
          head = dependency.first
          head if head.is_a?(Symbol) && settings_map.key?(head)
        end

        # Direct staleness of a single processor, without dependency effects.
        def derivation_processor_stale?(name, source_identity, settings_map)
          settings = settings_map[name]
          entry    = @derivation_manifest[name]

          return true unless entry
          return true if source_identity.nil? || entry[:source] != source_identity
          return true if settings[:version] != entry[:version]
          return true unless settings[:depends_on].map(&:to_s).sort == entry[:depends_on].map(&:to_s).sort
          return true if settings[:depends_on].any? { |path| derivatives.dig(*path).nil? }

          false
        end

        # Runs the stale processors in dependency order, resolving dependencies
        # from previously built results or the currently published derivatives.
        def run_derivation_processors(order, source, source_identity, options, entries, processed_files, transient_files)
          order.each do |name|
            settings = self.class.derivatives_processor_settings(name)
            dependencies = {}
            source.rewind if source.respond_to?(:rewind)

            settings[:depends_on].each do |path|
              file = lookup_processed_derivative(processed_files, path) || derivatives.dig(*path)

              if file.nil?
                fail Error, "derivatives processor #{name.inspect} depends on #{path.inspect}, but it was not found"
              end

              file = derivation_with_file(file, transient_files)
              file.rewind if file.respond_to?(:rewind)
              dependencies[derivation_dependency_key(path)] = file
            end

            result = instrument_derivatives(name, source, options) do
              instance_exec(source, **options, **dependencies, &self.class.derivatives_processor(name))
            end

            unless result.is_a?(Hash)
              fail Error, "expected derivatives processor #{name.inspect} to return a Hash, got #{result.inspect}"
            end

            processed_files[name] = result
            entries[name] = {
              version:    settings[:version],
              source:     source_identity,
              outputs:    derivation_leaves(result).map(&:first),
              depends_on: settings[:depends_on],
            }
          end
        end

        # Finds an uploaded or raw derivative produced during the current run.
        def lookup_processed_derivative(processed_files, path)
          processed_files.each_value do |files|
            value = files.dig(*path)
            return value if value
          end

          nil
        end

        # Keyword under which a dependency is passed to the processor block.
        def derivation_dependency_key(path)
          key = path.map { |segment| segment.is_a?(Integer) ? "node#{segment}" : segment }.join("_")
          key.to_sym
        end

        # Provides each consumer with an independently readable file copy of
        # the dependency, so multiple consumers (or a later node upload) never
        # share IO read positions.
        def derivation_with_file(derivative, transient_files)
          if derivative.is_a?(Shrine::UploadedFile)
            file = derivative.download
          else
            file = Tempfile.create("shrine-derivative", binmode: true)
            derivative.rewind if derivative.respond_to?(:rewind)
            IO.copy_stream(derivative, file.path)
          end

          file.rewind
          transient_files << file
          file
        end

        # Atomically replaces the rebuilt outputs: old derivatives stay
        # referenced until every new output has been uploaded successfully.
        def publish_derivations(order, entries, processed_files)
          derivatives_synchronize do
            published = deep_copy_derivatives(derivatives)

            order.each do |name|
              old_entry = @derivation_manifest[name]

              if old_entry
                old_entry[:outputs].each do |path|
                  remove_derivative_at(published, path) unless path.empty?
                end
              end

              published = deep_merge_derivatives(published, processed_files.fetch(name))
            end

            manifest = @derivation_manifest.dup
            order.each { |name| manifest[name] = entries.fetch(name) }
            @derivation_manifest = manifest

            set_derivatives(published)
          end
        end

        # Stable identity of the source used for incremental rebuilds. Ad-hoc
        # IOs cannot be identified, which forces a full rebuild.
        def derivation_source_identity(source)
          return nil unless source.is_a?(Shrine::UploadedFile)

          "#{source.storage_key}:#{source.id}"
        end

        # Recursively collects [path, file] pairs from a nested hash/array.
        def derivation_leaves(object, path = [])
          case object
          when Hash
            object.flat_map { |key, value| derivation_leaves(value, [*path, key]) }
          when Array
            object.flat_map.with_index { |value, index| derivation_leaves(value, [*path, index]) }
          else
            [[path, object]]
          end
        end

        # Removes a value at the given path, cleaning up emptied parents.
        def remove_derivative_at(object, path)
          return nil if path.empty?

          parent = path[0..-2].reduce(object) do |collection, key|
            collection && collection.is_a?(Hash) ? collection[key] : nil
          end

          return nil unless parent.is_a?(Hash) || parent.is_a?(Array)

          if parent.is_a?(Array) && path[-1].is_a?(Integer)
            parent.delete_at(path[-1])
          else
            parent.delete(path[-1])
          end
        end

        # Deep duplicates the structure while keeping UploadedFile references.
        def deep_copy_derivatives(object)
          case object
          when Hash
            object.transform_values { |value| deep_copy_derivatives(value) }
          when Array
            object.map { |value| deep_copy_derivatives(value) }
          else
            object
          end
        end

        # Produces a JSON-safe representation of the stored manifest.
        def serialize_derivation_manifest(manifest)
          manifest.each_with_object({}) do |(name, entry), result|
            result[name.to_s] = {
              "version"    => entry[:version],
              "source"     => entry[:source],
              "outputs"    => entry[:outputs].map { |path| path.map(&:to_s) },
              "depends_on" => entry[:depends_on].map { |path| path.map(&:to_s) },
            }
          end
        end

        # Loads a JSON-parsed manifest into symbol keys and paths.
        def deserialize_derivation_manifest(manifest_data)
          (manifest_data || {}).each_with_object({}) do |(name, entry), result|
            result[name.to_sym] = {
              version:    entry["version"] || entry[:version],
              source:     entry["source"] || entry[:source],
              outputs:    (entry["outputs"] || entry[:outputs] || []).map { |path| path.map { |key| key.is_a?(String) ? key.to_sym : key } },
              depends_on: (entry["depends_on"] || entry[:depends_on] || []).map { |path| path.map { |key| key.is_a?(String) ? key.to_sym : key } },
            }
          end
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
