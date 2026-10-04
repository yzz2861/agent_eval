# frozen_string_literal: true

class Shrine
  module Plugins
    # Documentation can be found in doc/plugins/virus_scanning.md
    #
    # The +virus_scanning+ plugin keeps newly assigned files in a quarantine
    # storage until an external scanner confirms they are safe. While a file is
    # waiting for a scan result, no public download URL is generated and the
    # file is not promoted to permanent storage.
    #
    # The scanner is integrated through an ordinary callable that receives the
    # Shrine::UploadedFile and returns whether the file is clean:
    #
    #   Shrine.plugin :virus_scanning,
    #     scanner: -> (file) { MyScanner.clean?(file.download) }
    #
    # A return value of +true+ or +:clean+ means the file passed the scan,
    # +false+ or +:infected+ means it was rejected, and an exception means the
    # scan failed.
    #
    # Scans can be run asynchronously by registering a +scan_block+, which is
    # responsible for enqueuing the scan. The background job then calls
    # Attacher#accept_scan!, Attacher#reject_scan! or Attacher#fail_scan! with
    # the task generation:
    #
    #   attacher.scan_block do |attacher|
    #     VirusScanJob.perform_async(
    #       attacher.record.class.name,
    #       attacher.record.id,
    #       attacher.name,
    #       attacher.scan_generation,
    #     )
    #   end
    #
    #   class VirusScanJob
    #     def perform(record_class, record_id, name, generation)
    #       record   = record_class.constantize.find(record_id)
    #       attacher = record.public_send(:"\#{name}_attacher")
    #
    #       begin
    #         if MyScanner.scan(attacher.file)
    #           attacher.accept_scan!(generation)
    #         else
    #           attacher.reject_scan!(generation)
    #         end
    #       rescue => error
    #         attacher.fail_scan!(generation, error.message)
    #       end
    #     end
    #   end
    module VirusScanning
      # Metadata key that holds the scan status: +pending+, +passed+,
      # +rejected+ or +failed+.
      SCAN_STATUS_KEY = "scan_status".freeze
      # Metadata key that binds the scan task to an attachment generation.
      SCAN_GENERATION_KEY = "scan_generation".freeze
      # Metadata key that holds the scanner error message for failed scans.
      SCAN_ERROR_KEY = "scan_error".freeze

      def self.configure(uploader, scanner: nil, scan_block: nil, quarantine: nil, **)
        uploader.opts[:virus_scanning] ||= { scanner: nil, scan_block: nil, quarantine: nil }

        uploader.opts[:virus_scanning][:scanner] = to_callable(scanner) if scanner
        uploader.opts[:virus_scanning][:scan_block] = to_callable(scan_block) if scan_block
        uploader.opts[:virus_scanning][:quarantine] = quarantine.to_sym if quarantine
      end

      def self.to_callable(object)
        object.respond_to?(:call) ? object : object.method(:call)
      end

      module AttacherClassMethods
        # Returns the globally configured scanner callable.
        def virus_scanner
          shrine_class.opts[:virus_scanning][:scanner]
        end

        # Registers a global block that starts a (typically asynchronous)
        # scan task for a newly quarantined file.
        def scan_block(&block)
          shrine_class.opts[:virus_scanning][:scan_block] = block if block
          shrine_class.opts[:virus_scanning][:scan_block]
        end
      end

      module AttacherMethods
        # Inherits the global scanner and scan block if defined.
        def initialize(**args)
          super(**args)
          @virus_scanner = self.class.virus_scanner
          @scan_block    = self.class.scan_block
          @scan_counter  = 0
        end

        # Loads the file and seeds the attachment generation counter so that
        # files replacing it receive a generation newer than the loaded one.
        def load_data(data)
          super
          remember_generation(file)
        end

        # Registers an instance-level scanner callable that overrides the
        # global one.
        def virus_scanner(scanner = nil)
          @virus_scanner = scanner.respond_to?(:call) ? scanner : scanner.method(:call) if scanner
          @virus_scanner
        end

        # Sets the scanner callable (equivalent to #virus_scanner with an
        # argument).
        def virus_scanner=(scanner)
          virus_scanner(scanner)
        end

        # Registers an instance-level scan block that overrides the global
        # one. The block receives the attacher when a file enters quarantine.
        def scan_block(&block)
          @scan_block = block if block
          @scan_block
        end

        # Returns the quarantine storage key. Defaults to the temporary
        # storage, since newly assigned files already reside there.
        def quarantine_key
          (shrine_class.opts[:virus_scanning][:quarantine] || cache_key).to_sym
        end

        # Returns the storage object used as quarantine.
        def quarantine
          shrine_class.find_storage(quarantine_key)
        end

        # Returns the current scan status as a symbol, or +nil+ for files not
        # tracked by this plugin (e.g. pre-existing attachments).
        def scan_status
          return nil unless file

          status = file.metadata[SCAN_STATUS_KEY]
          status && status.to_sym
        end

        # Returns the attachment generation the current scan task belongs to.
        def scan_generation
          return nil unless file

          generation = file.metadata[SCAN_GENERATION_KEY]
          generation && Integer(generation)
        end

        def scan_pending?
          scan_status == :pending
        end

        def scan_passed?
          scan_status == :passed
        end

        def scan_rejected?
          scan_status == :rejected
        end

        def scan_failed?
          scan_status == :failed
        end

        # Whether the current file is still confined to quarantine (it has a
        # scan result other than "passed").
        def quarantined?
          status = scan_status
          !!status && status != :passed
        end

        # Sets an existing cached file or uploads an IO object to quarantine,
        # stamps it as a pending scan task bound to a new attachment
        # generation and starts the scan.
        def attach_cached(value, **options)
          if value.is_a?(String) || value.is_a?(Hash)
            quarantined_file = cached(value, **options)

            unless quarantined_file.storage_key == quarantine_key
              quarantined_file = upload(quarantined_file, quarantine_key, action: :quarantine)
            end

            stamp_new_scan(quarantined_file)
            change(quarantined_file)
            start_scan!
          else
            return attach(value, **options)
          end
          file
        end

        # Uploads a new IO object to quarantine, stamps it as a pending scan
        # task and starts the scan. Passing +nil+ removes the attachment as
        # usual.
        def attach(io, storage: nil, **options)
          return super if io.nil?

          quarantined_file = upload(io, quarantine_key, action: :quarantine, **options)
          stamp_new_scan(quarantined_file)
          change(quarantined_file)

          start_scan!
          file
        end

        # Starts the scan task for the currently attached quarantined file and
        # resets its status to +pending+. When a scan block is registered it is
        # called (typically to enqueue a background job); otherwise the
        # configured scanner is invoked synchronously and its result applied.
        def start_scan!
          fail Shrine::Error, "no file is attached" unless file
          fail Shrine::Error, "file is not in quarantine" unless file.storage_key == quarantine_key

          remember_generation(file)
          update_scan(SCAN_STATUS_KEY => "pending", SCAN_ERROR_KEY => nil)

          if scan_block
            invoke_scan_block
          elsif virus_scanner
            run_scanner
          end

          file
        end

        # Runs the configured scanner synchronously and applies its result.
        # Returns the resulting scan status.
        def scan!
          fail Shrine::Error, "no scanner is configured" unless virus_scanner

          start_scan!
          scan_status
        end

        # Retries the scan for a failed task using the same generation.
        def rescan!
          fail Shrine::Error, "current scan is not in a failed state" unless scan_failed?

          start_scan!
        end

        # Marks the current generation's scan task as passed, promotes the
        # quarantined file to permanent storage and removes the quarantine
        # object owned by the task. Idempotent for repeated callbacks.
        def accept_scan!(generation, **)
          return file unless open_task?(generation)

          update_scan(SCAN_STATUS_KEY => "passed", SCAN_ERROR_KEY => nil)

          quarantined_file = file
          if quarantined_file.storage_key == quarantine_key
            # The scanner might have opened and read the file, so close any
            # cached IO to make promotion stream the full object again.
            quarantined_file.close if quarantined_file.opened?
            promote(storage: store_key)
          end
          delete_task_object(quarantined_file)

          file
        end

        # Marks the current generation's scan task as rejected and deletes the
        # quarantine object owned by the task. The rejected status is retained
        # on the attached file. Idempotent for repeated callbacks.
        def reject_scan!(generation, **)
          return file unless open_task?(generation)

          update_scan(SCAN_STATUS_KEY => "rejected", SCAN_ERROR_KEY => nil)
          delete_task_object(file)
          file
        end

        # Marks the current generation's scan task as failed and keeps the
        # quarantine object so the scan can be retried. Idempotent for
        # repeated callbacks.
        def fail_scan!(generation, message = nil, **)
          return file unless open_task?(generation)

          update_scan(SCAN_STATUS_KEY => "failed", SCAN_ERROR_KEY => message)
          file
        end

        # Files that haven't passed the scan stay in quarantine and are not
        # promoted when the record is saved.
        def promote_cached(**)
          return if scan_tracked? && !scan_passed?

          super
        end

        # Does not expose a download URL while the file is confined to
        # quarantine.
        def url(**)
          return if quarantined?

          super
        end

        private

        # Whether the attached file carries scan metadata.
        def scan_tracked?
          file&.metadata&.key?(SCAN_STATUS_KEY)
        end

        # Stamps a freshly quarantined file as a pending task of a new
        # attachment generation.
        def stamp_new_scan(file)
          write_scan_metadata(
            file,
            SCAN_STATUS_KEY     => "pending",
            SCAN_GENERATION_KEY => next_generation,
            SCAN_ERROR_KEY      => nil,
          )
        end

        # Allocates a monotonically increasing generation unique within this
        # attacher. Attachers loaded from persisted data seed themselves from
        # the file metadata in #load_data.
        def next_generation
          @scan_counter += 1
        end

        def remember_generation(file)
          generation = file&.metadata&.[](SCAN_GENERATION_KEY)
          return unless generation

          generation = Integer(generation)
          @scan_counter = generation if generation > @scan_counter
        end

        def same_generation?(generation)
          scan_generation && scan_generation == Integer(generation)
        end

        # A scanner callback may only act when its generation matches the
        # currently attached file (file identity + attachment generation).
        # Stale callbacks for replaced attachments are ignored. Only a pending
        # task can transition to a result, which makes repeated callbacks
        # idempotent.
        def open_task?(generation)
          scan_pending? && same_generation?(generation)
        end

        # Rewrites scan metadata on the current file and syncs it with the
        # record attribute when the model plugin is loaded.
        def update_scan(metadata)
          write_scan_metadata(file, metadata)
          set(file)
        end

        # Merges scan metadata into the uploaded file's metadata.
        def write_scan_metadata(file, metadata)
          metadata.each do |key, value|
            if value.nil?
              file.metadata.delete(key)
            else
              file.metadata[key] = value
            end
          end
        end

        # Deletes an object only when it is the quarantine object owned by
        # the current scan task: same quarantine storage and same generation.
        def delete_task_object(object)
          return unless object
          return unless object.storage_key == quarantine_key
          return unless object.metadata[SCAN_GENERATION_KEY] == scan_generation

          object.delete
        end

        # Normalizes the scanner result: +true+/:clean passes, +false+
        # /:infected rejects, an exception fails.
        def run_scanner
          result = virus_scanner.call(file)

          case result
          when false, :infected then reject_scan!(scan_generation)
          else                     accept_scan!(scan_generation)
          end
        rescue => error
          fail_scan!(scan_generation, error.message)
        end

        def invoke_scan_block
          block = scan_block

          if block.arity == 1
            block.call(self)
          else
            instance_exec(&block)
          end
        end
      end

      module FileMethods
        # Files that have not passed the scan never get a public download URL.
        def url(**)
          status = metadata[VirusScanning::SCAN_STATUS_KEY]

          return if status && status != "passed"

          super
        end
      end
    end

    register_plugin(:virus_scanning, VirusScanning)
  end
end
