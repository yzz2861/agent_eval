# frozen_string_literal: true

require "securerandom"

class Shrine
  # Raised when an operation is attempted on a file that is still held in
  # quarantine (e.g. generating a public URL or publishing it before the
  # external scanner has confirmed the file is clean).
  class FileInQuarantine < Error
  end

  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/quarantine
    #
    # The quarantine plugin makes every upload land in a dedicated
    # quarantine storage and waits for an external scanner to confirm the
    # file before it is published to permanent storage.
    #
    # The scanner is integrated through an ordinary callable, so no scanning
    # software has to be installed to use or test the plugin:
    #
    #   Shrine.plugin :quarantine, storage: :quarantine
    #
    #   Shrine::Attacher.scanner do |file, context|
    #     verdict    = ExternalScanner.analyze(file.download)
    #     scan_data  = context[:scan_data]
    #     attacher   = Shrine::Attacher.find_scan(
    #       model: context[:record], name: context[:name], file: scan_data,
    #     )
    #     attacher.resolve_scan(verdict, scan_data)
    #   end
    module Quarantine
      def self.load_dependencies(uploader, **)
        uploader.plugin :add_metadata
        uploader.plugin :atomic_helpers
      end

      def self.configure(uploader, **opts)
        uploader.opts[:quarantine] ||= { storage: :quarantine }
        uploader.opts[:quarantine].merge!(opts)
      end

      module AttacherClassMethods
        # Registers the scanner callable. The callable receives the
        # quarantined Shrine::UploadedFile and the attacher context, which
        # contains the serialized scan payload under +:scan_data+.
        #
        # The callable may scan synchronously and return a verdict:
        #
        #   * +:clean+ / +"clean+"    – the file is safe to publish
        #   * +:infected+ / +"infected"+ – the file is rejected
        #   * +:failed+ / +"failed"+   – the scan could not be completed
        #
        # or it can enqueue an external scan and return +:pending+, invoking
        # one of +#scan_pass+, +#scan_reject+, +#scan_fail+ (or
        # +#resolve_scan+) later. Any raised exception is recorded as a
        # +failed+ scan.
        def scanner(callable = nil, &block)
          shrine_class.opts[:quarantine][:scanner] = callable || block
        end

        # Registers a block used to persist scan state changes (for example
        # saving the record inside a background job). When absent, a loaded
        # persistence plugin (e.g. +:activerecord+) is used automatically.
        def scan_persist_block(&block)
          shrine_class.opts[:quarantine][:scan_persist_block] = block if block
          shrine_class.opts[:quarantine][:scan_persist_block]
        end

        # Finds an attacher for an asynchronous scan callback and verifies
        # that the referenced file is still the currently attached one.
        #
        # Raises Shrine::AttachmentChanged when the attachment has been
        # replaced, so an outdated scanner callback can never mutate the
        # current attachment.
        def find_scan(model: nil, entity: nil, record: nil, name: nil, file:)
          record ||= model || entity
          fail ArgumentError, "file data is required" unless file

          attacher =
            if record && name && record.respond_to?(:"#{name}_attacher")
              record.send(:"#{name}_attacher")
            elsif record && respond_to?(:from_model)
              from_model(record, name)
            else
              from_data(file)
            end

          unless attacher.file == attacher.uploaded_file(file)
            fail Shrine::AttachmentChanged, "attachment has changed"
          end

          attacher
        end
      end

      module AttacherMethods
        # Uses the quarantine storage as the temporary storage.
        def initialize(cache: shrine_class.opts[:quarantine][:storage], **)
          super
        end

        # A file held in quarantine never gets a public download URL.
        def url(**)
          return if quarantined?

          super
        end

        # Whether the given file is still held in quarantine storage.
        def quarantined?(file = self.file)
          file&.storage_key == cache_key
        end

        # The scan status (+pending+, +clean+, +infected+ or +failed+).
        # Files in permanent storage are considered clean.
        def scan_status(file = self.file)
          return nil unless file

          quarantined?(file) ? file.metadata["scan_status"] || "pending" : "clean"
        end

        def scan_pending?(file = self.file)
          scan_status(file) == "pending"
        end

        def scan_clean?(file = self.file)
          scan_status(file) == "clean"
        end

        def scan_infected?(file = self.file)
          scan_status(file) == "infected"
        end

        def scan_failed?(file = self.file)
          scan_status(file) == "failed"
        end

        # The scanner-assigned identity of the current scan. Generated when a
        # new file enters quarantine; never changes for that file.
        def scan_id(file = self.file)
          file&.metadata&.dig("scan_id")
        end

        # The attachment generation this scan belongs to. Incremented whenever
        # the attachment is replaced, letting callbacks detect stale
        # generations.
        def scan_generation(file = self.file)
          value = file&.metadata&.dig("scan_generation")
          value && Integer(value)
        end

        # The serializable payload handed to the scanner/background job.
        # Pass it back to the scan callback methods unchanged.
        def scan_data(file = self.file)
          return nil unless file

          file.data
        end

        # Runs the registered scanner against the currently quarantined file
        # and returns the resulting scan status.
        def start_scan(**options)
          fail Shrine::Error, "no file is attached" unless file

          scanner_callable = shrine_class.opts[:quarantine][:scanner]
          fail Shrine::Error, "scanner callable is not registered" unless scanner_callable

          payload = scan_data
          verdict =
            begin
              normalize_verdict(scanner_callable.call(file, context.merge(scan_data: payload)))
            rescue => exception
              record_scan_error(exception)
              return "failed"
            end

          if verdict == "pending"
            "pending"
          else
            apply_verdict(verdict, payload, **options)
          end
        end

        # Marks the scan clean and publishes the file to permanent storage,
        # removing the quarantined copy. Returns +:clean+, +:duplicate+ when
        # an identical clean callback is delivered again, or +:stale+ when
        # the callback belongs to a replaced attachment.
        def scan_pass(payload = scan_data)
          return :stale unless owns_scan?(payload)
          return :duplicate if scan_clean? && quarantined?
          return :stale unless scan_pending?

          quarantined_file = file
          promoted = publish_to_store
          quarantined_file.delete
          set(promoted)
          persist_scan

          :clean
        end

        # Marks the file infected. The file stays in quarantine (no public
        # URL) and is never published. Idempotent for repeat callbacks.
        def scan_reject(payload = scan_data, error: nil)
          terminate_scan("infected", payload, error:)
        end

        # Marks the scan as failed (e.g. scanner outage). The file stays in
        # quarantine so it can be retried later. Idempotent for repeat
        # callbacks.
        def scan_fail(payload = scan_data, error: nil)
          terminate_scan("failed", payload, error:)
        end

        # Retries a previously failed scan and returns the new status.
        def retry_scan(**options)
          return false unless scan_failed?

          update_scan_metadata("scan_status" => "pending", "scan_error" => nil)
          persist_scan
          start_scan(**options)
        end

        # Deletes a quarantined object owned by the given scan payload,
        # without ever touching the current attachment or permanent storage.
        # Used to clean up after stale (outdated generation) callbacks.
        def clean_scan(payload)
          candidate = uploaded_file(payload)

          return false unless candidate.storage_key == cache_key
          return false if file == candidate

          candidate.delete
          true
        end

        # Resolves an asynchronous scanner callback. +verdict+ is one of
        # +:clean+/+:infected+/:failed+. Returns the resulting status, or
        # +:stale+ when the callback belongs to a replaced attachment (in
        # which case only the object owned by that scan is cleaned up).
        def resolve_scan(verdict, payload = scan_data, **options)
          method_name =
            case normalize_verdict(verdict)
            when "clean"    then :scan_pass
            when "infected" then :scan_reject
            when "failed"   then :scan_fail
            else fail ArgumentError, "unsupported scan verdict: #{verdict.inspect}"
            end

          public_send(method_name, payload, **options)
        rescue Shrine::AttachmentChanged
          clean_scan(payload)
          :stale
        end

        # Delegates to the core promotion, but blocks publishing while the
        # file has not been confirmed clean (except internally on scan pass).
        def promote(storage: store_key, **options)
          if !@publishing_scanned_file &&
             storage.to_sym != cache_key && quarantined? && !scan_clean?
            fail Shrine::FileInQuarantine,
                 "cannot publish #{file!.id.inspect}: scan status is #{scan_status.inspect}"
          end

          super
        end

        private

        # Publishes the current file to permanent storage tagged as clean.
        def publish_to_store
          @publishing_scanned_file = true
          promote(metadata: { "scan_status" => "clean" })
        ensure
          @publishing_scanned_file = false
        end

        # Tags files entering quarantine with their scan identity.
        def upload(io, storage = store_key, **options)
          if storage.to_sym == cache_key && io
            options[:metadata] = quarantine_metadata(options[:metadata])
          end

          super
        end

        # Every new quarantined upload is scanned before it can be published.
        def promote_cached(**options)
          return super unless quarantined? && scanner_registered?

          start_scan(**options)
        end

        def terminate_scan(status, payload, error: nil)
          return :stale unless owns_scan?(payload)
          return status.to_sym unless scan_pending?

          metadata = { "scan_status" => status }
          metadata["scan_error"] = error_message(error) if error
          update_scan_metadata(metadata)
          persist_scan

          status.to_sym
        end

        # True only when the payload describes exactly the file identity and
        # scan generation currently attached.
        def owns_scan?(payload)
          return false unless payload && file

          candidate = uploaded_file(payload)

          file == candidate &&
            scan_id(candidate) == scan_id(file) &&
            scan_generation(candidate) == scan_generation(file)
        end

        def scanner_registered?
          !!shrine_class.opts[:quarantine][:scanner]
        end

        def normalize_verdict(verdict)
          case verdict
          when :clean, :infected, :failed, :pending
            verdict.to_s
          when "clean", "infected", "failed", "pending"
            verdict
          else
            "failed"
          end
        end

        def apply_verdict(verdict, payload, **options)
          case verdict
          when "clean"    then scan_pass(payload)
          when "infected" then scan_reject(payload, **options)
          when "failed"   then scan_fail(payload, **options)
          end
        end

        def quarantine_metadata(existing_metadata)
          metadata = (existing_metadata || {}).dup
          previous_generation = scan_generation

          metadata["scan_status"]     = "pending"
          metadata["scan_id"]         = SecureRandom.hex(16)
          metadata["scan_generation"] = previous_generation ? previous_generation + 1 : 1
          metadata.delete("scan_error")
          metadata
        end

        def update_scan_metadata(new_metadata)
          file.add_metadata(new_metadata)
          set(file) # trigger model write
        end

        def record_scan_error(error)
          Shrine.logger.error("SHRINE QUARANTINE: scan failed: #{error.class}: #{error.message}")

          if scan_pending?
            update_scan_metadata(
              "scan_status" => "failed",
              "scan_error"  => "#{error.class}: #{error.message}",
            )
            persist_scan
          end
        end

        def error_message(error)
          error.is_a?(Exception) ? "#{error.class}: #{error.message}" : error.to_s
        end

        def persist_scan
          block = shrine_class.opts[:quarantine][:scan_persist_block]

          if block
            block.call(self)
          elsif respond_to?(:persist, true)
            persist
          end
        end
      end

      module FileMethods
        # Files sitting in quarantine must never expose a public URL, even
        # when the Shrine::UploadedFile is accessed directly.
        def url(**options)
          if storage_key == shrine_class.opts[:quarantine][:storage] &&
             metadata["scan_status"] != "clean"
            fail Shrine::FileInQuarantine,
                 "#{id.inspect} is in quarantine " \
                 "(scan status: #{metadata["scan_status"] || "pending"})"
          end

          super
        end
      end
    end

    register_plugin(:quarantine, Quarantine)
  end
end
