# frozen_string_literal: true

require "digest"
require "tempfile"

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/content_addressable
    module ContentAddressable
      def self.load_dependencies(uploader, *)
        require "shrine/storage/ref_store"
      end

      def self.configure(uploader, ref_store: nil, storages: nil, algorithm: :sha256, prefix: nil)
        uploader.opts[:content_addressable] ||= {
          ref_store:        nil,
          ref_stores:       {},
          storages:         nil,
          algorithm:        :sha256,
          prefix:           nil,
        }

        options = uploader.opts[:content_addressable]

        if ref_store
          case ref_store
          when Hash
            ref_store.each do |storage_name, store|
              validate_ref_store!(store)
              options[:ref_stores][storage_name.to_sym] = store
            end
          else
            validate_ref_store!(ref_store)
            options[:ref_store] = ref_store
          end
        end

        options[:storages] = storages.map(&:to_sym) if storages
        options[:algorithm] = algorithm
        options[:prefix] = prefix

        fail Error, "a :ref_store must be configured for the content_addressable plugin" unless options[:ref_store] || !options[:ref_stores].empty?
      end

      def self.validate_ref_store!(store)
        unless store.respond_to?(:acquire) && store.respond_to?(:release)
          fail Error, "ref_store #{store.inspect} must implement #acquire and #release"
        end
      end

      module ClassMethods
        # Returns the RefStore used for the given storage key, or nil when
        # content-addressable storage is not enabled for that storage. When
        # a single (non-Hash) ref store was configured it is used for every
        # enabled storage; callers that need separate namespaces per storage
        # configure one RefStore instance per storage key.
        def content_addressable_ref_store(storage_key)
          options = opts[:content_addressable]

          return if options[:storages] && !options[:storages].include?(storage_key.to_sym)

          options[:ref_stores][storage_key.to_sym] || options[:ref_store]
        end

        # Returns the blob key for the given IO content. The content is read
        # on the server side; the IO is rewound after the digest is
        # calculated so that the caller can still upload it.
        def content_addressable_key(io, algorithm: opts[:content_addressable][:algorithm], prefix: opts[:content_addressable][:prefix])
          hexdigest =
            if io.respond_to?(:path) && io.path && File.exist?(io.path)
              Digest.const_get(algorithm.to_s.upcase).file(io.path).hexdigest
            else
              digest = Digest.const_get(algorithm.to_s.upcase).new
              digest.update(io.read(16 * 1024, buffer = +"")) until io.eof?
              io.rewind
              digest.hexdigest
            end

          "#{prefix}#{hexdigest}"
        end
      end

      module InstanceMethods
        # Uploads the content as a shared, content-addressed blob. The blob
        # key is computed from the actual content read on the server side,
        # while the returned UploadedFile keeps its own independent metadata
        # (filename, mime type, size, custom metadata).
        #
        # Passing an explicit `:location` bypasses reference management and
        # performs an ordinary upload to that location (used e.g. by
        # `UploadedFile#replace`).
        def upload(io, location: nil, metadata: nil, close: true, delete: false, **options)
          return super if location

          ref_store = ref_store_for(storage_key)
          return super unless ref_store

          file_metadata = get_metadata(io, metadata:, **options)
          content_io    = spool(io)
          blob_key       = self.class.content_addressable_key(content_io)

          ref_store.acquire(blob_key) do |created|
            if created
              _upload(content_io, **options, location: blob_key, metadata: file_metadata, close: false, delete: false)
            elsif !blob_exists?(blob_key)
              fail Error, "blob #{blob_key.inspect} is referenced but missing from #{storage_key.inspect}"
            end
          end

          File.unlink(io.path) if delete && io.respond_to?(:path) && File.exist?(io.path)

          self.class::UploadedFile.new(
            id:       blob_key,
            storage:  storage_key,
            metadata: file_metadata,
          )
        ensure
          close_content_io(io, content_io, close)
        end

        private

        def ref_store_for(storage_key)
          self.class.content_addressable_ref_store(storage_key)
        end

        def blob_exists?(location)
          storage.exists?(location)
        end

        # UploadedFile inputs and IO objects that already respond to #path
        # are used as-is; other IO objects are spooled to a Tempfile so the
        # digest calculation and the upload read the same bytes and the
        # upload remains streaming-friendly upstream.
        def spool(io)
          return io if io.respond_to?(:path) && io.path && File.exist?(io.path)

          tempfile = ::Tempfile.new(["shrine-content", ""], binmode: true)
          IO.copy_stream(io, tempfile.path)
          io.rewind
          tempfile.rewind
          tempfile
        end

        def close_content_io(original_io, content_io, close)
          if content_io.equal?(original_io)
            original_io.close if close
          else
            content_io.close! if content_io
            original_io.close if close
          end
        end
      end

      module FileMethods
        # Releases this attachment's reference. The shared blob is deleted
        # only when this was the last reference.
        def delete(**options)
          ref_store = shrine_class.content_addressable_ref_store(storage_key)

          return super unless ref_store

          ref_store.release(id) do |last|
            storage.delete(id) if last
          end
        end
      end

    end

    register_plugin(:content_addressable, ContentAddressable)
  end
end
