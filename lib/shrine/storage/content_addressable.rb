# frozen_string_literal: true

require "shrine"

class Shrine
  module Storage
    # Storage wrapper which stores each unique file only once, no matter how
    # many attachments reference it.
    #
    # It expects file IDs to be derived from the file content (see the
    # +content_addressable+ plugin, which generates such locations), and
    # wraps another storage, uploading the file only when the first
    # attachment references it, and deleting it only when the last
    # referencing attachment is deleted. Attachments still keep their own
    # metadata (filename, MIME type, etc) in the record, only the underlying
    # blob is shared.
    #
    #   refs = Shrine::Storage::ContentAddressable::MemoryRefs.new
    #
    #   Shrine.storages[:store] = Shrine::Storage::ContentAddressable.new(
    #     Shrine::Storage::FileSystem.new("public", prefix: "uploads"),
    #     refs: refs,
    #   )
    #
    # Since the content hash is computed on the server after reading the
    # actual file content, direct uploads are not supported.
    #
    # ## Reference store
    #
    # Deduplication is coordinated through a "reference store", which
    # atomically tracks how many attachments reference each file ID. It's
    # specified via the +:refs+ option, and needs to respond to:
    #
    # * <tt>#add(key) { ... }</tt> – registers a new reference. The block is
    #   called only when the first reference is registered, and should create
    #   the referenced object. If the block raises an error, the reference is
    #   discarded.
    #
    # * <tt>#remove(key) { ... }</tt> – unregisters a reference. The block is
    #   called only when the last reference is unregistered, and should delete
    #   the referenced object. If the block raises an error, the reference is
    #   retained.
    #
    # The reference store must execute the reference check and the block
    # atomically with respect to other +#add+/+#remove+ calls for the same
    # key. This guarantees that a file cannot be deleted while a new
    # reference to it is being registered, and that the file is uploaded only
    # once when multiple references to it are created concurrently.
    class ContentAddressable
      # An in-memory reference store, suitable for single-process
      # applications and tests. All operations are serialized through a
      # single mutex, which makes the create/delete decisions atomic with
      # respect to each other.
      class MemoryRefs
        def initialize
          @counts = Hash.new(0)
          @mutex  = Mutex.new
        end

        # Registers a reference, yielding to create the object when it's the
        # first one. If the block fails, the reference is not registered.
        def add(key)
          @mutex.synchronize do
            yield if @counts[key].zero?
            @counts[key] += 1
          end
        end

        # Unregisters a reference, yielding to delete the object when it's
        # the last one. If the block fails, the reference is retained.
        def remove(key)
          @mutex.synchronize do
            if @counts[key] > 0
              yield if @counts[key] == 1
              @counts[key] -= 1
              @counts.delete(key) if @counts[key].zero?
            end
          end
        end

        # Returns the current reference count for the given key.
        def count(key)
          @mutex.synchronize { @counts[key] }
        end

        # Unregisters all references.
        def clear
          @mutex.synchronize { @counts.clear }
        end
      end

      attr_reader :storage, :refs

      def initialize(storage, refs:)
        @storage = storage
        @refs    = refs
      end

      # Uploads the file only when the first attachment references it. If the
      # upload fails, the reference is discarded, so a failed upload cannot
      # affect other attachments.
      def upload(io, id, shrine_metadata: {}, **upload_options)
        refs.add(id) do
          storage.upload(io, id, shrine_metadata: shrine_metadata, **upload_options)
        end
      end

      def open(id, **options)
        storage.open(id, **options)
      end

      def exists?(id)
        storage.exists?(id)
      end

      def url(id, **options)
        storage.url(id, **options)
      end

      # Deletes the file only when the last referencing attachment is
      # deleted. If the deletion fails, the reference is retained, so it can
      # be retried.
      def delete(id)
        refs.remove(id) do
          storage.delete(id)
        end
      end

      def clear!(&condition)
        storage.clear!(&condition)
        refs.clear
      end
    end
  end
end
