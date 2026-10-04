# frozen_string_literal: true

class Shrine
  module Storage
    # A RefStore is a minimal *atomic reference store* for
    # content-addressable storage.
    #
    # A blob is identified exclusively by its content (usually a digest of
    # the content). Each attachment holds its own independent name and
    # metadata, but references a shared blob. Multiple attachments with the
    # same content hold multiple references to the same blob, and the blob
    # must be deleted only when the last reference is released.
    #
    # A RefStore implementation only needs to provide two atomic operations,
    # #acquire and #release. The blob bytes themselves live in an ordinary
    # Shrine storage (e.g. Shrine::Storage::FileSystem); the RefStore is
    # responsible for coordinating reference counts and serializing blob
    # creation and deletion.
    #
    # The reference identity (`key`) is arbitrary and chosen by the caller
    # (the `content_addressable` plugin uses the content digest). Reference
    # identity is meaningful only within a single RefStore instance.
    module RefStore
      # Acquires a reference to the blob identified by `key` and returns a
      # two-element array containing:
      #
      #   * a boolean indicating whether this caller is responsible for
      #     creating the blob (`true` exactly when no reference existed
      #     before, `false` when the blob already exists with at least one
      #     reference);
      #   * the return value of the given block.
      #
      #     ref_store.acquire("sha256-…") do |create|
      #       blob_storage.upload(io, key) if create
      #     end
      #     #=> [true, result]   # first reference: the caller creates the blob
      #     #=> [false, result]  # subsequent reference: blob already exists
      #
      # Concurrent calls for the same key are serialized. When the blob does
      # not exist yet, exactly one caller receives `create == true`; every
      # other caller blocks until that call has finished and then receives
      # `create == false`. This makes simultaneous creation of the first
      # reference safe: the blob bytes are written by exactly one caller.
      #
      # If the block raises, the reference is not counted and the RefStore
      # returns to the state it had before the call (a failed first upload
      # leaves no reference, so a later caller becomes the creator again).
      # The exception is re-raised.
      def acquire(key)
        fail NotImplementedError, "#{self.class} must implement #acquire"
      end

      # Releases a reference to the blob identified by `key` and returns
      # `true` when this was the last reference and the blob must be
      # deleted, `false` when other references remain.
      #
      #     if ref_store.release(key)
      #       blob_storage.delete(key) # only now is it safe to delete
      #     end
      #
      # When a block is given, it is invoked while the release is still
      # serialized against concurrent #acquire calls for the same key:
      #
      #     ref_store.release(key) do
      #       blob_storage.delete(key)
      #     end
      #
      # This closes the race between deleting the last reference and a new
      # reference joining in: an #acquire that starts after the last
      # reference was observed either finds no references (and becomes the
      # creator) or finds the new reference, so the blob is never deleted
      # out from under an attachment that still references it. The block's
      # return value is returned from #release.
      #
      # Releasing a key that has no references does nothing and returns a
      # falsey value; this keeps double-deletes idempotent.
      def release(key)
        fail NotImplementedError, "#{self.class} must implement #release"
      end
    end
  end
end
