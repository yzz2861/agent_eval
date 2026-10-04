# frozen_string_literal: true

require "shrine"
require "shrine/storage/ref_store"
require "fileutils"
require "pathname"

class Shrine
  module Storage
    # A local, on-disk implementation of the RefStore protocol. It is fully
    # usable in production with Shrine::Storage::FileSystem and serves as
    # the reference implementation for the atomic reference operations.
    #
    # Reference counts and locks are stored inside a dedicated directory and
    # are independent of the directory that holds the blob bytes. Atomicity
    # is provided with per-key `flock(2)` locks, so the guarantees hold not
    # only across threads but also across processes (e.g. multiple Puma or
    # Sidekiq workers).
    #
    #     blob_storage = Shrine::Storage::FileSystem.new("storage/blobs")
    # ref_store    = Shrine::Storage::FileSystemRefStore.new("storage/refs")
    #
    #     created, _ = ref_store.acquire(key) do |create|
    #       blob_storage.upload(io, key) if create
    #     end
    #
    #     ref_store.release(key) do |last|
    #       blob_storage.delete(key) if last
    #     end
    class FileSystemRefStore
      include RefStore

      # Keys derived from content digests, optionally with an algorithm
      # prefix such as "sha256-". This rejects path traversal input.
      VALID_KEY = /\A[A-Za-z0-9._-]+\z/

      attr_reader :directory

      # Initializes a reference store rooted at `directory`. The directory
      # (and its internal `refs/` and `locks/` subdirectories) is created if
      # it doesn't exist.
      def initialize(directory)
        @directory = Pathname(directory).expand_path

        @directory.mkpath unless @directory.exist?
        refs_directory.mkpath  unless refs_directory.exist?
        locks_directory.mkpath unless locks_directory.exist?
      end

      # See RefStore#acquire.
      def acquire(key)
        synchronize(key) do
          created = !reference_path(key).exist?

          begin
            result = yield(created)
          rescue
            # A failed first upload must leave no reference behind, so a
            # concurrent/retrying caller can become the creator again.
            delete_count(key) if created
            raise
          end

          write_count(key, (read_count(key) || 0) + 1)

          [created, result]
        end
      end

      # See RefStore#release. When a block is given it runs while the
      # per-key lock is still held, closing the delete/join race.
      def release(key)
        synchronize(key) do
          count = read_count(key)

          if count.nil?
            return block_given? ? yield(false) : false
          end

          if count <= 1
            delete_count(key)
            last = true
          else
            write_count(key, count - 1)
            last = false
          end

          block_given? ? yield(last) : last
        end
      end

      # Returns the current number of references for `key` (0 when the blob
      # is unknown). Mostly useful for tests and diagnostics.
      def count(key)
        synchronize(key) { read_count(key) || 0 }
      end

      # Removes all reference bookkeeping. The blob storage is not touched.
      def clear!
        FileUtils.rm_rf(refs_directory)
        FileUtils.rm_rf(locks_directory)
        refs_directory.mkpath
        locks_directory.mkpath
      end

      private

      def synchronize(key)
        validate_key!(key)

        path = lock_path(key)
        FileUtils.mkdir_p(path.dirname)

        File.open(path, File::RDWR | File::CREAT, 0644) do |lock_file|
          lock_file.flock(File::LOCK_EX)
          yield
        ensure
          lock_file.flock(File::LOCK_UN)
        end
      end

      def read_count(key)
        path = reference_path(key)
        return unless path.exist?

        Integer(path.read)
      end

      def write_count(key, count)
        path = reference_path(key)
        FileUtils.mkdir_p(path.dirname)

        # Atomic replace so another process never observes a partial file.
        temporary_path = path.dirname.join(".#{path.basename}.#{Process.pid}.#{Thread.current.object_id}.tmp")
        File.write(temporary_path, count.to_s)
        File.rename(temporary_path, path)
      end

      def delete_count(key)
        reference_path(key).delete
      rescue Errno::ENOENT
      end

      # Shards key files by their first characters to avoid placing every
      # reference file in a single directory.
      def shard(key)
        key[0, 4]
      end

      def reference_path(key)
        refs_directory.join(shard(key), key)
      end

      def lock_path(key)
        locks_directory.join(shard(key), key)
      end

      def refs_directory
        @directory.join("refs")
      end

      def locks_directory
        @directory.join("locks")
      end

      def validate_key!(key)
        unless key.is_a?(String) && VALID_KEY.match?(key)
          fail Error, "invalid reference key #{key.inspect}"
        end
      end
    end
  end
end
