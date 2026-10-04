# frozen_string_literal: true

require "fileutils"
require "json"
require "stringio"

class Shrine
  class ResumableUpload
    # Small interface that isolates resumable upload state from the service
    # logic. A session store persists upload {Session} metadata and the
    # partially received byte content (the "assembly").
    #
    # Custom stores (Redis, SQL, ...) only need to implement the methods
    # marked as abstract below. Byte ranges are half-open `[start, end)`
    # offsets.
    class SessionStore
      # Persists a newly created session. Called once per session.
      def create(session) # :notnew:
        fail NotImplementedError, "#{self.class}#create not implemented"
      end

      # Returns the {Session} with the given id, or `nil` if it doesn't
      # exist (or has already been cleaned up).
      def find(id)
        fail NotImplementedError, "#{self.class}#find not implemented"
      end

      # Persists changes to an existing session.
      def update(session)
        fail NotImplementedError, "#{self.class}#update not implemented"
      end

      # Writes `chunk` (a binary String) at the given absolute byte offset
      # into the session's assembly.
      def write_chunk(session, start_offset, chunk)
        fail NotImplementedError, "#{self.class}#write_chunk not implemented"
      end

      # Reads up to `length` previously stored bytes starting at
      # `start_offset`. Returns a binary String (which may be shorter than
      # requested near the end of the assembly).
      def read_chunk(session, start_offset, length)
        fail NotImplementedError, "#{self.class}#read_chunk not implemented"
      end

      # Opens the assembled content for reading and yields the IO object.
      def open(session, &block)
        fail NotImplementedError, "#{self.class}#open not implemented"
      end

      # Removes the partially assembled content for the session. Published
      # files live in the Shrine storage and are never touched here.
      def delete_content(session)
        fail NotImplementedError, "#{self.class}#delete_content not implemented"
      end

      # Deletes the session record together with its assembled content.
      def delete(session)
        fail NotImplementedError, "#{self.class}#delete not implemented"
      end

      # Yields every persisted session.
      def each_session
        fail NotImplementedError, "#{self.class}#each_session not implemented"
      end

      # Removes sessions that have expired. Returns the deleted sessions.
      # Published files in the destination Shrine storage are intentionally
      # not affected.
      def cleanup(now = Time.now.utc)
        expired = []
        each_session do |session|
          next unless session.expired?(now)

          delete(session)
          expired << session
        end
        expired
      end

      include Enumerable

      def each(&block)
        each_session(&block)
      end
    end

    # In-memory session store. All state lives in process memory, which
    # makes it the default implementation suitable for local testing.
    class MemorySessionStore < SessionStore
      def initialize(sessions: {}, assemblies: {})
        @sessions  = sessions
        @assemblies = assemblies
        @mutex = Mutex.new
      end

      def create(session)
        @mutex.synchronize do
          fail Shrine::Error, "session #{session.id.inspect} already exists" if @sessions.key?(session.id)

          @sessions[session.id] = session
          @assemblies[session.id] = String.new.force_encoding(Encoding::BINARY)
        end
      end

      def find(id)
        @mutex.synchronize { @sessions[id] }
      end

      def update(session)
        @mutex.synchronize do
          fail Shrine::Error, "session #{session.id.inspect} doesn't exist" unless @sessions.key?(session.id)

          @sessions[session.id] = session
        end
      end

      def write_chunk(session, start_offset, chunk)
        @mutex.synchronize do
          assembly = @assemblies.fetch(session.id)
          pad!(assembly, start_offset)
          assembly[start_offset, chunk.bytesize] = chunk
        end
      end

      def read_chunk(session, start_offset, length)
        @mutex.synchronize do
          assembly = @assemblies.fetch(session.id)
          assembly.byteslice(start_offset, length).to_s
        end
      end

      def open(session)
        io = @mutex.synchronize { StringIO.new(@assemblies.fetch(session.id).dup) }

        if block_given?
          begin
            yield io
          ensure
            io.close
          end
        else
          io
        end
      end

      def delete_content(session)
        @mutex.synchronize do
          @assemblies[session.id] = String.new.force_encoding(Encoding::BINARY)
        end
      end

      def delete(session)
        @mutex.synchronize do
          @sessions.delete(session.id)
          @assemblies.delete(session.id)
        end
      end

      def each_session
        @mutex.synchronize { @sessions.values.dup }.each { |session| yield session }
      end

      def clear!
        @mutex.synchronize do
          @sessions.clear
          @assemblies.clear
        end
      end

      private

      # Out-of-order chunks can target offsets beyond the current size. The
      # padding is never trusted as received data (confirmed ranges are
      # tracked separately on the session), it only keeps the String
      # writable.
      def pad!(assembly, start_offset)
        return if start_offset <= assembly.bytesize

        assembly << ("\0".b * (start_offset - assembly.bytesize))
      end
    end

    # Filesystem-backed session store. Session metadata is kept in JSON
    # files and partially uploaded bytes in `*.part` files, so state
    # survives across requests (and processes) on a single machine.
    class FileSystemSessionStore < SessionStore
      SESSION_SUFFIX = ".json"
      ASSEMBLY_SUFFIX = ".part"

      attr_reader :directory

      def initialize(directory)
        @directory = File.expand_path(directory)
        FileUtils.mkdir_p(@directory)
      end

      def create(session)
        File.open(session_path(session.id), File::WRONLY | File::CREAT | File::EXCL) do |file|
          file.write(serialize(session))
        end
        FileUtils.touch(assembly_path(session.id))
      end

      def find(id)
        return nil unless valid_id?(id) && File.exist?(session_path(id))

        Session.from_h(JSON.parse(File.read(session_path(id))))
      end

      def update(session)
        File.write(session_path(session.id), serialize(session))
      end

      def write_chunk(session, start_offset, chunk)
        with_assembly(session) do |file|
          file.seek(start_offset)
          file.write(chunk)
        end
      end

      def read_chunk(session, start_offset, length)
        with_assembly(session) do |file|
          file.seek(start_offset)
          file.read(length).to_s
        end
      end

      def open(session)
        file = File.open(assembly_path(session.id), "rb")

        if block_given?
          begin
            yield file
          ensure
            file.close
          end
        else
          file
        end
      end

      def delete_content(session)
        FileUtils.rm_f(assembly_path(session.id))
      end

      def delete(session)
        delete_content(session)
        FileUtils.rm_f(session_path(session.id))
      end

      def each_session
        Dir.glob(File.join(@directory, "*#{SESSION_SUFFIX}")).sort.each do |path|
          yield Session.from_h(JSON.parse(File.read(path)))
        end
      end

      private

      def serialize(session)
        JSON.pretty_generate(session.to_h)
      end

      def session_path(id)
        File.join(@directory, "#{id}#{SESSION_SUFFIX}")
      end

      def assembly_path(id)
        File.join(@directory, "#{id}#{ASSEMBLY_SUFFIX}")
      end

      # Only ever open session files for generated ids.
      def valid_id?(id)
        id.is_a?(String) && id.match?(/\A[A-Za-z0-9_-]+\z/)
      end

      # Exclusive file lock keeps concurrent (and cross-process) chunk
      # submissions for the same session serialized.
      def with_assembly(session)
        File.open(assembly_path(session.id), File::RDWR | File::CREAT) do |file|
          file.flock(File::LOCK_EX)
          file.binmode
          result = yield file
          file.flush
          result
        end
      end
    end
  end
end
