# frozen_string_literal: true

require "digest"
require "fileutils"

require "shrine/upload_session"

class Shrine
  module Storage
    class FileSystem
      attr_reader :upload_session_store, :upload_sessions_directory, :upload_session_ttl

      # Creates a new resumable upload session and returns the session ID.
      # The client must declare the total expected size up front. A content
      # checksum algorithm can be declared so that #finalize_upload_session
      # can verify the complete content.
      def create_upload_session(total_size:, id: nil, metadata: {}, checksum_algorithm: nil, ttl: nil)
        require_upload_sessions!

        total_size = Integer(total_size)
        raise ArgumentError, "total_size cannot be negative" if total_size < 0

        id ||= Shrine::UploadSession.generate_id
        validate_upload_session_id!(id)

        checksum_algorithm = normalize_checksum_algorithm(checksum_algorithm)

        now        = Time.now
        expires_at = now + (ttl || upload_session_ttl) if (ttl || upload_session_ttl)

        session = Shrine::UploadSession.new(
          id:                 id,
          total_size:         total_size,
          metadata:           normalize_upload_session_metadata(metadata),
          checksum_algorithm: checksum_algorithm,
          created_at:         now,
          updated_at:         now,
          expires_at:         expires_at,
        )

        upload_session_store.create(session)

        session
      end

      # Accepts a chunk for the given byte range. Chunks may be sent out of
      # order and re-sent after an interrupted upload.
      #
      # Resubmitting the exact same range with the exact same content is a
      # no-op (idempotent retry). Submitting different content for an already
      # accepted range, or a range that partially overlaps accepted ranges,
      # raises Shrine::UploadChunkConflict.
      def put_upload_chunk(session_id, io, offset:, length: nil)
        require_upload_sessions!

        start_offset = Integer(offset)
        raise ArgumentError, "offset cannot be negative" if start_offset < 0

        data = read_upload_chunk(io, length)
        end_offset = start_offset + data.bytesize

        raise ArgumentError, "cannot upload an empty chunk" if data.bytesize.zero?

        upload_session_store.fetch(session_id) do |session|
          ensure_active_upload_session!(session)

          if end_offset > session.total_size
            raise Shrine::UploadChunkOutOfRange,
                  "chunk ending at byte #{end_offset} exceeds declared size of #{session.total_size} bytes"
          end

          overlaps = overlapping_ranges(session.ranges, start_offset, end_offset)

          if overlaps.empty?
            write_upload_chunk!(session.id, start_offset, data)
            session.add_range!(start_offset, end_offset)
          elsif overlaps == [[start_offset, end_offset]]
            unless upload_chunk_matches?(session.id, start_offset, data)
              raise Shrine::UploadChunkConflict,
                    "received different content for the already accepted range #{start_offset}-#{end_offset}"
            end
          else
            raise Shrine::UploadChunkConflict,
                  "range #{start_offset}-#{end_offset} partially overlaps already accepted ranges #{session.ranges.inspect}"
          end

          session
        end
      end

      # Returns the current session state, including the confirmed byte
      # ranges. Raises Shrine::UploadSessionNotFound for unknown or expired
      # sessions.
      def get_upload_session(session_id)
        require_upload_sessions!

        session = upload_session_store.read(session_id)
        raise Shrine::UploadSessionNotFound, "upload session #{session_id.inspect} not found" if session.expired?

        session
      end
      alias upload_session get_upload_session

      # Finalizes a session: verifies that every declared byte was received
      # and, when a checksum was declared, verifies the complete content
      # digest. The staged content is then published atomically at its final
      # location and an {Shrine::UploadSession} with the published file id is
      # returned.
      #
      # Calling #finalize_upload_session twice returns the same result;
      # only the first call publishes a file.
      def finalize_upload_session(session_id, id: nil, checksum: nil, checksum_algorithm: nil)
        require_upload_sessions!

        upload_session_store.fetch(session_id) do |session|
          next session if session.finalized?

          ensure_active_upload_session!(session)

          unless session.complete?
            raise Shrine::UploadSessionIncomplete,
                  "upload session #{session_id.inspect} is incomplete: accepted ranges #{session.ranges.inspect} of #{session.total_size} bytes"
          end

          algorithm = normalize_checksum_algorithm(checksum_algorithm || session.checksum_algorithm)

          if checksum || algorithm
            raise ArgumentError, "a checksum algorithm must be provided when a checksum is given" if checksum && !algorithm
            raise ArgumentError, "a checksum is required to finalize session #{session_id.inspect}" if algorithm && !checksum

            calculated = calculate_upload_checksum(session.id, algorithm)
            unless checksum.to_s.downcase == calculated
              raise Shrine::UploadSessionIncomplete,
                    "content checksum mismatch for upload session #{session_id.inspect}"
            end
          end

          uploaded_id = id || generate_uploaded_id(session)
          publish_upload_session!(session.id, uploaded_id)

          session.uploaded_id = uploaded_id
          session.metadata     = session.metadata.merge("size" => session.total_size)
          session.updated_at   = Time.now

          session
        end
      end

      # Aborts an unfinished session and removes its staged chunks.
      def abort_upload_session(session_id)
        require_upload_sessions!

        upload_session_store.fetch(session_id) do |session|
          raise Shrine::UploadSessionClosed, "upload session #{session_id.inspect} is already finalized" if session.finalized?

          remove_staged_upload_chunks!(session.id)
          upload_session_store.delete(session.id)

          session
        end
      end

      # Removes sessions (and their staged chunks) that have passed their
      # expiration time. Published files are never touched by this.
      def prune_upload_sessions!(now = Time.now)
        require_upload_sessions!

        upload_session_store.prune_expired!(now).each do |session|
          remove_staged_upload_chunks!(session.id) unless session.finalized?
        end
      end

      # Whether this storage instance supports resumable upload sessions.
      def supports_upload_sessions?
        @upload_sessions_enabled
      end

      private

      def initialize_upload_sessions(upload_sessions:, upload_session_store:, upload_sessions_directory:, upload_session_ttl:)
        @upload_sessions_enabled    = upload_sessions
        @upload_session_store       = upload_session_store || Shrine::UploadSessions::Memory.new
        @upload_session_ttl         = upload_session_ttl
        @upload_sessions_directory  =
          directory.join(upload_sessions_directory || DEFAULT_UPLOAD_SESSIONS_DIRECTORY)
      end

      def require_upload_sessions!
        return if @upload_sessions_enabled

        raise Shrine::UploadSessionError, "upload sessions are disabled on this storage"
      end

      def ensure_active_upload_session!(session)
        raise Shrine::UploadSessionNotFound, "upload session #{session.id.inspect} not found" if session.expired?
      end

      def validate_upload_session_id!(id)
        return if id.is_a?(String) && id =~ /\A[A-Za-z0-9_-]+\z/

        raise ArgumentError, "upload session id #{id.inspect} is invalid"
      end

      def normalize_checksum_algorithm(algorithm)
        return nil if algorithm.nil?

        algorithm = algorithm.to_s.downcase
        supported = %w[md5 sha1 sha256 sha384 sha512]

        unless supported.include?(algorithm)
          raise ArgumentError, "unsupported checksum algorithm #{algorithm.inspect}"
        end

        algorithm
      end

      def normalize_upload_session_metadata(metadata)
        Hash(metadata).transform_keys(&:to_s)
      rescue TypeError, NoMethodError, ArgumentError
        raise ArgumentError, "metadata must be a hash"
      end

      def read_upload_chunk(io, length)
        data =
          if length
            length = Integer(length)
            raise ArgumentError, "length cannot be negative" if length < 0
            io.read(length)
          else
            io.read
          end

        (data || +"").dup.force_encoding(Encoding::BINARY)
      end

      def overlapping_ranges(ranges, start_offset, end_offset)
        ranges.filter_map do |range_start, range_end|
          overlap_start = [start_offset, range_start].max
          overlap_end   = [end_offset, range_end].min

          [overlap_start, overlap_end] if overlap_start < overlap_end
        end
      end

      def write_upload_chunk!(session_id, start_offset, data)
        FileUtils.mkdir_p(upload_sessions_directory, mode: directory_permissions)

        chunk_path = staged_chunks_path(session_id)
        mode       = chunk_path.exist? ? "r+b" : "w+b"

        File.open(chunk_path, mode) do |file|
          file.binmode
          file.pwrite(data, start_offset)
        end

        chunk_path.chmod(permissions) if permissions
      end

      def upload_chunk_matches?(session_id, start_offset, data)
        chunk_path = staged_chunks_path(session_id)
        return false unless chunk_path.file?

        chunk_path.open("rb") do |file|
          file.seek(start_offset)
          file.read(data.bytesize)
        end == data
      end

      def calculate_upload_checksum(session_id, algorithm)
        digest = Digest(algorithm.upcase)

        chunk_path = staged_chunks_path(session_id)
        return digest.hexdigest("") unless chunk_path.file? # empty files never staged chunks

        digest.file(chunk_path).hexdigest
      end

      def publish_upload_session!(session_id, uploaded_id)
        chunk_path = staged_chunks_path(session_id)
        target     = path!(uploaded_id)

        begin
          File.rename(chunk_path, target)
        rescue Errno::ENOENT
          # Empty files never had any chunks staged.
          FileUtils.touch(target)
        end

        target.chmod(permissions) if permissions
      end

      def remove_staged_upload_chunks!(session_id)
        staged_chunks_path(session_id).delete
      rescue Errno::ENOENT
      end

      def staged_chunks_path(session_id)
        validate_upload_session_id!(session_id)

        path = upload_sessions_directory.join("#{session_id}.part")
        expanded = path.expand_path

        unless expanded.to_s.start_with?("#{upload_sessions_directory.expand_path}#{File::SEPARATOR}")
          raise Shrine::UploadSessionNotFound, "upload session #{session_id.inspect} not found"
        end

        path
      end

      def generate_uploaded_id(session)
        extension = File.extname(session.metadata["filename"].to_s).downcase

        SecureRandom.hex(16) + extension
      end
    end
  end
end
