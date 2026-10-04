# frozen_string_literal: true

require "securerandom"
require "digest"
require "stringio"

class Shrine
  # Service that drives resumable, chunked uploads. It is storage agnostic
  # on the session side (see {ResumableUpload::SessionStore}) and publishes
  # finalized files to a registered Shrine storage.
  class ResumableUpload
    # Base error for resumable upload failures. Carries an HTTP status used
    # by the Rack endpoint.
    class Error < Shrine::Error
      STATUS = 400

      def status
        self.class.const_get(:STATUS)
      end
    end

    # The session is unknown or has been cleaned up.
    class SessionNotFound < Error
      STATUS = 404
    end

    # The chunk targeted bytes outside the declared total length.
    class RangeInvalid < Error
      STATUS = 416
    end

    # Bytes in the range were already received with different content, or
    # the range partially overlaps an already confirmed range.
    class Conflict < Error
      STATUS = 409
    end

    # finalize was requested before the complete length was received.
    class Incomplete < Error
      STATUS = 409
    end

    # The assembled content did not match the checksum declared at session
    # creation.
    class ChecksumMismatch < Error
      STATUS = 460
    end

    # Operation was requested on a session that is already finalized.
    class AlreadyFinalized < Error
      STATUS = 409
    end

    # Supported algorithms for the "<algorithm>=<digest>" checksum format.
    CHECKSUM_ALGORITHMS = %w[sha1 sha256 sha384 sha512 md5].freeze

    # Writes given options to instance variables.
    def initialize(options)
      options.each do |name, value|
        instance_variable_set("@#{name}", value)
      end

      @session_store ||= Shrine::ResumableUpload::MemorySessionStore.new
      @expires_in    ||= 24 * 60 * 60
      @id_generator  ||= -> { SecureRandom.hex(16) }
      @locks         = Hash.new { |hash, key| hash[key] = Mutex.new }
      @locks_mutex   = Mutex.new
    end

    # The Shrine storage that finalized files are published to.
    def storage
      @shrine_class.find_storage(@storage_key)
    end

    # The store holding session metadata and partial content.
    attr_reader :session_store

    # Creates a new upload session.
    #
    # Options:
    #
    # :total_size
    # :  Total byte length of the file (required).
    # :checksum
    # :  Expected content digest in the `"sha256=<hex>"` format (optional).
    # :filename / :content_type
    # :  Metadata remembered until finalization.
    # :expires_in
    # :  Per-session lifetime in seconds (overrides the service default).
    def create_session(total_size:, checksum: nil, filename: nil, content_type: nil,
                       expires_in: nil, **)
      total_size = coerce_size!(total_size)
      fail Error, "total_size cannot be negative" if total_size.negative?
      expires_in = expires_in.nil? ? nil : Integer(expires_in)

      validate_checksum!(checksum) if checksum

      now = Time.now.utc
      session = Session.new(
        id:           @id_generator.call,
        total_size:   total_size,
        checksum:     normalize_checksum(checksum),
        filename:     filename,
        content_type: content_type,
        ranges:       [],
        created_at:   now,
        expires_at:   now + (expires_in || @expires_in),
      )

      session_store.create(session)

      # An empty file is complete immediately, but it is not published
      # until finalize is called.
      session
    end

    # Returns the session for the given id. Raises {SessionNotFound} for
    # unknown ids (expired sessions are treated as missing).
    def get_session(id)
      fetch_session(id)
    end

    # Confirms a chunk of bytes.
    #
    # `chunk` must be a binary String. `start_offset` is the absolute byte
    # offset where the chunk starts; the end offset is derived from the
    # chunk length.
    #
    # Re-submitting an already confirmed range with identical content is
    # idempotent and succeeds. Different content for a fully confirmed
    # range and partial overlap with a confirmed range are rejected with
    # {Conflict}.
    def put_chunk(id, chunk, start_offset:)
      chunk = chunk.to_s
      chunk = chunk.dup.force_encoding(Encoding::BINARY) unless chunk.encoding == Encoding::BINARY
      start_offset = Integer(start_offset)
      end_offset   = start_offset + chunk.bytesize

      with_session_lock(id) do
        session = fetch_session(id)
        fail_already_finalized!(session) if session.finalized?

        validate_range!(session, start_offset, end_offset)
        return session if chunk.bytesize.zero?
        disposition = verify_chunk!(session, start_offset, end_offset, chunk)

        session_store.write_chunk(session, start_offset, chunk)
        if disposition == :new
          session.ranges << [start_offset, end_offset]
          session_store.update(session)
        end

        session
      end
    end

    # Finalizes a session: verifies the complete length and the declared
    # content checksum, then publishes the assembled bytes to the Shrine
    # storage and returns the resulting `Shrine::UploadedFile`.
    #
    # Finalizing is idempotent: a second call for an already finalized
    # session returns the same published file instead of publishing
    # another one.
    def finalize(id, **options)
      with_session_lock(id) do
        session = session_store.find(id)
        fail SessionNotFound, "upload session #{id.inspect} not found" if session.nil?

        return published_file(session) if session.finalized?

        fail SessionNotFound, "upload session #{id.inspect} has expired" if session.expired?

        fail Incomplete, "upload is not complete: #{session.received_size} of #{session.total_size} bytes received" unless session.complete?

        verify_checksum!(session)

        uploaded_file = publish(session, **options)

        session.uploaded_file_data = uploaded_file.data
        session_store.update(session)

        uploaded_file
      end
    end

    # Aborts an unfinished session, discarding its partially assembled
    # content. Published files are never deleted by this method.
    def abort(id)
      with_session_lock(id) do
        session = fetch_session(id)
        fail_already_finalized!(session) if session.finalized?

        session_store.delete(session)
        nil
      end
    end

    # Removes expired sessions and their assembled content. Returns the
    # deleted {Session} objects. Files already published to the Shrine
    # storage are left untouched.
    def cleanup(now = Time.now.utc)
      session_store.cleanup(now)
    end

    # Returns the Rack application exposing this service.
    def endpoint
      @endpoint ||= ResumableUploadEndpoint.new(self)
    end

    def inspect
      "#<#{@shrine_class.inspect}::ResumableUpload(:#{@storage_key})>"
    end
    alias to_s inspect

    private

    def fetch_session(id)
      session = session_store.find(id)
      fail SessionNotFound, "upload session #{id.inspect} not found" if session.nil?
      fail SessionNotFound, "upload session #{id.inspect} has expired" if session.expired?

      session
    end

    def fail_already_finalized!(session)
      fail AlreadyFinalized, "upload session #{session.id.inspect} has already been finalized"
    end

    def validate_range!(session, start_offset, end_offset)
      if start_offset.negative? || end_offset > session.total_size
        fail RangeInvalid, "byte range #{start_offset}-#{end_offset} exceeds total size #{session.total_size}"
      end
      if end_offset < start_offset
        fail RangeInvalid, "byte range end offset cannot precede start offset"
      end
    end

    # Checks the incoming chunk against bytes already confirmed.
    #
    # A chunk is accepted when:
    #
    # * it doesn't touch any confirmed bytes (new range), or
    # * it lies completely within bytes already confirmed and its content
    #   matches (an idempotent retry of an exact range or a sub-range).
    #
    # Chunks that mix confirmed and unconfirmed bytes (partial overlap)
    # and chunks whose overlapping bytes differ in content are rejected
    # with {Conflict}.
    #
    # Returns `:new` or `:duplicate`.
    def verify_chunk!(session, start_offset, end_offset, chunk)
      confirmed_length = 0

      session.merged_ranges.each do |existing_start, existing_end|
        overlap_start = [start_offset, existing_start].max
        overlap_end   = [end_offset, existing_end].min

        next if overlap_end <= overlap_start

        # The chunk reaches beyond this confirmed range, so it mixes
        # confirmed and unconfirmed bytes: always reject.
        unless start_offset >= existing_start && end_offset <= existing_end
          fail Conflict, "byte range #{start_offset}-#{end_offset} partially overlaps confirmed range #{existing_start}-#{existing_end}"
        end

        stored = session_store.read_chunk(session, overlap_start, overlap_end - overlap_start)
        incoming = chunk.byteslice(overlap_start - start_offset, overlap_end - overlap_start)

        unless secure_compare_bytes(stored, incoming)
          fail Conflict, "received different content for already confirmed byte range #{overlap_start}-#{overlap_end}"
        end

        confirmed_length += overlap_end - overlap_start
      end

      if confirmed_length.zero?
        :new
      elsif confirmed_length == chunk.bytesize
        :duplicate
      else
        fail Conflict, "byte range #{start_offset}-#{end_offset} partially overlaps already confirmed ranges"
      end
    end

    def verify_checksum!(session)
      return if session.checksum.nil?

      algorithm, expected = session.checksum.split("=", 2)
      digest = Digest(algorithm.upcase).new

      session_store.open(session) do |io|
        io.binmode
        while (block = io.read(1024 * 1024))
          digest.update(block)
        end
      end

      unless secure_compare(digest.hexdigest!, expected)
        fail ChecksumMismatch, "content #{algorithm} checksum did not match what was declared"
      end
    end

    def publish(session, location: nil, metadata: nil, **)
      metadata = build_metadata(session, metadata)
      location ||= generate_location(session)

      session_store.open(session) do |assembly|
        io = StringIO.new(assembly.read)

        if @upload
          result = @upload.call(io, session, location: location, metadata: metadata)
        else
          result = uploader.upload(io, location: location, metadata: metadata, action: :resumable_upload)
        end
        result
      end
    end

    def build_metadata(session, override)
      metadata = {
        "filename"  => session.filename,
        "size"      => session.total_size,
        "mime_type" => session.content_type,
      }

      if @metadata
        metadata.merge!(@metadata.call(session) || {})
      end

      metadata.merge!(override) if override
      metadata
    end

    def generate_location(session)
      if @location
        @location.call(session)
      else
        extension = File.extname(session.filename.to_s).downcase
        SecureRandom.hex + extension
      end
    end

    def published_file(session)
      @shrine_class.uploaded_file(session.uploaded_file_data)
    end

    def uploader
      @uploader ||= @shrine_class.new(@storage_key)
    end

    def validate_checksum!(checksum)
      algorithm, = normalize_checksum(checksum).split("=", 2)
      unless CHECKSUM_ALGORITHMS.include?(algorithm)
        fail Error, "unsupported checksum algorithm #{algorithm.inspect}, supported: #{CHECKSUM_ALGORITHMS.join(", ")}"
      end
    end

    def normalize_checksum(checksum)
      return nil if checksum.nil?

      algorithm, digest = checksum.to_s.split("=", 2)
      fail Error, "checksum must be in the \"algorithm=hex-digest\" format" if digest.nil?

      "#{algorithm.downcase}=#{digest.downcase}"
    end

    def coerce_size!(total_size)
      Integer(total_size)
    rescue ArgumentError, TypeError
      fail Error, "total_size must be a non-negative integer"
    end

    # Constant-time string comparison, used so retry responses don't leak
    # byte differences through timing.
    def secure_compare(left, right)
      return false unless left.bytesize == right.bytesize

      secure_compare_bytes(left.b, right.b)
    end

    def secure_compare_bytes(left, right)
      left_bytes  = left.b
      right_bytes = right.b

      return false unless left_bytes.bytesize == right_bytes.bytesize

      result = 0
      left_bytes.each_byte.with_index { |byte, index| result |= byte ^ right_bytes.getbyte(index) }
      result.zero?
    end

    # Per-session mutex serializes concurrent requests inside one
    # process; session stores are responsible for cross-process safety.
    # The mutex map is kept for the lifetime of the service so that
    # concurrent requests never observe different locks for the same id.
    def with_session_lock(id, &block)
      mutex = @locks_mutex.synchronize { @locks[id] }
      mutex.synchronize(&block)
    end
  end
end
