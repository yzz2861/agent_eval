# frozen_string_literal: true

require_relative 'constants'

module Zip
  # A write-only, non-rewindable view over an arbitrary target IO.
  #
  # Only `write` (and, optionally, `binmode`/`flush`/`close`) are used, so the
  # target does not need to support `seek`, `pos`, `tell` or `rewind` (an
  # operating-system pipe, an HTTP request body, etc.). The number of bytes
  # emitted is tracked locally instead of being asked for from the target.
  #
  # Ruby IO objects are allowed to return from `write` before all the given
  # bytes have been accepted (a "short write"). That is handled here by
  # retrying with the remainder.
  class WriteOnlyIO
    attr_reader :bytes_written, :target

    def initialize(target)
      @target = target
      @bytes_written = 0
    end

    def binmode
      @target.binmode if @target.respond_to?(:binmode)
      self
    end

    def flush
      @target.flush if @target.respond_to?(:flush)
    end

    def close
      @target.close if @target.respond_to?(:close)
    end

    def tell
      @bytes_written
    end
    alias pos tell

    # Modeled after the other zip output streams.
    def <<(data)
      write_all(data.to_s)
      self
    end

    def write(data)
      write_all(data.to_s)
    end

    private

    def write_all(data)
      total = 0
      while total < data.bytesize
        written = @target.write(data.byteslice(total..-1))
        if written.nil? || written.negative?
          raise IOError, "underlying IO returned #{written.inspect} from write"
        end
        raise IOError, 'underlying IO wrote 0 bytes without blocking' if written.zero?
        remaining_bytes = data.bytesize - total
        if written > remaining_bytes
          raise IOError, 'underlying IO wrote more bytes than were given'
        end

        total += written
        @bytes_written += written
      end
      total
    end
  end

  # Writes a zip archive strictly from start to finish to an IO that only
  # needs to respond to `write`. Nothing is ever seeked back to or rewritten:
  #
  # * Every file entry is emitted with bit 3 of the general purpose flags
  #    set, zero CRC/sizes in the local header, and a data descriptor after
  #    the entry data carrying the values that are only known then.
  #  * The central directory and end-of-central-directory record are written
  #    once, at the very end.
  #
  # Because the local header cannot be revisited, the zip64 decision has to
  # be made up front:
  #
  #  * `zip64: false` (the default) writes a classic archive and fails fast
  #    with {Zip64RequiredError} as soon as an entry's size, its compressed
  #    size, an entry's header offset, or the number of entries approaches
  #    the 32-bit limit. No corrupt archive is produced.
  #  * `zip64: true` writes every entry with zip64 extra fields (with the
  #    conventional zero placeholders in the local header), an 8-byte data
  #    descriptor and a zip64 end-of-central-directory record.
  class ForwardOutputStream
    include ::Zip::IOExtras::AbstractOutputStream

    DATA_DESCRIPTOR_SIGNATURE = 0x08074b50

    ZIP32_MAX = 0xFFFFFFFF
    ZIP32_MAX_ENTRIES = 0xFFFF

    # @param target [#write] an IO that accepts bytes; it does not need to be
    #   seekable or positionable.
    # @param zip64 [Boolean] whether zip64 extensions are committed to before
    #   anything is written (see the class description).
    # @param encrypter [Zip::Encrypter, nil] optional entry encrypter.
    # @param comment [String] archive comment for the end record.
    def initialize(target, zip64: false, encrypter: nil, comment: '')
      @io = WriteOnlyIO.new(target)
      @io.binmode
      @zip64 = zip64
      @encrypter = encrypter || NullEncrypter.new
      @cdir = CentralDirectory.new
      @cdir.comment = comment
      @compressor = NullCompressor.instance
      @current_entry = nil
      @entry_start = 0
      @closed = false
    end

    class << self
      # Streams a zip archive to the given write-only IO. The IO is flushed
      # but *not* closed when the block returns, so it is safe to pass a pipe
      # or a request body that the caller manages.
      def write_stream(target, zip64: false, encrypter: nil, comment: '')
        zos = new(
          target,
          zip64:    zip64,
          encrypter: encrypter,
          comment:  comment
        )
        return zos unless block_given?

        begin
          yield zos
        rescue StandardError
          zos.abort
          raise
        end
        zos.finish
        zos
      end
    end

    def comment
      @cdir.comment
    end

    def comment=(value)
      @cdir.comment = value
    end

    # Starts a new entry, finalising the current one first. +entry_or_name+
    # may be a {Zip::Entry}, a {Zip::StreamableStream} or a name string.
    def put_next_entry(
      entry_or_name, comment = '', extra = ExtraField.new,
      compression_method = Entry::DEFLATED, level = Zip.default_compression
    )
      check_open!
      entry =
        if entry_or_name.kind_of?(Entry) || entry_or_name.kind_of?(StreamableStream)
          entry_or_name
        else
          Entry.new(
            nil, entry_or_name.to_s, comment: comment, extra: extra,
            compression_method: compression_method, compression_level: level
          )
        end

      finalize_current_entry
      check_duplicate_name(entry)
      start_entry(entry)
      @current_entry = entry
    end

    # Writes the final data descriptor for the current entry, then the central
    # directory and end-of-central-directory record, and closes the target IO.
    def close
      finish_archive(close_io: true)
    end

    # Like #close but leaves the target IO open (only flushed).
    def finish
      finish_archive(close_io: false)
    end

    # Gives up on the archive without writing a central directory. The stream
    # is closed afterwards, so no further entries can be added and a later
    # call to #close cannot make the partial output look complete.
    def abort
      @current_entry = nil
      @compressor = NullCompressor.instance
      @closed = true
    end

    def closed?
      @closed
    end

    # Modeled after IO.<<
    def <<(data)
      check_open!
      @compressor << data
      self
    end

    private

    def check_open!
      raise IOError, 'zip stream is closed' if @closed
    end

    def check_duplicate_name(entry)
      return if Zip.allow_duplicate_entry_names
      return unless @cdir.include?(entry.name)

      raise EntryExistsError.new('put_next_entry', entry.name)
    end

    def start_entry(entry)
      check_32bit_limit(@io.tell, ZIP32_MAX, 'local header offset') unless @zip64
      unless @zip64
        check_32bit_limit(@cdir.size, ZIP32_MAX_ENTRIES, 'number of entries')
      end

      @encrypter.prepare_entry(entry)
      @cdir << entry

      unless entry.directory?
        # CRC and sizes are only known after the data has been written, so
        # they are deferred to the data descriptor (bit 3).
        entry.gp_flags |= 0x08
        entry.gp_flags |= @encrypter.gp_flags
      end

      prepare_entry_zip64(entry)

      entry.local_header_offset = @io.tell
      # Sizes are unknown here; write zero placeholders and let the data
      # descriptor (and the central directory) carry the real values.
      entry.size = 0
      entry.compressed_size = 0
      entry.crc = 0
      entry.write_local_entry(@io)

      @entry_start = @io.tell
      @encrypter.reset!
      @io << @encrypter.header(entry.mtime) unless entry.directory?
      @compressor = get_compressor(entry)
    end

    def prepare_entry_zip64(entry)
      return unless @zip64 && entry.file?

      entry.version_needed_to_extract =
        [entry.version_needed_to_extract, VERSION_NEEDED_TO_EXTRACT_ZIP64].max
      zip64 = entry.extra[:zip64] || entry.extra.create(:zip64)
      # The local zip64 extra must contain both size fields. Their values are
      # not known yet, so the conventional zero placeholders are used.
      zip64.original_size = 0
      zip64.compressed_size = 0
    end

    def get_compressor(entry)
      case entry.compression_method
      when Entry::DEFLATED
        Deflater.new(@io, entry.compression_level, @encrypter)
      when Entry::STORED
        PassThruCompressor.new(@io, @encrypter)
      else
        raise CompressionMethodError, entry.compression_method
      end
    end

    def finalize_current_entry
      return unless @current_entry

      entry = @current_entry
      @compressor.finish
      @io << @encrypter.trailer unless entry.directory?

      data_end = @io.tell
      entry.compressed_size = data_end - @entry_start
      entry.size = @compressor.size
      entry.crc = @encrypter.crc(@compressor.crc)

      if entry.zip64?
        entry.extra[:zip64].original_size = entry.size
        entry.extra[:zip64].compressed_size = entry.compressed_size
      end

      unless entry.zip64?
        check_32bit_limit(entry.size, ZIP32_MAX, "uncompressed size of '#{entry.name}'")
        check_32bit_limit(
          entry.compressed_size, ZIP32_MAX, "compressed size of '#{entry.name}'"
        )
      end

      write_data_descriptor(entry) unless entry.directory?
      @current_entry = nil
      @compressor = NullCompressor.instance
    end

    def write_data_descriptor(entry)
      if entry.zip64?
        @io << [
          DATA_DESCRIPTOR_SIGNATURE,
          entry.crc,
          entry.compressed_size,
          entry.size
        ].pack('VVQ<Q<')
      else
        # The traditional encrypter's own descriptor is identical to this
        # one, and AES writes its authentication code as a trailer first, so
        # a single explicit descriptor works for every encrypter here.
        @io << [
          DATA_DESCRIPTOR_SIGNATURE,
          entry.crc,
          entry.compressed_size,
          entry.size
        ].pack('VVVV')
      end
    end

    def finish_archive(close_io:)
      return if @closed

      finalize_current_entry
      unless @zip64
        check_32bit_limit(@io.tell, ZIP32_MAX, 'central directory offset')
        check_32bit_limit(@cdir.size, ZIP32_MAX_ENTRIES, 'number of entries')
      end
      @cdir.write_to_stream(@io, force_zip64: @zip64)
      @io.flush
      @io.close if close_io
      @closed = true
    end

    def check_32bit_limit(value, limit, what)
      raise Zip64RequiredError.new(value, what) if value >= limit
    end
  end
end
