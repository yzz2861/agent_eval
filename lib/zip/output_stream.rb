# frozen_string_literal: true

require 'forwardable'

##
module Zip
  # ZipOutputStream is the basic class for writing zip files. It is
  # possible to create a ZipOutputStream object directly, passing
  # the zip file name to the constructor, but more often than not
  # the ZipOutputStream will be obtained from a ZipFile (perhaps using the
  # ZipFileSystem interface) object for a particular entry in the zip
  # archive.
  #
  # A ZipOutputStream inherits IOExtras::AbstractOutputStream in order
  # to provide an IO-like interface for writing to a single zip
  # entry. Beyond methods for mimicking an IO-object it contains
  # the method put_next_entry that closes the current entry
  # and creates a new.
  #
  # Please refer to ZipInputStream for example code.
  #
  # java.util.zip.ZipOutputStream is the original inspiration for this
  # class.
  class OutputStream
    extend Forwardable
    include ::Zip::IOExtras::AbstractOutputStream

    def_delegators :@cdir, :comment, :comment=

    # Opens the indicated zip file. If a file with that name already
    # exists it will be overwritten.
    def initialize(file_name, stream: false, encrypter: nil, suppress_extra_fields: false,
                   forward_only: false, zip64: nil, **opts)
      super(**opts)
      @file_name = file_name
      @output_stream = if stream
                         iostream = Zip::RUNNING_ON_WINDOWS ? @file_name : @file_name.dup
                         unless forward_only
                           iostream.reopen(@file_name)
                           iostream.rewind
                         end
                         iostream
                       else
                         ::File.new(@file_name, 'wb')
                       end
      if forward_only
        @output_stream = IOExtras::WriteOnlyIO.new(@output_stream)
        @output_stream.binmode
      end
      @cdir = ::Zip::CentralDirectory.new
      @compressor = ::Zip::NullCompressor.instance
      @encrypter = encrypter || ::Zip::NullEncrypter.new
      @suppress_extra_fields = suppress_extra_fields
      @forward_only = forward_only
      @zip64 = zip64
      @closed = false
      @aborted = false
      @current_entry = nil
    end

    class << self
      # Same as #initialize but if a block is passed the opened
      # stream is passed to the block and closed when the block
      # returns.
      def open(file_name, encrypter: nil, suppress_extra_fields: false, **opts)
        unless block_given?
          return new(
            file_name,
            encrypter:             encrypter,
            suppress_extra_fields: suppress_extra_fields,
            **opts
          )
        end

        zos = new(file_name, stream: false, encrypter: encrypter,
                  suppress_extra_fields: suppress_extra_fields, **opts)
        yield zos
      ensure
        zos.close if zos
      end

      # Same as #open but writes to a filestream instead
      def write_buffer(io = ::StringIO.new, encrypter: nil, suppress_extra_fields: false, **opts)
        io.binmode if io.respond_to?(:binmode)
        zos = new(io, stream: true, encrypter: encrypter,
                  suppress_extra_fields: suppress_extra_fields, **opts)
        yield zos
        zos.close_buffer
      end

      # Writes a complete zip archive to an IO that only supports writing
      # sequentially, such as a pipe. Local file headers use a data
      # descriptor, and the IO is never rewound or seeked.
      #
      # Zip64 follows +Zip.write_zip64_support+ by default. Pass
      # +zip64: false+ for archives known to remain within the 32-bit
      # limits, or +zip64: true+ to reserve Zip64 fields in every local
      # entry before its data is written.
      def write_stream(
        io = ::StringIO.new, encrypter: nil, suppress_extra_fields: false,
        zip64: nil, **opts
      )
        zos = new(
          io,
          stream:               true,
          forward_only:         true,
          encrypter:            encrypter,
          suppress_extra_fields: suppress_extra_fields,
          zip64:                zip64,
          **opts
        )
        yield zos
        zos.close_buffer
      end
    end

    # Closes the stream and writes the central directory to the zip file
    def close
      return if @closed
      raise IOError, 'zip stream has encountered an error and cannot be finalized' if @aborted

      begin
        finalize_current_entry
        write_central_directory
      rescue StandardError
        @aborted = true
        raise
      end
      @output_stream.close
      @closed = true
    end

    # Closes the stream and writes the central directory to the zip file
    def close_buffer
      return @output_stream if @closed
      raise IOError, 'zip stream has encountered an error and cannot be finalized' if @aborted

      begin
        finalize_current_entry
        write_central_directory
      rescue StandardError
        @aborted = true
        raise
      end
      @closed = true
      @output_stream.flush
      @output_stream
    end

    # Closes the current entry and opens a new for writing.
    # +entry+ can be a ZipEntry object or a string.
    #
    # Raises Zip::EntryExistsError if an entry with the same name has
    # already been written to this stream, unless
    # Zip.allow_duplicate_entry_names is on.
    def put_next_entry(
      entry_name, comment = '', extra = ExtraField.new,
      compression_method = Entry::DEFLATED, level = Zip.default_compression
    )
      raise Error, 'zip stream is closed' if @closed
      raise Error, 'zip stream has encountered an error' if @aborted

      new_entry =
        if entry_name.kind_of?(Entry) || entry_name.kind_of?(StreamableStream)
          entry_name
        else
          Entry.new(
            @file_name, entry_name.to_s, comment: comment, extra: extra,
            compression_method: compression_method, compression_level: level
          )
        end

      init_next_entry(new_entry)
      @current_entry = new_entry
    end

    def copy_raw_entry(entry) # :nodoc:
      entry = entry.dup
      raise Error, 'zip stream is closed' if @closed
      raise Error, 'zip stream has encountered an error' if @aborted
      raise Error, 'copy_raw_entry is not supported for forward-only streams' if @forward_only
      raise Error, 'entry is not a ZipEntry' unless entry.kind_of?(Entry)

      finalize_current_entry
      check_duplicate_name(entry, 'copy_raw_entry')
      @cdir << entry
      src_pos = entry.local_header_offset
      entry.write_local_entry(@output_stream)
      @compressor = NullCompressor.instance
      entry.get_raw_input_stream do |is|
        is.seek(src_pos, IO::SEEK_SET)
        ::Zip::Entry.read_local_entry(is)
        IOExtras.copy_stream_n(@output_stream, is, entry.compressed_size)
      end
      @compressor = NullCompressor.instance
      @current_entry = nil
    end

    private

    def finalize_current_entry
      return unless @current_entry

      begin
        finish
        @output_stream << @encrypter.trailer unless @current_entry.directory?
        update_current_entry_metadata
        verify_forward_limits unless @current_entry.directory?
        @output_stream << data_descriptor if @forward_only && !@current_entry.directory?
      rescue StandardError
        @aborted = true
        raise
      end

      @current_entry = nil
      @compressor = ::Zip::NullCompressor.instance
    end

    def init_next_entry(entry)
      finalize_current_entry
      check_duplicate_name(entry, 'put_next_entry')
      entry.zip64_strategy = @zip64
      prepare_forward_flags(entry) if @forward_only
      @encrypter.prepare_entry(entry)
      @cdir << entry
      begin
        entry.write_local_entry(@output_stream, suppress_extra_fields: @suppress_extra_fields)
        @encrypter.reset!
        @output_stream << @encrypter.header(entry.mtime) unless entry.directory?
        @compressor = get_compressor(entry)
      rescue StandardError
        @aborted = true
        raise
      end
    end

    def check_duplicate_name(entry, proc_name)
      return if Zip.allow_duplicate_entry_names
      return unless @cdir.include?(entry.name)

      raise EntryExistsError.new(proc_name, entry.name)
    end

    def get_compressor(entry)
      case entry.compression_method
      when Entry::DEFLATED
        ::Zip::Deflater.new(@output_stream, entry.compression_level, @encrypter)
      when Entry::STORED
        ::Zip::PassThruCompressor.new(@output_stream, @encrypter)
      else
        raise ::Zip::CompressionMethodError, entry.compression_method
      end
    end

    def use_zip64?
      return Zip.write_zip64_support if @zip64.nil?

      @zip64
    end

    def prepare_forward_flags(entry)
      entry.gp_flags |= 0x08 unless entry.directory?
      entry.gp_flags |= @encrypter.gp_flags unless entry.directory?
      if entry.file? && use_zip64?
        entry.size = 0xFFFFFFFF
        entry.compressed_size = 0xFFFFFFFF
        entry.reserve_local_zip64_lengths!
        return
      end
      return unless entry.size.nil? || entry.size >= 0xFFFFFFFF ||
                    entry.compressed_size >= 0xFFFFFFFF ||
                    @output_stream.tell + entry.calculate_local_header_size >= 0xFFFFFFFF

      raise Error,
            "Zip64 is required for entry '#{entry.name}', but it was disabled for this stream"
    end

    def update_current_entry_metadata
      @current_entry.compressed_size = @output_stream.tell -
                                       @current_entry.local_header_offset -
                                       @current_entry.calculate_local_header_size
      @current_entry.size = @compressor.size
      @current_entry.crc = @encrypter.crc(@compressor.crc)
      @current_entry.gp_flags |= @encrypter.gp_flags unless @current_entry.directory?

      return unless @current_entry.zip64?

      zip64 = @current_entry.extra[:zip64]
      zip64.original_size = @current_entry.size
      zip64.compressed_size = @current_entry.compressed_size
    end

    def verify_forward_limits
      return if use_zip64?

      if @current_entry.size >= 0xFFFFFFFF ||
         @current_entry.compressed_size >= 0xFFFFFFFF
        raise Error, "Entry '#{@current_entry.name}' requires Zip64 extensions"
      end
    end

    def data_descriptor
      if @encrypter.is_a?(NullEncrypter)
        [SPLIT_FILE_SIGNATURE, @current_entry.crc,
         @current_entry.compressed_size, @current_entry.size].pack('VVVV')
      else
        @encrypter.data_descriptor(
          @current_entry.crc,
          @current_entry.compressed_size,
          @current_entry.size
        )
      end
    end

    def write_central_directory
      update_local_headers unless @forward_only
      @cdir.write_to_stream(
        @output_stream,
        suppress_extra_fields: @suppress_extra_fields,
        zip64:                @forward_only ? use_zip64? : nil
      )
    end

    def update_local_headers
      pos = @output_stream.pos
      @cdir.each do |entry|
        @output_stream.pos = entry.local_header_offset
        entry.write_local_entry(@output_stream, suppress_extra_fields: @suppress_extra_fields,
                                                rewrite:               true)
      end
      @output_stream.pos = pos
    end

    protected

    def finish # :nodoc:
      @compressor.finish
    end

    public

    # Modeled after IO.<<
    def <<(data)
      begin
        @compressor << data
      rescue StandardError
        @aborted = true
        raise
      end
      self
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
