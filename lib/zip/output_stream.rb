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
  #
  # Pass `reproducible: true` to buffer entries until close, write them in
  # sorted name order, and normalize timestamps, permissions, filesystem
  # markers, and non-essential extra fields. Byte-for-byte stability requires
  # the same compression implementation/version and archive options.
  class OutputStream
    extend Forwardable
    include ::Zip::IOExtras::AbstractOutputStream

    def_delegators :@cdir, :comment, :comment=

    # Opens the indicated zip file. If a file with that name already
    # exists it will be overwritten.
    def initialize(file_name, stream: false, encrypter: nil,
                   suppress_extra_fields: false, reproducible: false, **opts)
      super(**opts)
      @file_name = file_name
      @output_stream = if stream
                         iostream = Zip::RUNNING_ON_WINDOWS ? @file_name : @file_name.dup
                         iostream.reopen(@file_name)
                         iostream.rewind
                         iostream
                       else
                         ::File.new(@file_name, 'wb')
                       end
      @cdir = ::Zip::CentralDirectory.new
      @compressor = ::Zip::NullCompressor.instance
      @encrypter = encrypter || ::Zip::NullEncrypter.new
      @suppress_extra_fields = suppress_extra_fields
      @reproducible_options = ::Zip::ReproducibleOptions.new(reproducible)
      if @reproducible_options.enabled? && !@encrypter.is_a?(::Zip::NullEncrypter)
        raise ArgumentError, 'Cannot write a reproducible archive with encryption enabled'
      end
      @reproducible_entries = []
      @closed = false
      @current_entry = nil
    end

    class << self
      # Same as #initialize but if a block is passed the opened
      # stream is passed to the block and closed when the block
      # returns.
      def open(file_name, encrypter: nil, suppress_extra_fields: false,
               reproducible: false, **opts)
        unless block_given?
          return new(
            file_name,
            encrypter:             encrypter,
            suppress_extra_fields: suppress_extra_fields,
            reproducible:          reproducible,
            **opts
          )
        end

        zos = new(file_name, stream: false, encrypter: encrypter,
                  suppress_extra_fields: suppress_extra_fields,
                  reproducible: reproducible, **opts)
        yield zos
      ensure
        zos.close if zos
      end

      # Same as #open but writes to a filestream instead
      def write_buffer(io = ::StringIO.new, encrypter: nil,
                       suppress_extra_fields: false, reproducible: false, **opts)
        io.binmode if io.respond_to?(:binmode)
        zos = new(io, stream: true, encrypter: encrypter,
                  suppress_extra_fields: suppress_extra_fields,
                  reproducible: reproducible, **opts)
        yield zos
        zos.close_buffer
      end
    end

    # Closes the stream and writes the central directory to the zip file
    def close
      return if @closed

      begin
        finalize_current_entry
        unless @reproducible_options.enabled?
          update_local_headers
        end
        write_reproducible_entries if @reproducible_options.enabled?
        write_central_directory
      ensure
        cleanup_reproducible_entries if @reproducible_options.enabled?
      end
      @output_stream.close
      @closed = true
    end

    # Closes the stream and writes the central directory to the zip file
    def close_buffer
      return @output_stream if @closed

      begin
        finalize_current_entry
        unless @reproducible_options.enabled?
          update_local_headers
        end
        write_reproducible_entries if @reproducible_options.enabled?
        write_central_directory
      ensure
        cleanup_reproducible_entries if @reproducible_options.enabled?
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

      new_entry =
        if entry_name.kind_of?(Entry) || entry_name.kind_of?(StreamableStream)
          entry_name
        else
          Entry.new(
            @file_name, entry_name.to_s, comment: comment, extra: extra,
            compression_method: compression_method, compression_level: level
          )
        end

      if @reproducible_options.enabled?
        finalize_current_entry
        init_reproducible_next_entry(new_entry)
      else
        init_next_entry(new_entry)
        @current_entry = new_entry
      end
    end

    def copy_raw_entry(entry) # :nodoc:
      entry = entry.dup
      raise Error, 'zip stream is closed' if @closed
      raise Error, 'entry is not a ZipEntry' unless entry.kind_of?(Entry)
      if @reproducible_options.enabled?
        if entry.aes? || entry.encrypted?
          raise ArgumentError, 'Cannot write a reproducible archive with encryption enabled'
        end

        copy_raw_entry_reproducibly(entry)
        return
      end

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

    def write_central_directory
      @cdir.write_to_stream(
        @output_stream,
        suppress_extra_fields: @suppress_extra_fields,
        entries:               @reproducible_ordered_entries
      )
    end

    def check_reproducible_duplicate_name(entry, proc_name)
      return if Zip.allow_duplicate_entry_names
      if @reproducible_entries.none? { |(stored_entry, _)| stored_entry.name == entry.name }
        return
      end

      raise EntryExistsError.new(proc_name, entry.name)
    end

    def write_reproducible_entries
      @reproducible_ordered_entries = ordered_reproducible_pairs.map(&:first)
      ordered_reproducible_pairs.each do |stored_entry, tempfile|
        tempfile.rewind
        stored_entry.local_header_offset = @output_stream.tell
        stored_entry.write_local_entry(
          @output_stream,
          suppress_extra_fields: @suppress_extra_fields
        )
        ::Zip::IOExtras.copy_stream(@output_stream, tempfile)
      end
    end

    def cleanup_reproducible_entries
      @reproducible_entries.each { |_, tempfile| tempfile.close! }
      @reproducible_entries.clear
      @reproducible_ordered_entries = nil
    end

    def init_reproducible_next_entry(entry)
      check_reproducible_duplicate_name(entry, 'put_next_entry')
      if entry.aes? || entry.encrypted?
        raise ArgumentError, 'Cannot write a reproducible archive with encryption enabled'
      end

      entry.apply_reproducible_options!(@reproducible_options)
      tempfile = Tempfile.new('zip-reproducible-entry', encoding: Encoding::BINARY)
      tempfile.binmode
      @reproducible_entries << [entry, tempfile]
      @cdir << entry
      @current_entry = entry
      @compressor = get_reproducible_compressor(entry, tempfile)

      return unless block_given?

      yield(tempfile)
      finalize_reproducible_current_entry
    end

    def copy_raw_entry_reproducibly(entry)
      finalize_current_entry
      check_reproducible_duplicate_name(entry, 'copy_raw_entry')
      entry.get_raw_input_stream do |input|
        input.seek(entry.local_header_offset, IO::SEEK_SET)
        local_entry = ::Zip::Entry.read_local_entry(input)
        compression_method = local_entry.compression_method
        decompressor = case compression_method
                       when Entry::DEFLATED then ::Zip::Inflater.new(input)
                       when Entry::STORED
                         ::Zip::PassThruDecompressor.new(input, local_entry.size)
                       else raise ::Zip::CompressionMethodError, compression_method
                       end

        entry.compression_method = compression_method
        init_reproducible_next_entry(entry)
        remaining_size = local_entry.size
        until remaining_size.zero?
          chunk = decompressor.read(remaining_size)
          break unless chunk

          write(chunk)
          remaining_size -= chunk.bytesize
        end
        finalize_current_entry
      end
    end

    def get_reproducible_compressor(entry, output)
      case entry.compression_method
      when Entry::DEFLATED
        ::Zip::Deflater.new(output, entry.compression_level)
      when Entry::STORED
        ::Zip::PassThruCompressor.new(output)
      else
        raise ::Zip::CompressionMethodError, entry.compression_method
      end
    end

    def ordered_reproducible_pairs
      if @reproducible_options.sort_entries
        @reproducible_entries.sort_by.with_index do |(entry, _), index|
          [entry.name, index]
        end
      else
        @reproducible_entries
      end
    end

    def finalize_reproducible_current_entry
      return unless @current_entry

      finish
      tempfile = @reproducible_entries.assoc(@current_entry)&.last
      tempfile&.flush
      @current_entry.compressed_size = tempfile&.tell || @compressor.size
      @current_entry.size = @compressor.size
      @current_entry.crc = @compressor.crc
      @current_entry = nil
      @compressor = ::Zip::NullCompressor.instance
    end

    def finalize_current_entry
      return finalize_reproducible_current_entry if @reproducible_options.enabled?
      return unless @current_entry

      finish
      @output_stream << @encrypter.trailer unless @current_entry.directory?
      @current_entry.compressed_size = @output_stream.tell -
                                       @current_entry.local_header_offset -
                                       @current_entry.calculate_local_header_size
      @current_entry.size = @compressor.size
      @current_entry.crc = @encrypter.crc(@compressor.crc)
      @output_stream << @encrypter.data_descriptor(
        @current_entry.crc,
        @current_entry.compressed_size,
        @current_entry.size
      )
      @current_entry.gp_flags |= @encrypter.gp_flags unless @current_entry.directory?
      @current_entry = nil
      @compressor = ::Zip::NullCompressor.instance
    end

    def init_next_entry(entry)
      finalize_current_entry
      check_duplicate_name(entry, 'put_next_entry')
      @encrypter.prepare_entry(entry)
      @cdir << entry
      entry.write_local_entry(@output_stream, suppress_extra_fields: @suppress_extra_fields)
      @encrypter.reset!
      @output_stream << @encrypter.header(entry.mtime) unless entry.directory?
      @compressor = get_compressor(entry)
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
      @compressor << data
      self
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
