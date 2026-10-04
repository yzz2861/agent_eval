# frozen_string_literal: true

require 'forwardable'

require_relative 'dirtyable'

module Zip
  class CentralDirectory # :nodoc:
    extend Forwardable
    include Dirtyable

    END_OF_CD_SIG          = 0x06054b50
    ZIP64_END_OF_CD_SIG    = 0x06064b50
    ZIP64_EOCD_LOCATOR_SIG = 0x07064b50

    STATIC_EOCD_SIZE       = 22
    ZIP64_STATIC_EOCD_SIZE = 56
    ZIP64_EOCD_LOC_SIZE    = 20
    MAX_FILE_COMMENT_SIZE  = (1 << 16) - 1
    MAX_END_OF_CD_SIZE     =
      MAX_FILE_COMMENT_SIZE + STATIC_EOCD_SIZE + ZIP64_EOCD_LOC_SIZE

    attr_accessor :comment

    def_delegators :@entry_set,
                   :<<, :delete, :each, :entries, :find_entry, :glob,
                   :include?, :size

    mark_dirty :<<, :comment=, :delete

    def initialize(entries = EntrySet.new, comment = '') # :nodoc:
      super(dirty_on_create: false)
      @entry_set = entries.kind_of?(EntrySet) ? entries : EntrySet.new(entries)
      @comment   = comment
    end

    def read_from_stream(io)
      read_eocds(io)
      set_volume_count(io)
      read_central_directory_entries(io)
    end

    def write_to_stream(io, suppress_extra_fields: false) # :nodoc:
      cdir_offset = io.tell
      @entry_set.each do |entry|
        entry.write_c_dir_entry(io, suppress_extra_fields: suppress_extra_fields)
      end
      eocd_offset = io.tell
      cdir_size = eocd_offset - cdir_offset
      if Zip.write_zip64_support &&
         (cdir_offset > 0xFFFFFFFF || cdir_size > 0xFFFFFFFF || @entry_set.size > 0xFFFF)
        write_64_e_o_c_d(io, cdir_offset, cdir_size)
        write_64_eocd_locator(io, eocd_offset)
      end
      write_e_o_c_d(io, cdir_offset, cdir_size)
    end

    # Reads the End of Central Directory Record (and the Zip64 equivalent if
    # needs be) and returns the number of entries in the archive. This is a
    # convenience method that avoids reading in all of the entry data to get a
    # very quick entry count.
    def count_entries(io)
      read_eocds(io)
      set_volume_count(io)
      @size
    end

    def ==(other) # :nodoc:
      return false unless other.kind_of?(CentralDirectory)

      @entry_set.entries.sort == other.entries.sort && comment == other.comment
    end

    private

    def write_e_o_c_d(io, offset, cdir_size) # :nodoc:
      tmp = [
        END_OF_CD_SIG,
        0, # @numberOfThisDisk
        0, # @numberOfDiskWithStartOfCDir
        @entry_set ? [@entry_set.size, 0xFFFF].min : 0,
        @entry_set ? [@entry_set.size, 0xFFFF].min : 0,
        [cdir_size, 0xFFFFFFFF].min,
        [offset, 0xFFFFFFFF].min,
        @comment ? @comment.bytesize : 0
      ]
      io << tmp.pack('VvvvvVVv')
      io << @comment
    end

    def write_64_e_o_c_d(io, offset, cdir_size) # :nodoc:
      tmp = [
        ZIP64_END_OF_CD_SIG,
        44, # size of zip64 end of central directory record (excludes signature and field itself)
        VERSION_MADE_BY,
        VERSION_NEEDED_TO_EXTRACT_ZIP64,
        0, # @numberOfThisDisk
        0, # @numberOfDiskWithStartOfCDir
        @entry_set ? @entry_set.size : 0, # number of entries on this disk
        @entry_set ? @entry_set.size : 0, # number of entries total
        cdir_size, # size of central directory
        offset # offset of start of central directory in its disk
      ]
      io << tmp.pack('VQ<vvVVQ<Q<Q<Q<')
    end

    def write_64_eocd_locator(io, zip64_eocd_offset)
      tmp = [
        ZIP64_EOCD_LOCATOR_SIG,
        0, # number of disk containing the start of zip64 eocd record
        zip64_eocd_offset, # offset of the start of zip64 eocd record in its disk
        1 # total number of disks
      ]
      io << tmp.pack('VVQ<V')
    end

    def unpack_64_e_o_c_d(buffer) # :nodoc:
      _, # ZIP64_END_OF_CD_SIG. We know we have this at this point.
      size_of_zip64_e_o_c_d,
      _version_made_by,
      _version_needed_for_extract,
      _number_of_this_disk,
      _number_of_disk_with_start_of_cdir,
      _total_number_of_entries_in_cdir_on_this_disk,
      @size,
      size_in_bytes,
      @cdir_offset = buffer.unpack('VQ<vvVVQ<Q<Q<Q<')

      @eocd_disk = _number_of_this_disk
      @cdir_disk_start = _number_of_disk_with_start_of_cdir
      @total_volumes = 1
      validate_archive!(size_in_bytes)

      zip64_extensible_data_size =
        size_of_zip64_e_o_c_d - ZIP64_STATIC_EOCD_SIZE + 12
      @zip64_extensible_data = if zip64_extensible_data_size.zero?
                                 ''
                               else
                                 buffer.slice(
                                   ZIP64_STATIC_EOCD_SIZE,
                                   zip64_extensible_data_size
                                 )
                               end
    end

    def unpack_64_eocd_locator(buffer) # :nodoc:
      _, # ZIP64_EOCD_LOCATOR_SIG. We know we have this at this point.
      zip64_eocd_disk, zip64_eocd_offset, total_volumes = buffer.unpack('VVQ<V')

      [zip64_eocd_disk, zip64_eocd_offset, total_volumes]
    end

    # Unpack the EOCD and return a boolean indicating whether this header is
    # complete without needing Zip64 extensions.
    def unpack_e_o_c_d(buffer) # :nodoc:
      _, # END_OF_CD_SIG. We know we have this at this point.
      number_of_this_disk,
      number_of_disk_with_start_of_cdir,
      total_number_of_entries_in_cdir_on_this_disk,
      @size,
      size_in_bytes,
      @cdir_offset,
      comment_length = buffer.unpack('VvvvvVVv')

      @eocd_disk = number_of_this_disk
      @cdir_disk_start = number_of_disk_with_start_of_cdir
      @total_volumes = nil

      complete = !([number_of_this_disk, number_of_disk_with_start_of_cdir,
                    total_number_of_entries_in_cdir_on_this_disk, @size].any?(0xFFFF) ||
                    size_in_bytes == 0xFFFFFFFF || @cdir_offset == 0xFFFFFFFF)

      validate_archive!(size_in_bytes) if complete

      @comment = if comment_length.positive?
                   buffer.slice(STATIC_EOCD_SIZE, comment_length)
                 else
                   ''
                 end

      complete
    end

    def read_central_directory_entries(io) # :nodoc:
      # `StringIO` doesn't raise `EINVAL` if you seek beyond the current end,
      # so we need to catch that *and* query `io#eof?` here.
      eof = false
      begin
        seek_to_disk_offset(io, @cdir_disk_start || 0, @cdir_offset)
      rescue Errno::EINVAL
        eof = true
      end
      raise Error, 'Zip consistency problem while reading central directory entry' if eof || io.eof?

      @entry_set = EntrySet.new
      @size.times do
        entry = Entry.read_c_dir_entry(io)
        break unless entry

        offset = if entry.zip64?
                   entry.extra[:zip64].relative_header_offset
                 else
                   entry.local_header_offset
                 end

        unless offset.nil?
          io_save = io.tell
          seek_to_disk_offset(io, entry.disk_start_number, offset)
          entry.read_extra_field(read_local_extra_field(io), local: true)
          io.seek(io_save, IO::SEEK_SET)
        end

        @entry_set << entry
      end
    end

    def read_local_extra_field(io)
      buf = io.read(::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH) || ''
      return '' unless buf.bytesize == ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH

      head, _, _, _, _, _, _, _, _, _, n_len, e_len = buf.unpack('VCCvvvvVVVvv')
      return '' unless head == ::Zip::LOCAL_ENTRY_SIGNATURE

      io.seek(n_len, IO::SEEK_CUR) # Skip over the entry name.
      io.read(e_len)
    end

    def read_eocds(io) # :nodoc:
      data = eocd_data(io).last

      eocd_location = data.rindex([END_OF_CD_SIG].pack('V'))
      raise Error, 'Zip end of central directory signature not found' unless eocd_location

      # Parse the EOCD and return if it is complete without Zip64 extensions.
      return if unpack_e_o_c_d(data.slice(eocd_location..-1))

      # Need to read in the Zip64 EOCD locator and then the Zip64 EOCD.
      zip64_eocd_locator = data.rindex([ZIP64_EOCD_LOCATOR_SIG].pack('V'), eocd_location)
      unless zip64_eocd_locator
        raise Error, 'Zip64 end of central directory locator signature expected but not found'
      end

      zip64_eocd_disk, zip64_eocd_offset, @total_volumes =
        unpack_64_eocd_locator(data.slice(zip64_eocd_locator...eocd_location))
      validate_disk_offset!(io, zip64_eocd_disk, zip64_eocd_offset)

      seek_to_disk_offset(io, zip64_eocd_disk, zip64_eocd_offset)
      zip64_eocd_data = io.read(ZIP64_STATIC_EOCD_SIZE)
      unless zip64_eocd_data&.unpack1('V') == ZIP64_END_OF_CD_SIG
        raise Error, 'Zip64 end of central directory signature not found'
      end

      record_size = zip64_eocd_data.unpack1('x4Q<')
      extensible_data_size = record_size - (ZIP64_STATIC_EOCD_SIZE - 12)
      if extensible_data_size.positive?
        zip64_eocd_data << io.read(extensible_data_size)
      end

      # Finally, unpack the Zip64 EOCD.
      unpack_64_e_o_c_d(zip64_eocd_data)
    end

    def eocd_data(io)
      if io.respond_to?(:multi_volume?) && io.multi_volume?
        last_disk = io.volume_count - 1
        offset = [0, io.volume_size(last_disk) - MAX_END_OF_CD_SIZE].max
        io.seek_to(last_disk, offset)
      else
        begin
          io.seek(-MAX_END_OF_CD_SIZE, IO::SEEK_END)
        rescue Errno::EINVAL
          io.seek(0, IO::SEEK_SET)
        end
      end

      [io.tell, io.read]
    end

    def seek_to_disk_offset(io, disk_number, offset)
      if io.respond_to?(:multi_volume?) && io.multi_volume?
        io.seek_to(disk_number, offset)
      elsif disk_number.to_i.nonzero?
        raise VolumeOffsetError.new(disk_number, offset)
      else
        io.seek(offset, IO::SEEK_SET)
      end
    end

    def validate_archive!(size_in_bytes)
      validate_size!(@size, size_in_bytes)
      return if @total_volumes.nil? || @total_volumes <= 1

      expected_last_disk = @total_volumes - 1
      if @eocd_disk != expected_last_disk
        raise Error,
              "Zip end of central directory is on disk #{@eocd_disk}, " \
              "but the archive has #{@total_volumes} volumes"
      end

      return unless @cdir_disk_start >= @total_volumes

      raise VolumeOffsetError.new(@cdir_disk_start, @cdir_offset)
    end

    def set_volume_count(io)
      return unless io.respond_to?(:multi_volume?) && io.multi_volume?

      @total_volumes = io.volume_count
    end

    def validate_disk_offset!(io, disk_number, offset)
      return unless io.respond_to?(:multi_volume?) && io.multi_volume?

      unless disk_number.is_a?(Integer) && disk_number >= 0 &&
             disk_number < io.volume_count &&
             offset.is_a?(Integer) && offset >= 0 &&
             offset <= io.volume_size(disk_number)
        raise VolumeOffsetError.new(disk_number, offset)
      end
    end

    def validate_size!(size, size_in_bytes)
      return if size * CDIR_ENTRY_STATIC_HEADER_LENGTH <= size_in_bytes

      error = EntryNumberMismatchError.new(size, size_in_bytes)
      raise error if Zip.validate_declared_number_of_entries

      warn error.message
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
