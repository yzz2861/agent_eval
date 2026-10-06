# frozen_string_literal: true

require 'zlib'

module Zip
  # Zip::Recovery is a read-only forensic scanner for zip archives whose
  # central directory is missing or corrupt.
  #
  # Instead of trusting the central directory, it scans the raw file for
  # local file header signatures and then tries to *confirm* each candidate
  # entry using independent evidence:
  #
  # - the local header's own length fields;
  # - the end of the deflate stream (deflate streams are self-terminating);
  # - the CRC32 declared in the header or in a data descriptor;
  # - the data descriptor that follows entries written with general purpose
  #   bit 3 set.
  #
  # A bare +PK+ signature is never treated as proof of an entry boundary:
  # entry payloads can contain the same bytes, so every candidate must be
  # confirmed by the evidence above before it is reported as +verified+.
  #
  # Entries that cannot be confirmed are reported honestly as
  # +indeterminate+ (for example, a stored entry with no reliable length
  # information, where the end of the data cannot be determined) or
  # +unrecoverable+ (for example, corrupt or truncated data). The scanner
  # never guesses a "success".
  #
  # The source archive is only ever opened read-only and is never modified.
  # Zip::Recovery.export writes the confirmed entries to a *new* destination
  # archive, leaving the original untouched.
  #
  # Only stored and deflated entries can be verified; encrypted entries and
  # entries using other compression methods are reported as +unrecoverable+.
  #
  # Example:
  #
  #   report = Zip::Recovery.scan('broken.zip')
  #   puts report
  #   Zip::Recovery.export('broken.zip', 'recovered.zip')
  #
  module Recovery
    # The entry was confirmed by independent evidence (CRC32 and sizes).
    STATUS_VERIFIED = :verified

    # The entry may be intact, but there is not enough evidence to confirm
    # it. Nothing is guessed; the entry is excluded from exports.
    STATUS_INDETERMINATE = :indeterminate

    # The entry is contradicted by the evidence (corrupt, truncated,
    # encrypted, or otherwise not verifiable).
    STATUS_UNRECOVERABLE = :unrecoverable

    # 0x08074b50; shared constant with the (unsupported) split-file marker.
    DATA_DESCRIPTOR_SIGNATURE = ::Zip::SPLIT_FILE_SIGNATURE

    ZIP64_MARKER = 0xFFFFFFFF
    ZIP64_EXTRA_FIELD_ID = 0x0001

    SCAN_CHUNK_SIZE = 1024 * 1024
    IO_CHUNK_SIZE   = 256 * 1024

    LOCAL_HEADER_SIZE = ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH

    class << self
      # Scan +source+ (the path of a zip archive) and return a
      # Zip::Recovery::Report describing every confirmable, indeterminate
      # and unrecoverable entry, along with the evidence for each verdict.
      #
      # The source is only ever opened read-only.
      def scan(source)
        Scanner.new(source).scan
      end

      # Scan +source+ and write every verified entry to a new zip archive at
      # +destination+. The source archive is never modified.
      #
      # Raises Zip::Error if +destination+ already exists, so that a recovery
      # run can never clobber existing data.
      #
      # Returns the Zip::Recovery::Report for the scan.
      def export(source, destination)
        if ::File.exist?(destination)
          raise ::Zip::Error,
                "Destination '#{destination}' already exists; refusing to overwrite it."
        end

        report = scan(source)
        ::File.open(source, 'rb') do |source_io|
          ::Zip::OutputStream.open(destination) do |output_stream|
            report.verified_entries.each do |entry|
              export_entry(entry, source_io, output_stream, destination)
            end
          end
        end
        report
      end

      private

      def export_entry(entry, source_io, output_stream, destination)
        output_stream.put_next_entry(entry.to_zip_entry(destination))
        entry.extract_to(source_io, output_stream)
      rescue ::Zip::EntryExistsError, ::Zip::EntryNameError => e
        entry.evidence << "not exported: #{e.message}"
      end
    end

    # The verdict for a single candidate entry found during a recovery scan.
    class EntryReport
      # +crc+, +compressed_size+ and +size+ are the values declared in the
      # local header, unless the entry was verified by other means (a data
      # descriptor or the deflate stream itself), in which case they are the
      # confirmed values.
      attr_reader :name, :local_header_offset, :compression_method, :gp_flags,
                  :crc, :compressed_size, :size, :time, :status

      # The list of evidence strings backing the verdict. Appended to during
      # scanning (and, occasionally, during export).
      attr_reader :evidence

      attr_writer :crc, :compressed_size, :size # :nodoc:

      def initialize(name:, local_header_offset:, compression_method:, gp_flags:, # :nodoc:
                     crc:, compressed_size:, size:, time:)
        @name = name
        @local_header_offset = local_header_offset
        @compression_method = compression_method
        @gp_flags = gp_flags
        @crc = crc
        @compressed_size = compressed_size
        @size = size
        @time = time
        @evidence = []
        @status = nil
        @extraction = nil
      end

      # Was this entry confirmed by independent evidence?
      def verified?
        @status == STATUS_VERIFIED
      end

      # Could this entry neither be confirmed nor ruled out?
      def indeterminate?
        @status == STATUS_INDETERMINATE
      end

      # Is this entry contradicted by the evidence?
      def unrecoverable?
        @status == STATUS_UNRECOVERABLE
      end

      # The human-readable name of the entry's compression method.
      def compression_method_name
        ::Zip::COMPRESSION_METHODS[@compression_method] || "Unknown (#{@compression_method})"
      end

      def to_h
        {
          name: @name,
          local_header_offset: @local_header_offset,
          compression_method: @compression_method,
          status: @status,
          crc: @crc,
          compressed_size: @compressed_size,
          size: @size,
          evidence: @evidence.dup
        }
      end

      def confirm(status, extraction = nil) # :nodoc:
        @status = status
        @extraction = extraction
        self
      end

      # Stream the verified entry data from +source_io+ (the original
      # archive, opened read-only) to +output_io+, re-checking the CRC32 as
      # the data goes past. Raises Zip::Error if the entry was not verified
      # or the data no longer matches the verified checksum.
      def extract_to(source_io, output_io)
        unless verified?
          raise ::Zip::Error, "Entry '#{name}' was not verified; refusing to extract it."
        end

        crc = 0
        total = 0
        copy_verified_data(source_io, output_io) do |chunk|
          crc = Zlib.crc32(chunk, crc)
          total += chunk.bytesize
        end
        return self if crc == @extraction[:crc] && total == @extraction[:size]

        raise ::Zip::Error,
              "Recovered data for '#{name}' no longer matches the verified CRC32."
      end

      def to_zip_entry(zipfile) # :nodoc:
        ::Zip::Entry.new(
          zipfile, @name,
          compression_method: export_compression_method,
          time: @time || ::Zip::DOSTime.now
        )
      end

      private

      def export_compression_method
        if @compression_method == ::Zip::COMPRESSION_METHOD_STORE
          ::Zip::Entry::STORED
        else
          ::Zip::Entry::DEFLATED
        end
      end

      def copy_verified_data(source_io, output_io)
        if @compression_method == ::Zip::COMPRESSION_METHOD_STORE
          each_compressed_chunk(source_io) do |chunk|
            output_io << chunk
            yield chunk
          end
        else
          inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
          each_compressed_chunk(source_io) do |chunk|
            out = inflate_chunk(inflater, chunk)
            output_io << out
            yield out
          end
        end
      end

      def inflate_chunk(inflater, chunk)
        inflater.inflate(chunk)
      rescue Zlib::Error => e
        raise ::Zip::DecompressionError, e
      end

      def each_compressed_chunk(source_io)
        source_io.seek(@extraction[:data_offset])
        remaining = @extraction[:compressed_size]
        while remaining.positive?
          chunk = source_io.read([remaining, IO_CHUNK_SIZE].min)
          raise ::Zip::Error, "Source archive truncated while extracting '#{name}'." unless chunk

          remaining -= chunk.bytesize
          yield chunk
        end
      end
    end

    # The result of a recovery scan: a manifest of every candidate entry,
    # its verdict, and the evidence behind it.
    class Report
      include Enumerable

      # The path that was scanned, and the number of PK signatures that
      # looked like local headers but were discarded as implausible (these
      # are commonly payload bytes that happen to match the signature).
      attr_reader :source, :rejected_candidates

      # All EntryReport objects, in file order.
      attr_reader :entries

      def initialize(source) # :nodoc:
        @source = source
        @entries = []
        @rejected_candidates = 0
      end

      def each(&block)
        @entries.each(&block)
      end

      # Entries confirmed by independent evidence.
      def verified_entries
        @entries.select(&:verified?)
      end

      # Entries that can neither be confirmed nor ruled out.
      def indeterminate_entries
        @entries.select(&:indeterminate?)
      end

      # Entries contradicted by the evidence.
      def unrecoverable_entries
        @entries.select(&:unrecoverable?)
      end

      def add_entry(entry) # :nodoc:
        @entries << entry
      end

      def reject_candidate # :nodoc:
        @rejected_candidates += 1
      end

      def to_h
        {
          source: @source,
          verified: verified_entries.map(&:name),
          indeterminate: indeterminate_entries.map(&:name),
          unrecoverable: unrecoverable_entries.map(&:name),
          entries: @entries.map(&:to_h)
        }
      end

      # A human-readable recovery manifest: one section per entry, listing
      # the verdict and every piece of evidence behind it.
      def to_s
        lines = ["Recovery scan of '#{@source}': " \
                 "#{verified_entries.size} verified, " \
                 "#{indeterminate_entries.size} indeterminate, " \
                 "#{unrecoverable_entries.size} unrecoverable " \
                 "(#{@rejected_candidates} implausible candidate signatures discarded)."]
        @entries.each do |entry|
          lines << format('[%<status>s] %<name>s @ 0x%<offset>08x, %<method>s',
                          status: entry.status, name: entry.name.inspect,
                          offset: entry.local_header_offset,
                          method: entry.compression_method_name)
          entry.evidence.each { |line| lines << "    - #{line}" }
        end
        lines.join("\n")
      end
    end

    # The raw scanner. Finds local header signature candidates and tries to
    # confirm each one with independent evidence.
    class Scanner # :nodoc:all
      InflateResult = Struct.new(:status, :crc, :size, :consumed, :error, keyword_init: true)

      # Data descriptor layouts tried, in order: with/without the optional
      # signature, and 32-bit/Zip64 sizes. A layout only matches if the
      # values it carries confirm the values measured from the entry data.
      DESCRIPTOR_LAYOUTS = [
        [true, false, 16],
        [true, true, 24],
        [false, false, 12],
        [false, true, 20]
      ].freeze

      def initialize(path)
        @path = path
        @file_size = ::File.size(path)
      end

      def scan
        report = Report.new(@path)
        ::File.open(@path, 'rb') do |io|
          each_signature(io, ::Zip::LOCAL_ENTRY_SIGNATURE) do |offset|
            entry = analyze_candidate(io, offset)
            if entry
              report.add_entry(entry)
            else
              report.reject_candidate
            end
          end
        end
        report
      end

      private

      # Yields the absolute offset of every occurrence of +signature+ in
      # +io+, reading in chunks so large archives do not fill memory. The
      # block may seek +io+ freely; the read position is restored for every
      # chunk.
      def each_signature(io, signature, from: 0)
        magic = [signature].pack('V')
        read_offset = from
        carry = +''.b
        loop do
          io.seek(read_offset)
          chunk = io.read(SCAN_CHUNK_SIZE)
          break unless chunk

          buffer = carry + chunk
          buffer_base = read_offset - carry.bytesize
          pos = 0
          while (index = buffer.index(magic, pos))
            yield buffer_base + index
            pos = index + 1
          end
          carry = buffer.bytesize > 3 ? buffer.byteslice(-3, 3) : buffer
          read_offset += chunk.bytesize
        end
      end

      def read_at(io, offset, length)
        io.seek(offset)
        io.read(length)
      end

      def analyze_candidate(io, offset)
        header = read_at(io, offset, LOCAL_HEADER_SIZE)
        return nil unless header && header.bytesize == LOCAL_HEADER_SIZE

        _sig, _ver, gp_flags, method, mtime, mdate, crc, csize, size, name_len, extra_len =
          header.unpack('VvvvvvVVVvv')
        return nil unless plausible_header?(method, name_len)

        name = read_at(io, offset + LOCAL_HEADER_SIZE, name_len)
        extra = read_at(io, offset + LOCAL_HEADER_SIZE + name_len, extra_len)
        return nil unless name && name.bytesize == name_len && plausible_name?(name)
        return nil unless extra && extra.bytesize == extra_len

        size, csize = zip64_sizes(extra, size, csize)
        entry = build_report(name, offset, gp_flags, method, crc, csize, size, mtime, mdate)
        verify(entry, io, offset + LOCAL_HEADER_SIZE + name_len + extra_len)
        entry
      rescue StandardError
        # A corrupt archive must never crash the scan; an unparseable
        # candidate is simply discarded.
        nil
      end

      def plausible_header?(method, name_len)
        ::Zip::COMPRESSION_METHODS.key?(method) && name_len.positive?
      end

      # Entry names never contain NUL or control characters; anything that
      # does is payload noise, not a header.
      def plausible_name?(name)
        name.bytes.none? { |byte| byte < 0x20 }
      end

      def build_report(name, offset, gp_flags, method, crc, csize, size, mtime, mdate)
        name = name.dup
        name.force_encoding(::Zip.force_entry_names_encoding) if ::Zip.force_entry_names_encoding
        EntryReport.new(
          name: name,
          local_header_offset: offset,
          compression_method: method,
          gp_flags: gp_flags,
          crc: crc,
          compressed_size: csize,
          size: size,
          time: dos_time(mdate, mtime)
        )
      end

      def dos_time(date, time)
        ::Zip::DOSTime.parse_binary_dos_format(date, time)
      rescue ArgumentError
        nil
      end

      # Resolves Zip64 size markers from the Zip64 extra field, if present.
      def zip64_sizes(extra, size, csize)
        return [size, csize] unless size == ZIP64_MARKER || csize == ZIP64_MARKER

        pos = 0
        while pos + 4 <= extra.bytesize
          id, length = extra.byteslice(pos, 4).unpack('vv')
          if id == ZIP64_EXTRA_FIELD_ID
            data = extra.byteslice(pos + 4, length) || +''.b
            cursor = 0
            if size == ZIP64_MARKER && data.bytesize >= cursor + 8
              size = data.byteslice(cursor, 8).unpack1('Q<')
              cursor += 8
            end
            if csize == ZIP64_MARKER && data.bytesize >= cursor + 8
              csize = data.byteslice(cursor, 8).unpack1('Q<')
            end
            break
          end
          pos += 4 + length
        end
        [size, csize]
      end

      def verify(entry, io, data_offset)
        if entry.gp_flags & 1 == 1
          return unverifiable(entry, 'general purpose bit 0 is set: entry is encrypted, ' \
                                     'contents cannot be verified')
        end
        if entry.size == ZIP64_MARKER || entry.compressed_size == ZIP64_MARKER
          return unverifiable(entry, 'Zip64 size markers present but no Zip64 extra field ' \
                                     'found in the local header')
        end

        case entry.compression_method
        when ::Zip::COMPRESSION_METHOD_STORE
          verify_stored(entry, io, data_offset)
        when ::Zip::COMPRESSION_METHOD_DEFLATE
          verify_deflated(entry, io, data_offset)
        else
          unverifiable(entry, "compression method '#{entry.compression_method_name}' is not " \
                              'supported by the recovery scanner; contents cannot be verified')
        end
      end

      def unverifiable(entry, reason)
        entry.evidence << reason
        entry.confirm(STATUS_UNRECOVERABLE)
      end

      def uses_descriptor?(entry)
        entry.gp_flags & 8 == 8
      end

      def extraction(entry, data_offset, compressed_size)
        {
          data_offset: data_offset,
          compressed_size: compressed_size,
          crc: entry.crc,
          size: entry.size
        }
      end

      def crc32_of_range(io, offset, length)
        io.seek(offset)
        crc = 0
        remaining = length
        while remaining.positive?
          chunk = io.read([remaining, IO_CHUNK_SIZE].min)
          return nil unless chunk

          remaining -= chunk.bytesize
          crc = Zlib.crc32(chunk, crc)
        end
        crc
      end

      # Inflates from +offset+. When +limit+ is given, exactly that many
      # compressed bytes are fed to the inflater; otherwise the inflate runs
      # until the deflate stream terminates itself.
      def inflate(io, offset, limit)
        inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        io.seek(offset)
        crc = 0
        size = 0
        chunk = nil
        until inflater.finished? || limit&.zero?
          chunk = io.read(limit ? [limit, IO_CHUNK_SIZE].min : IO_CHUNK_SIZE)
          break unless chunk

          limit -= chunk.bytesize if limit
          begin
            out = inflater.inflate(chunk)
          rescue Zlib::Error => e
            return InflateResult.new(status: :corrupt, error: e.message, crc: crc,
                                     size: size, consumed: inflater.total_in)
          end
          crc = Zlib.crc32(out, crc)
          size += out.bytesize
        end
        InflateResult.new(status: inflate_status(inflater, chunk), crc: crc, size: size,
                          consumed: inflater.total_in)
      end

      def inflate_status(inflater, chunk)
        return :finished if inflater.finished?

        chunk.nil? ? :truncated : :short
      end

      # Matches a data descriptor at +offset+ against values measured from
      # the entry data. Only a descriptor whose CRC32 and sizes confirm the
      # measured values counts as evidence.
      def match_descriptor(io, offset, result)
        DESCRIPTOR_LAYOUTS.any? do |signed, zip64, length|
          descriptor_matches?(io, offset, signed, zip64, length, result)
        end
      end

      def descriptor_matches?(io, offset, signed, zip64, length, result)
        head = read_at(io, offset, length)
        return false unless head && head.bytesize == length

        pos = 0
        if signed
          return false unless head.byteslice(0, 4).unpack1('V') == DATA_DESCRIPTOR_SIGNATURE

          pos = 4
        end
        crc = head.byteslice(pos, 4).unpack1('V')
        csize, size = descriptor_sizes(head, pos, zip64)
        crc == result.crc && csize == result.consumed && size == result.size
      end

      def descriptor_sizes(head, pos, zip64)
        if zip64
          head.byteslice(pos + 4, 16).unpack('Q<Q<')
        else
          head.byteslice(pos + 4, 8).unpack('VV')
        end
      end

      # --- Stored entries -------------------------------------------------

      def verify_stored(entry, io, data_offset)
        if entry.compressed_size.positive?
          entry.evidence << 'compressed size taken from the local header'
          verify_stored_known_length(entry, io, data_offset)
        elsif uses_descriptor?(entry)
          entry.evidence << 'general purpose bit 3 set: sizes are in a data descriptor ' \
                            'following the entry data'
          verify_stored_via_descriptor(entry, io, data_offset)
        elsif entry.size.zero? && entry.crc.zero?
          entry.evidence << 'local header declares an empty entry (sizes and CRC32 are all zero)'
          entry.confirm(STATUS_VERIFIED, extraction(entry, data_offset, 0))
        else
          unverifiable(entry, 'stored entry declares zero compressed size but a non-zero ' \
                              'size/CRC32; local header is inconsistent')
        end
      end

      def verify_stored_known_length(entry, io, data_offset)
        if entry.size != entry.compressed_size
          return unverifiable(entry, "stored entry declares compressed size " \
                                     "#{entry.compressed_size} but uncompressed size " \
                                     "#{entry.size}; local header is inconsistent")
        end
        if data_offset + entry.compressed_size > @file_size
          return unverifiable(entry, 'declared entry data extends beyond the end of the ' \
                                     'file; archive is truncated')
        end

        actual = crc32_of_range(io, data_offset, entry.compressed_size)
        if actual == entry.crc
          entry.evidence << format('CRC32 match (0x%08x) over %d stored bytes',
                                   entry.crc, entry.compressed_size)
          entry.confirm(STATUS_VERIFIED, extraction(entry, data_offset, entry.compressed_size))
        else
          unverifiable(entry, format('CRC32 mismatch: header declares 0x%08x but the data ' \
                                     'hashes to 0x%08x', entry.crc, actual))
        end
      end

      # A stored entry whose length is only recorded in a trailing data
      # descriptor has no self-terminating stream, so the descriptor must be
      # located by scanning forward. A candidate descriptor only counts as
      # evidence when its signature, its sizes (which must equal each other
      # and the exact distance from the data start) and its CRC32 all agree.
      def verify_stored_via_descriptor(entry, io, data_offset)
        found = find_stored_descriptor(io, data_offset)
        unless found
          entry.evidence << 'no data descriptor could be confirmed; a stored entry without ' \
                            'a reliable length has no determinable end, so this entry ' \
                            'cannot be recovered safely'
          return entry.confirm(STATUS_INDETERMINATE)
        end

        entry.evidence << format('data descriptor confirmed at 0x%08x: signature, sizes ' \
                                 'and CRC32 all consistent', found[:offset])
        entry.evidence << format('CRC32 match (0x%08x)', found[:crc])
        entry.crc = found[:crc]
        entry.compressed_size = found[:csize]
        entry.size = found[:size]
        entry.confirm(STATUS_VERIFIED, extraction(entry, data_offset, found[:csize]))
      end

      def find_stored_descriptor(io, data_offset)
        each_signature(io, DATA_DESCRIPTOR_SIGNATURE, from: data_offset) do |offset|
          match = check_stored_descriptor(io, data_offset, offset)
          return match if match
        end
        nil
      end

      def check_stored_descriptor(io, data_offset, offset)
        head = read_at(io, offset, 24)
        return nil unless head && head.bytesize >= 16

        crc = head.byteslice(4, 4).unpack1('V')
        csize, size = stored_descriptor_sizes(head, offset - data_offset)
        return nil unless csize
        return nil unless crc32_of_range(io, data_offset, csize) == crc

        { offset: offset, crc: crc, csize: csize, size: size }
      end

      # For a stored entry the descriptor's two sizes must equal each other
      # and the exact distance from the start of the entry data.
      def stored_descriptor_sizes(head, distance)
        csize32, size32 = head.byteslice(8, 8).unpack('VV')
        return [csize32, size32] if csize32 == size32 && csize32 == distance

        if head.bytesize >= 24
          csize64, size64 = head.byteslice(8, 16).unpack('Q<Q<')
          return [csize64, size64] if csize64 == size64 && csize64 == distance
        end

        [nil, nil]
      end

      # --- Deflated entries -----------------------------------------------

      def verify_deflated(entry, io, data_offset)
        if uses_descriptor?(entry)
          entry.evidence << 'general purpose bit 3 set: sizes are in a data descriptor ' \
                            'following the entry data'
          verify_deflated_streamed(entry, io, data_offset)
        elsif entry.compressed_size.positive?
          entry.evidence << 'compressed size taken from the local header'
          verify_deflated_known_length(entry, io, data_offset)
        elsif entry.size.zero? && entry.crc.zero?
          entry.evidence << 'local header declares an empty entry (sizes and CRC32 are all zero)'
          entry.confirm(STATUS_VERIFIED, extraction(entry, data_offset, 0))
        else
          unverifiable(entry, 'deflated entry declares zero compressed size but a non-zero ' \
                              'size/CRC32 and carries no data descriptor; local header is ' \
                              'inconsistent')
        end
      end

      def verify_deflated_known_length(entry, io, data_offset)
        if data_offset + entry.compressed_size > @file_size
          return unverifiable(entry, 'declared entry data extends beyond the end of the ' \
                                     'file; archive is truncated')
        end

        result = inflate(io, data_offset, entry.compressed_size)
        return entry.confirm(STATUS_UNRECOVERABLE) unless inflate_usable?(entry, result)

        confirm_deflated_known_length(entry, result, data_offset)
      end

      def confirm_deflated_known_length(entry, result, data_offset)
        if result.consumed != entry.compressed_size
          return unverifiable(entry, "deflate stream ended after #{result.consumed} bytes " \
                                     "but the declared compressed size is " \
                                     "#{entry.compressed_size}; declared length is inconsistent")
        end
        if result.size != entry.size
          return unverifiable(entry, "inflated size #{result.size} does not match the " \
                                     "declared size #{entry.size}")
        end
        if result.crc != entry.crc
          return unverifiable(entry, format('CRC32 mismatch: header declares 0x%08x but ' \
                                            'the inflated data hashes to 0x%08x',
                                            entry.crc, result.crc))
        end

        entry.evidence << 'deflate stream finished exactly at the declared compressed size'
        entry.evidence << format('CRC32 match (0x%08x)', entry.crc)
        entry.confirm(STATUS_VERIFIED, extraction(entry, data_offset, entry.compressed_size))
      end

      # Bit 3 entries carry no sizes in the local header, but a deflate
      # stream terminates itself, so the compressed length can be measured
      # from the stream. The measured CRC32/sizes still need confirmation
      # from a data descriptor (or, failing that, matching header values).
      def verify_deflated_streamed(entry, io, data_offset)
        result = inflate(io, data_offset, nil)
        return entry.confirm(STATUS_UNRECOVERABLE) unless inflate_usable?(entry, result)

        entry.evidence << "deflate stream ended cleanly after #{result.consumed} compressed bytes"
        confirm_deflated_streamed(entry, io, data_offset, result)
      end

      def confirm_deflated_streamed(entry, io, data_offset, result)
        descriptor_offset = data_offset + result.consumed
        if match_descriptor(io, descriptor_offset, result)
          entry.evidence << format('data descriptor at 0x%08x confirms CRC32 and sizes',
                                   descriptor_offset)
        elsif header_confirms_stream?(entry, result)
          entry.evidence << 'no data descriptor found, but the local header CRC32/sizes ' \
                            'match the measured stream'
        else
          entry.evidence << 'no data descriptor and no matching header values; the stream ' \
                            'ended cleanly but its integrity cannot be confirmed'
          return entry.confirm(STATUS_INDETERMINATE)
        end

        entry.evidence << format('CRC32 match (0x%08x)', result.crc)
        entry.crc = result.crc
        entry.compressed_size = result.consumed
        entry.size = result.size
        entry.confirm(STATUS_VERIFIED, extraction(entry, data_offset, result.consumed))
      end

      def header_confirms_stream?(entry, result)
        entry.crc.positive? && entry.compressed_size.positive? &&
          entry.crc == result.crc && entry.compressed_size == result.consumed &&
          entry.size == result.size
      end

      # Records the evidence for a failed inflate and reports whether the
      # stream finished cleanly.
      def inflate_usable?(entry, result)
        case result.status
        when :finished
          true
        when :truncated
          entry.evidence << 'entry data ended before the deflate stream terminated; ' \
                            'archive is truncated'
          false
        when :corrupt
          entry.evidence << "deflate stream is corrupt (#{result.error})"
          false
        else
          entry.evidence << 'deflate stream did not complete within the declared ' \
                            'compressed size'
          false
        end
      end
    end
  end
end
