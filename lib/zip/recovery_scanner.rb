# frozen_string_literal: true

require 'pathname'

module Zip
  # Zip::RecoveryScanner rescues entries from a zip archive whose central
  # directory is missing, truncated or corrupt, and which therefore cannot
  # be opened by Zip::File at all.
  #
  # The scanner walks the local file headers directly and confirms each
  # entry through a chain of evidence rather than trusting structure
  # signatures alone:
  #
  # 1. A candidate local header must parse and pass plausibility checks.
  #    The bytes "PK\x03\x04" can legitimately appear inside entry
  #    payloads, so a signature on its own is never treated as proof.
  # 2. The entry's data boundaries are taken from the declared compressed
  #    size or - for streamed (bit 3) deflated entries - from the end of
  #    the deflate stream itself, which is self-terminating.
  # 3. The CRC32 of the recovered data must match the local header, or a
  #    following data descriptor whose values are fully consistent with
  #    the recovered data.
  #
  # Stored entries written for streaming (bit 3 set, zero sizes in the
  # local header) carry no reliable length and their data is not
  # self-terminating. These are reported as +:undetermined+ - the scanner
  # refuses to guess a payload end by hunting for signatures, because the
  # same bytes may occur inside the payload.
  #
  # The scanner is strictly read-only: the source archive is never
  # modified. Recovered entries are exported to a separate destination
  # directory together with a manifest listing the evidence for every
  # entry:
  #
  #   scanner = Zip::RecoveryScanner.new('broken.zip')
  #   report = scanner.scan
  #   puts report
  #   scanner.recover('rescued/')
  #
  # Note that recovery from a corrupt archive can never be perfect: if a
  # candidate header and a matching CRC happen to occur inside unknown
  # bytes, the result is indistinguishable from a real entry. Always
  # review the evidence in the manifest.
  class RecoveryScanner
    # The name of the manifest file written to the recovery destination.
    MANIFEST_FILENAME = 'recovery_manifest.txt'

    LOCAL_SIGNATURE           = "PK\x03\x04".b.freeze
    DATA_DESCRIPTOR_SIGNATURE = "PK\x07\x08".b.freeze
    CENTRAL_SIGNATURES        = ["PK\x01\x02".b, "PK\x05\x06".b, "PK\x06\x06".b].freeze

    ENCRYPTED_FLAG       = 0x01
    DATA_DESCRIPTOR_FLAG = 0x08

    MAX_PLAUSIBLE_VERSION = 63
    ZIP64_EXTRA_ID        = 0x0001
    ZIP64_PLACEHOLDER     = 0xFFFFFFFF

    TRUNCATED_MESSAGE = 'entry data is truncated: declared size runs past end of file'

    # A single entry found by the scan, with the evidence gathered for it.
    class RecoveredEntry
      attr_reader :name, :offset, :compression_method, :gp_flags, :evidence
      attr_accessor :compressed_size, :size, :crc, :status, :data, :exported_to

      def initialize(name:, offset:, compression_method:, gp_flags:)
        @name               = name
        @offset             = offset
        @compression_method = compression_method
        @gp_flags           = gp_flags
        @compressed_size    = nil
        @size               = nil
        @crc                = nil
        @status             = :undetermined
        @evidence           = []
        @data               = nil
        @exported_to        = nil
      end

      # The entry was confirmed and its data recovered.
      def recovered?
        @status == :recovered
      end

      # The entry's data boundaries cannot be determined reliably.
      def undetermined?
        @status == :undetermined
      end

      # The entry is known but its data cannot be recovered.
      def unrecoverable?
        @status == :unrecoverable
      end

      def directory?
        @name.end_with?('/')
      end
    end

    # The result of a scan: every candidate entry plus its evidence.
    class Report
      include Enumerable

      attr_reader :source, :entries

      def initialize(source, source_bytesize, entries)
        @source          = source
        @source_bytesize = source_bytesize
        @entries         = entries
      end

      def each(&block)
        entries.each(&block)
      end

      def recovered
        entries.select(&:recovered?)
      end

      def undetermined
        entries.select(&:undetermined?)
      end

      def unrecoverable
        entries.select(&:unrecoverable?)
      end

      # A human-readable manifest of the scan, including the evidence
      # gathered for each entry.
      def to_s
        lines = [
          'Zip recovery manifest',
          '=====================',
          "Source: #{@source} (#{@source_bytesize} bytes, left unmodified)",
          "Recovered: #{recovered.size}, undetermined: #{undetermined.size}, " \
            "unrecoverable: #{unrecoverable.size}",
          ''
        ]
        entries.each_with_index { |entry, index| lines.concat(entry_lines(entry, index)) }
        lines.join("\n")
      end

      private

      def entry_lines(entry, index)
        lines = ["[#{index + 1}] #{entry.status.to_s.upcase} #{display_name(entry.name)}"]
        lines << "    offset: #{entry.offset}, " \
                 "method: #{method_name(entry.compression_method)}, " \
                 "size: #{entry.size || 'unknown'}, " \
                 "compressed: #{entry.compressed_size || 'unknown'}, " \
                 "crc: #{entry.crc ? format('0x%08x', entry.crc) : 'unknown'}"
        entry.evidence.each { |item| lines << "    - #{item}" }
        lines << "    exported to: #{entry.exported_to}" if entry.exported_to
        lines
      end

      def display_name(name)
        name.dup.force_encoding(Encoding::UTF_8).scrub.inspect
      end

      def method_name(method)
        ::Zip::COMPRESSION_METHODS[method] || "unknown (#{method})"
      end
    end

    # +source+ may be a path to a zip file, or a readable IO. The source
    # is only ever read, never written.
    def initialize(source)
      @source = source
      @report = nil
    end

    # Scan the source and return a Report. The source is not modified.
    def scan
      @report ||= build_report(read_source)
    end

    # Scan (unless already scanned) and export every recovered entry into
    # +dest_dir+, writing a manifest there as well. Returns the Report.
    # The source archive is not modified.
    def recover(dest_dir)
      report = scan
      FileUtils.mkdir_p(dest_dir)
      report.recovered.each { |entry| export_entry(entry, dest_dir) }
      ::File.binwrite(::File.join(dest_dir, MANIFEST_FILENAME), report.to_s)
      report
    end

    private

    def read_source
      data =
        if @source.respond_to?(:read)
          @source.rewind if @source.respond_to?(:rewind)
          @source.read
        else
          ::File.binread(@source.to_s)
        end
      data.dup.force_encoding(Encoding::BINARY)
    end

    def source_description
      @source.respond_to?(:read) ? @source.inspect : @source.to_s
    end

    def build_report(data)
      entries = []
      offset = 0
      while offset <= data.bytesize - ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH
        index = data.index(LOCAL_SIGNATURE, offset)
        break unless index

        next_offset = nil
        if (header = parse_local_header(data, index))
          entry, next_offset = examine_entry(data, index, header)
          entries << entry
        end
        offset = next_offset || index + 1
        break if next_offset && central_directory_start?(data, next_offset)
      end
      Report.new(source_description, data.bytesize, entries)
    end

    def central_directory_start?(data, offset)
      CENTRAL_SIGNATURES.include?(data[offset, 4])
    end

    # Parse and sanity-check a candidate local header. Returns nil if the
    # candidate is not plausible.
    def parse_local_header(data, pos)
      static = data[pos, ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH]
      return nil unless static && static.bytesize == ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH

      _sig, version, gp_flags, method, _mtime, _mdate, crc, csize, usize,
        name_len, extra_len = static.unpack('VvvvvvVVVvv')
      return nil if version > MAX_PLAUSIBLE_VERSION
      return nil unless ::Zip::COMPRESSION_METHODS.key?(method)
      return nil if name_len.zero?

      data_offset = pos + ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH + name_len + extra_len
      return nil if data_offset > data.bytesize

      name = data[pos + ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH, name_len]
      return nil if name.match?(/[\x00-\x1f]/)

      { version: version, gp_flags: gp_flags, method: method, crc: crc,
        compressed_size: csize, size: usize, name: name,
        extra: data[pos + ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH + name_len, extra_len],
        data_offset: data_offset }
    end

    def examine_entry(data, pos, header)
      entry = RecoveredEntry.new(name: header[:name], offset: pos,
                                 compression_method: header[:method],
                                 gp_flags: header[:gp_flags])
      entry.evidence << format('local header parsed (version %<version>d, ' \
                               'gp_flags 0x%<flags>04x)',
                               version: header[:version], flags: header[:gp_flags])
      resolve_zip64(header)
      [entry, examine_data(data, entry, header)]
    end

    def examine_data(data, entry, header)
      if header[:gp_flags] & ENCRYPTED_FLAG != 0
        fail_entry(entry, 'entry is encrypted; contents cannot be verified or recovered')
      elsif zip64_unresolved?(header)
        fail_entry(entry, 'zip64 sizes indicated but the zip64 extra field is missing ' \
                          'or incomplete')
      elsif header[:method] == ::Zip::COMPRESSION_METHOD_STORE
        examine_stored(data, entry, header)
      elsif header[:method] == ::Zip::COMPRESSION_METHOD_DEFLATE
        examine_deflated(data, entry, header)
      else
        fail_entry(entry, "compression method #{header[:method]} " \
                          "(#{::Zip::COMPRESSION_METHODS[header[:method]]}) cannot be verified")
      end
    end

    def zip64_unresolved?(header)
      header[:compressed_size] == ZIP64_PLACEHOLDER || header[:size] == ZIP64_PLACEHOLDER
    end

    def fail_entry(entry, reason)
      entry.status = :unrecoverable
      entry.evidence << reason
      nil
    end

    # A streamed entry has bit 3 set and carries no metadata in its local
    # header; the values follow the data in a data descriptor instead.
    def streamed?(header)
      header[:gp_flags] & DATA_DESCRIPTOR_FLAG != 0 &&
        header[:crc].zero? && header[:compressed_size].zero? && header[:size].zero?
    end

    def examine_stored(data, entry, header)
      return mark_undetermined(entry) if streamed?(header)

      csize = header[:compressed_size]
      entry.evidence << "data length #{csize} taken from the local header"
      return fail_entry(entry, TRUNCATED_MESSAGE) if header[:data_offset] + csize > data.bytesize
      if csize != header[:size]
        return fail_entry(entry, 'stored entry has mismatched sizes: ' \
                                 "compressed #{csize} != uncompressed #{header[:size]}")
      end

      verify_against_header(entry, header, data, data[header[:data_offset], csize])
    end

    # Stored data is not self-terminating, so without a reliable length
    # there is no honest way to find the end of the payload.
    def mark_undetermined(entry)
      entry.evidence << 'stored entry with bit 3 set and zero sizes in the local header: ' \
                        'the data length cannot be determined reliably'
      entry.evidence << 'refusing to guess the payload end by scanning for signatures, ' \
                        'as the payload itself may contain the same bytes'
      nil
    end

    def examine_deflated(data, entry, header)
      return examine_streamed_deflated(data, entry, header) if streamed?(header)

      csize = header[:compressed_size]
      entry.evidence << "data length #{csize} taken from the local header"
      return fail_entry(entry, TRUNCATED_MESSAGE) if header[:data_offset] + csize > data.bytesize

      inflated = inflate_exact(data[header[:data_offset], csize])
      unless inflated
        return fail_entry(entry, 'deflate stream is corrupt or does not fill the ' \
                                 'declared compressed size')
      end

      verify_against_header(entry, header, data, inflated)
    end

    # A deflate stream terminates itself, so the compressed size of a
    # streamed entry can be found by inflating until the stream ends,
    # without relying on any signatures in the payload.
    def examine_streamed_deflated(data, entry, header)
      result = inflate_until_end(data, header[:data_offset])
      unless result
        return fail_entry(entry, 'deflate stream does not terminate within the file ' \
                                 '(truncated or corrupt)')
      end

      inflated, csize = result
      data_end = header[:data_offset] + csize
      entry.evidence << "deflate stream ended cleanly at offset #{data_end}"
      crc = ::Zlib.crc32(inflated)
      descriptor = match_descriptor(data, data_end, crc, csize, inflated.bytesize)
      entry.evidence << descriptor_evidence(descriptor, data_end, crc)
      recover_entry(entry, inflated, crc, csize, data_end + (descriptor || 0))
    end

    def descriptor_evidence(descriptor, data_end, crc)
      if descriptor
        "data descriptor at offset #{data_end} confirms CRC32 and sizes"
      else
        format('no data descriptor follows; CRC32 0x%08x computed from recovered ' \
               'data, with nothing to cross-check against', crc)
      end
    end

    def verify_against_header(entry, header, data, payload)
      crc = ::Zlib.crc32(payload)
      if crc != header[:crc]
        message = format('CRC32 mismatch: header declares 0x%08x, recovered data has 0x%08x',
                         header[:crc], crc)
        return fail_entry(entry, message)
      end
      if payload.bytesize != header[:size]
        message = "size mismatch: header declares #{header[:size]} bytes, " \
                  "recovered data has #{payload.bytesize}"
        return fail_entry(entry, message)
      end

      entry.evidence << format('CRC32 verified against local header (0x%08x)', crc)
      confirm_entry(entry, header, data, payload, crc)
    end

    def confirm_entry(entry, header, data, payload, crc)
      csize = header[:compressed_size]
      next_offset = header[:data_offset] + csize
      descriptor = nil
      if header[:gp_flags] & DATA_DESCRIPTOR_FLAG != 0
        descriptor = match_descriptor(data, next_offset, crc, csize, payload.bytesize)
      end
      if descriptor
        entry.evidence << "data descriptor at offset #{next_offset} confirms CRC32 and sizes"
        next_offset += descriptor
      end
      recover_entry(entry, payload, crc, csize, next_offset)
    end

    def recover_entry(entry, payload, crc, csize, next_offset)
      entry.status = :recovered
      entry.data = payload
      entry.crc = crc
      entry.size = payload.bytesize
      entry.compressed_size = csize
      entry.evidence << 'entry confirmed'
      next_offset
    end

    # Inflate exactly the given bytes; the deflate stream must end
    # precisely at the end of the slice. Returns nil on any problem.
    def inflate_exact(compressed)
      inflater = ::Zlib::Inflate.new(-::Zlib::MAX_WBITS)
      output = inflater.inflate(compressed)
      inflater.finished? && inflater.total_in == compressed.bytesize ? output : nil
    rescue ::Zlib::Error
      nil
    ensure
      inflater&.close
    end

    # Inflate starting at +offset+, letting the deflate stream terminate
    # itself. Returns [inflated_data, compressed_size] or nil.
    def inflate_until_end(data, offset)
      inflater = ::Zlib::Inflate.new(-::Zlib::MAX_WBITS)
      output = inflater.inflate(data[offset..] || ''.b)
      inflater.finished? ? [output, inflater.total_in] : nil
    rescue ::Zlib::Error
      nil
    ensure
      inflater&.close
    end

    # Match a data descriptor immediately after a streamed entry's data.
    # Only a descriptor whose CRC and sizes exactly equal the recovered
    # values is accepted, so payload bytes can never fake one. Returns
    # the descriptor length in bytes, or nil.
    def match_descriptor(data, pos, crc, csize, usize)
      return nil if pos >= data.bytesize

      has_signature = data[pos, 4] == DATA_DESCRIPTOR_SIGNATURE
      base = has_signature ? pos + 4 : pos
      if descriptor_values(data, base, 12, 'VVV') == [crc, csize, usize]
        return has_signature ? 16 : 12
      end
      if descriptor_values(data, base, 20, 'VQQ') == [crc, csize, usize]
        return has_signature ? 24 : 20
      end
      nil
    end

    def descriptor_values(data, base, length, format)
      raw = data[base, length]
      raw && raw.bytesize == length ? raw.unpack(format) : nil
    end

    # Replace 0xFFFFFFFF placeholder sizes with the values from the
    # entry's zip64 extra field, if present.
    def resolve_zip64(header)
      return unless zip64_unresolved?(header)

      extra = header[:extra] || ''.b
      pos = 0
      while pos + 4 <= extra.bytesize
        id, length = extra[pos, 4].unpack('vv')
        apply_zip64_extra(header, extra[pos + 4, length] || ''.b) if id == ZIP64_EXTRA_ID
        pos += 4 + length
      end
    end

    def apply_zip64_extra(header, body)
      offset = 0
      [:size, :compressed_size].each do |key|
        next unless header[key] == ZIP64_PLACEHOLDER
        break if offset + 8 > body.bytesize

        header[key] = body[offset, 8].unpack1('Q')
        offset += 8
      end
    end

    def export_entry(entry, dest_dir)
      dest = safe_destination(dest_dir, entry.name)
      unless dest
        entry.evidence << 'entry name is not a safe relative path; not exported'
        return
      end

      if entry.directory?
        FileUtils.mkdir_p(dest)
      else
        FileUtils.mkdir_p(::File.dirname(dest))
        ::File.binwrite(dest, entry.data)
      end
      entry.exported_to = dest
    end

    # Entries in a corrupt archive cannot be trusted: refuse names that
    # would escape the destination directory.
    def safe_destination(dest_dir, name)
      return nil if name.empty? || name.include?("\x00")

      clean = Pathname.new(name).cleanpath.to_s
      return nil if clean == '..' || clean.start_with?('../', '/')
      return nil if clean.match?(/\A[A-Za-z]:/) # Windows drive letter

      ::File.join(dest_dir, clean)
    end
  end
end
