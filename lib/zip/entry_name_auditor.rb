# frozen_string_literal: true

# String#unicode_normalize is preloaded on Ruby >= 3.4, but needs an
# explicit require on earlier versions.
require 'unicode_normalize' unless String.method_defined?(:unicode_normalize)
require 'zlib'

module Zip
  # Audits the names of the entries in a zip archive.
  #
  # A single entry can carry its name in up to three places, which do not
  # have to agree: the local file header, the central directory entry, and
  # the Info-ZIP Unicode Path extra field (0x7075). Rubyzip (like most
  # readers) silently uses the central directory name. This auditor reads
  # every location independently and reports, for each entry, the raw name
  # bytes, the declared encoding and the decoded result for each location,
  # along with any inconsistencies found:
  #
  # * local header and central directory names that differ;
  # * names that are not valid UTF-8 where UTF-8 is declared;
  # * Unicode Path extra fields whose CRC32 does not match the header name;
  # * entries whose names collide after Unicode (NFC) normalization.
  #
  # Use it directly via ::Zip::EntryNameAuditor.audit(io), or implicitly
  # through the +name_audit:+ option of Zip::File.new/open.
  class EntryNameAuditor
    # Valid values for the +name_audit:+ option of Zip::File.new/open.
    MODES = %i[off lenient strict].freeze

    EFS_FLAG = 0b1000_0000_0000 # Language encoding flag (EFS), gp flag bit 11.
    UNICODE_PATH_ID = [0x7075].pack('v')
    ZIP64_ID = [0x0001].pack('v')

    # A single observation of an entry name: the raw bytes found at one
    # location in the archive, the encoding declared for them, and the
    # result of decoding them with that encoding.
    class NameObservation
      attr_reader :source, :raw, :declared_encoding, :encoding_source, :decoded

      def initialize(source:, raw:, declared_encoding:, encoding_source:)
        @source            = source
        @raw               = raw
        @declared_encoding = declared_encoding
        @encoding_source   = encoding_source
        @decoded           = raw.dup.force_encoding(declared_encoding)
      end

      def valid_encoding?
        @decoded.valid_encoding?
      end

      # The decoded name as NFC-normalized UTF-8, with any trailing path
      # separator removed. Invalid bytes are replaced, so this is always
      # safe to display or compare.
      def normalized
        decoded_utf8.unicode_normalize(:nfc).chomp('/')
      end

      def decoded_utf8
        @decoded.encode(Encoding::UTF_8, invalid: :replace, undef: :replace,
                        replace: "�")
      end

      def to_h
        {
          source:            @source,
          raw_hex:           @raw.unpack1('H*'),
          declared_encoding: @declared_encoding.name,
          encoding_source:   @encoding_source,
          decoded:           @decoded,
          valid_encoding:    valid_encoding?
        }
      end
    end

    # The result of checking one Unicode Path extra field against the name
    # stored in the header that carries it.
    UnicodePathCheck = Struct.new(
      :source, :version, :name_crc32, :computed_crc32, :unicode_name, :valid_utf8
    ) do
      def crc_ok?
        !name_crc32.nil? && name_crc32 == computed_crc32
      end
    end

    # A single problem found while auditing. +code+ is a machine-readable
    # symbol, +message+ a human-readable description.
    Issue = Struct.new(:code, :message)

    # The audit results for a single archive entry.
    class EntryAudit
      attr_reader :observations, :unicode_path_checks, :issues

      def initialize(observations:, unicode_path_checks:, issues:)
        @observations        = observations
        @unicode_path_checks = unicode_path_checks
        @issues              = issues
      end

      def ok?
        @issues.empty?
      end

      def central_observation
        @observations.find { |obs| obs.source == :central_directory }
      end

      def local_observation
        @observations.find { |obs| obs.source == :local_header }
      end

      # The decoded central directory name (the name Rubyzip would use).
      def name
        central_observation&.decoded
      end

      def to_h
        {
          observations:        @observations.map(&:to_h),
          unicode_path_checks: @unicode_path_checks.map(&:to_h),
          issues:              @issues.map(&:to_h)
        }
      end
    end

    # The full audit report for an archive.
    class Report
      attr_reader :entries, :issues

      def initialize(entries)
        @entries = entries
        @issues  = entries.flat_map(&:issues) + collision_issues
      end

      def ok?
        @issues.empty?
      end

      # Raise ::Zip::NameAmbiguityError unless the report is clean.
      # Returns self otherwise.
      def strict!
        return self if ok?

        raise ::Zip::NameAmbiguityError, @issues.map(&:message)
      end

      def to_h
        {
          entries: @entries.map(&:to_h),
          issues:  @issues.map(&:to_h)
        }
      end

      private

      def collision_issues
        groups = Hash.new { |hash, key| hash[key] = [] }
        @entries.each do |entry|
          obs = entry.central_observation
          next unless obs&.valid_encoding?

          groups[obs.normalized] << obs
        end
        groups.filter_map do |normalized, observations|
          next unless observations.size > 1

          names = observations.map { |obs| "0x#{obs.raw.unpack1('H*')}" }.join(', ')
          Issue.new(:normalized_name_collision,
                    "#{observations.size} entries normalize to '#{normalized}': #{names}")
        end
      end
    end

    class << self
      # Audit the zip archive readable from +io+ (any seekable IO, e.g. a
      # File or StringIO) and return a Report. The stream position is
      # restored before returning.
      def audit(io)
        pos = io.pos if io.respond_to?(:pos)
        new(io).audit
      ensure
        io.pos = pos if pos
      end
    end

    def initialize(io)
      @io = io
    end

    def audit
      cdir_offset, _cdir_size, count = read_eocd
      entries = read_central_entries(cdir_offset, count).map { |central| audit_entry(central) }
      Report.new(entries)
    end

    private

    def read_exactly(length)
      return +'' if length.zero?

      buf = @io.read(length)
      if buf.nil? || buf.bytesize < length
        raise ::Zip::Error, 'Unexpected end of file while auditing entry names'
      end

      buf
    end

    def read_eocd
      @io.seek(0, IO::SEEK_END)
      file_size = @io.tell
      raise ::Zip::Error, 'Not a zip archive: file is empty' if file_size.zero?

      tail_size = [file_size, ::Zip::CentralDirectory::MAX_END_OF_CD_SIZE].min
      @io.seek(file_size - tail_size, IO::SEEK_SET)
      data = @io.read(tail_size)
      eocd_at = data.rindex([::Zip::CentralDirectory::END_OF_CD_SIG].pack('V'))
      raise ::Zip::Error, 'Zip end of central directory signature not found' unless eocd_at

      _sig, _disk, _cd_disk, _disk_count, count, cdir_size, cdir_offset, =
        data[eocd_at, ::Zip::CentralDirectory::STATIC_EOCD_SIZE].unpack('VvvvvVVv')
      if count == 0xFFFF || cdir_size == 0xFFFFFFFF || cdir_offset == 0xFFFFFFFF
        count, cdir_size, cdir_offset = read_zip64_eocd(data, eocd_at, file_size - tail_size)
      end
      [cdir_offset, cdir_size, count]
    end

    def read_zip64_eocd(data, eocd_at, base)
      locator_at = eocd_at - ::Zip::CentralDirectory::ZIP64_EOCD_LOC_SIZE
      locator = if locator_at.negative?
                  @io.seek(base + locator_at, IO::SEEK_SET)
                  @io.read(::Zip::CentralDirectory::ZIP64_EOCD_LOC_SIZE)
                else
                  data[locator_at, ::Zip::CentralDirectory::ZIP64_EOCD_LOC_SIZE]
                end
      sig, _disk, zip64_offset, = locator.unpack('VVQ<')
      unless sig == ::Zip::CentralDirectory::ZIP64_EOCD_LOCATOR_SIG
        raise ::Zip::Error,
              'Zip64 end of central directory locator signature expected but not found'
      end

      @io.seek(zip64_offset, IO::SEEK_SET)
      fields = read_exactly(::Zip::CentralDirectory::ZIP64_STATIC_EOCD_SIZE).unpack('VQ<vvVVQ<Q<Q<Q<')
      [fields[7], fields[8], fields[9]]
    end

    def read_central_entries(offset, count)
      @io.seek(offset, IO::SEEK_SET)
      Array.new(count) { read_central_entry }
    end

    def read_central_entry
      buf = read_exactly(::Zip::CDIR_ENTRY_STATIC_HEADER_LENGTH)
      (sig, _version_made, _version_needed, gp_flags, _method, _time, _date,
       _crc, compressed_size, size, name_len, extra_len, comment_len, disk,
       _iattr, _eattr, local_offset) = buf.unpack('VvvvvvvVVVvvvvvVV')
      unless sig == ::Zip::CENTRAL_DIRECTORY_ENTRY_SIGNATURE
        raise ::Zip::Error, 'Zip consistency problem while reading central directory entry'
      end

      name = read_exactly(name_len)
      extra = read_exactly(extra_len)
      read_exactly(comment_len) # Skip over the entry comment.
      { gp_flags: gp_flags, name: name, extra: extra,
        local_header_offset: resolve_local_offset(extra, size, compressed_size, local_offset) }
    end

    def resolve_local_offset(extra, size, compressed_size, local_offset)
      return local_offset unless local_offset == 0xFFFFFFFF

      content = zip64_content(extra)
      raise ::Zip::Error, 'Zip64 extra field expected but not found' unless content

      content = content.dup
      content.slice!(0, 8) if size == 0xFFFFFFFF
      content.slice!(0, 8) if compressed_size == 0xFFFFFFFF
      content.slice!(0, 8).unpack1('Q<')
    end

    def zip64_content(extra)
      index = 0
      while index + 4 <= extra.bytesize
        id  = extra[index, 2]
        len = extra[index + 2, 2].unpack1('v')
        return extra[index + 4, len] if id == ZIP64_ID

        index += 4 + len
      end
      nil
    end

    def read_local_header(offset)
      @io.seek(offset, IO::SEEK_SET)
      buf = @io.read(::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH)
      return nil unless buf && buf.bytesize == ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH

      sig, _version, gp_flags, _method, _time, _date, _crc, _csize, _size,
        name_len, extra_len = buf.unpack('VvvvvvVVVvv')
      return nil unless sig == ::Zip::LOCAL_ENTRY_SIGNATURE

      { gp_flags: gp_flags, name: read_exactly(name_len), extra: read_exactly(extra_len) }
    rescue SystemCallError
      nil
    end

    def declared_encoding(gp_flags)
      if (gp_flags & EFS_FLAG) != 0
        [Encoding::UTF_8, :efs_flag]
      elsif ::Zip.force_entry_names_encoding
        [Encoding.find(::Zip.force_entry_names_encoding), :forced]
      else
        [Encoding::IBM437, :zip_default]
      end
    end

    def unicode_path_fields(extra_bin)
      fields = []
      index = 0
      while index + 4 <= extra_bin.bytesize
        id  = extra_bin[index, 2]
        len = extra_bin[index + 2, 2].unpack1('v')
        break if index + 4 + len > extra_bin.bytesize

        fields << extra_bin[index + 4, len] if id == UNICODE_PATH_ID
        index += 4 + len
      end
      fields
    end

    def audit_entry(central)
      observations = []
      issues = []
      observations << build_observation(:central_directory, central, issues)
      local = read_local_header(central[:local_header_offset])
      if local
        observations << build_observation(:local_header, local, issues)
        check_name_match(observations, central, local, issues)
      else
        issues << Issue.new(:unreadable_local_header,
                            "Local header for '#{observations.first.decoded_utf8}' " \
                            'could not be read')
      end
      checks = unicode_path_checks(central, local, issues)
      EntryAudit.new(observations: observations, unicode_path_checks: checks, issues: issues)
    end

    def build_observation(source, header, issues)
      encoding, encoding_source = declared_encoding(header[:gp_flags])
      obs = NameObservation.new(source: source, raw: header[:name],
                                declared_encoding: encoding, encoding_source: encoding_source)
      if encoding == Encoding::UTF_8 && !obs.valid_encoding?
        issues << Issue.new(:invalid_utf8,
                            "The #{source} name 0x#{obs.raw.unpack1('H*')} is declared " \
                            'as UTF-8 but is not valid UTF-8')
      end
      obs
    end

    def check_name_match(observations, central, local, issues)
      return if central[:name] == local[:name]

      central_obs, local_obs = observations
      message = "Local header name '#{local_obs.decoded_utf8}' differs from " \
                "central directory name '#{central_obs.decoded_utf8}'"
      issues << Issue.new(:local_central_name_mismatch, message)
    end

    def unicode_path_checks(central, local, issues)
      checks = []
      check_unicode_path(checks, issues, :central_directory, central[:extra], central[:name])
      check_unicode_path(checks, issues, :local_header, local[:extra], local[:name]) if local
      checks
    end

    def check_unicode_path(checks, issues, source, extra, header_name)
      unicode_path_fields(extra).each do |content|
        check = build_unicode_path_check(source, content, header_name)
        checks << check
        audit_unicode_path_check(check, issues)
      end
    end

    def build_unicode_path_check(source, content, header_name)
      return UnicodePathCheck.new(source, nil, nil, nil, nil, false) if content.bytesize < 5

      utf8 = (content[5..] || +'').dup.force_encoding(Encoding::UTF_8)
      UnicodePathCheck.new(source, content.getbyte(0), content[1, 4].unpack1('V'),
                           ::Zlib.crc32(header_name), utf8, utf8.valid_encoding?)
    end

    def audit_unicode_path_check(check, issues)
      if check.version.nil?
        issues << Issue.new(:malformed_unicode_path,
                            "Truncated Unicode Path extra field in #{check.source}")
        return
      end
      if check.version != ::Zip::ExtraField::UnicodePath::VERSION
        issues << Issue.new(:unicode_path_unknown_version,
                            "Unsupported Unicode Path extra field version " \
                            "#{check.version} in #{check.source}")
      end
      unless check.crc_ok?
        message = "Unicode Path extra field in #{check.source} has name CRC " \
                  "0x#{check.name_crc32.to_s(16)} but the header name CRCs as " \
                  "0x#{check.computed_crc32.to_s(16)}"
        issues << Issue.new(:unicode_path_crc_mismatch, message)
      end
      return if check.valid_utf8

      issues << Issue.new(:invalid_utf8,
                          "Unicode Path extra field name in #{check.source} " \
                          'is not valid UTF-8')
    end
  end
end
