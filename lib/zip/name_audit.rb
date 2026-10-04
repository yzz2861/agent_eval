# frozen_string_literal: true

require 'zlib'

module Zip
  # Records how a single zip entry's name appears in each part of an
  # archive: the local file header, the central directory, and the
  # Info-ZIP Unicode Path extra field (0x7075), if present. An audit is
  # collected while an archive is read when `Zip.name_audit_mode` is
  # `:lenient` or `:strict`, and is exposed via `Zip::Entry#name_audit`.
  class NameAudit
    # A single observation of an entry's name in one part of an archive.
    class Record
      # Where in the archive this observation was made: `:local_header`,
      # `:central_directory` or `:unicode_path_extra`.
      attr_reader :source

      # For `:unicode_path_extra` records, which header's extra field this
      # record came from (`:local_header` or `:central_directory`).
      # `nil` otherwise.
      attr_reader :context

      # The raw name bytes, exactly as stored in the archive
      # (`Encoding::BINARY`).
      attr_reader :raw_bytes

      # The encoding the archive itself declares for the name ('UTF-8'
      # when the EFS general purpose flag is set, or as implied by the
      # Unicode Path extra field), or `nil` when nothing is declared.
      attr_reader :declared_encoding

      # The encoding rubyzip applied when decoding (the value of
      # `Zip.force_entry_names_encoding` at read time), or `nil`.
      attr_reader :applied_encoding

      # The name as decoded and normalised by rubyzip.
      attr_reader :decoded_name

      # For `:unicode_path_extra` records, the CRC32 of the header name
      # bytes declared by the field. `nil` otherwise.
      attr_reader :name_crc32

      def initialize(source:, raw_bytes:, declared_encoding:, applied_encoding:, decoded_name:,
                     context: nil, name_crc32: nil)
        @source = source
        @context = context
        @raw_bytes = raw_bytes
        @declared_encoding = declared_encoding
        @applied_encoding = applied_encoding
        @decoded_name = decoded_name
        @name_crc32 = name_crc32
      end

      def to_s
        fields = [context ? "#{source} (#{context})" : source.to_s]
        fields << "raw=#{raw_bytes.unpack1('H*')}"
        fields << "declared=#{declared_encoding || 'unspecified'}"
        fields << "applied=#{applied_encoding || 'none'}"
        fields << "decoded=#{decoded_name.inspect}"
        fields << format('name_crc32=%08x', name_crc32) if name_crc32
        fields.join(' ')
      end
    end

    # A single inconsistency found between an entry's recorded names.
    # `code` is a Symbol identifying the kind of issue (`:name_mismatch`,
    # `:invalid_utf8`, `:unicode_path_crc_mismatch` or `:duplicate_name`)
    # and `message` is a human-readable description.
    Issue = Struct.new(:code, :message)

    # All name observations made for the entry (Array of Record).
    attr_reader :records

    def initialize # :nodoc:
      @records = []
      @reported_issues = []
    end

    def add_record(record) # :nodoc:
      @records << record
    end

    def add_issue(code, message) # :nodoc:
      @reported_issues << Issue.new(code, message)
    end

    # The first record with the given source, or `nil`.
    def [](source)
      @records.find { |record| record.source == source }
    end

    # All inconsistencies detected across the recorded names
    # (Array of Issue).
    def issues
      computed_issues + @reported_issues
    end

    # True when no inconsistencies have been detected.
    def consistent?
      issues.empty?
    end

    def to_s
      lines = @records.map { |record| "  #{record}" }
      issues.each { |issue| lines << "  [#{issue.code}] #{issue.message}" }
      lines.join("\n")
    end

    private

    def computed_issues
      [name_mismatch_issue, invalid_encoding_issues, crc_mismatch_issues].flatten.compact
    end

    def name_mismatch_issue
      local = self[:local_header]
      central = self[:central_directory]
      return unless local && central && local.raw_bytes != central.raw_bytes

      Issue.new(
        :name_mismatch,
        "local header name #{local.raw_bytes.inspect} does not match " \
        "central directory name #{central.raw_bytes.inspect}"
      )
    end

    def invalid_encoding_issues
      @records.filter_map do |record|
        next unless record.declared_encoding == 'UTF-8'
        next if record.raw_bytes.dup.force_encoding('UTF-8').valid_encoding?

        Issue.new(
          :invalid_utf8,
          "#{record.source} name bytes #{record.raw_bytes.inspect} are " \
          'declared as UTF-8 but are not valid UTF-8'
        )
      end
    end

    def crc_mismatch_issues
      @records.filter_map do |record|
        next unless record.source == :unicode_path_extra
        next if record.name_crc32.nil?

        base = self[record.context]
        next if base.nil? || record.name_crc32 == Zlib.crc32(base.raw_bytes)

        Issue.new(
          :unicode_path_crc_mismatch,
          "Unicode Path extra field CRC32 #{format('%08x', record.name_crc32)} " \
          "does not match the #{record.context} name bytes #{base.raw_bytes.inspect}"
        )
      end
    end
  end
end
