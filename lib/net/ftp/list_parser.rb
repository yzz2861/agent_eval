# frozen_string_literal: true

require "date"

module Net
  class FTP
    #
    # Parses the human-readable text returned by the FTP +LIST+ command,
    # which is the only directory listing available on servers that do
    # not implement MLSD/MLST.
    #
    # Three common listing dialects are understood:
    #
    # +:unix+:: the output of Unix +ls -l+
    # +:dos+::  the output of MS-DOS/Windows +dir+
    # +:vms+::  the output of OpenVMS/VMS +DIRECTORY+
    #
    # The parser never raises for unrecognized input.  Lines it cannot
    # understand are returned as ListDiagnostic objects together with the
    # original text, so callers never silently lose data or receive entries
    # that merely look plausible.
    #
    module ListParser
      # Supported dialect identifiers.
      DIALECTS = [:unix, :dos, :vms].freeze

      # Raised when an unknown dialect is specified explicitly.
      class DialectError < ArgumentError; end

      # Raised for an invalid +timezone+ argument.
      class TimezoneError < ArgumentError; end

      MONTHS = {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4,
        "may" => 5, "jun" => 6, "jul" => 7, "aug" => 8,
        "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
      }.freeze

      # One parsed entry of a LIST response.
      #
      # +type+ is one of +:file+, +:directory+, +:symlink+, or +:other+.
      # +mtime_precision+ records how much of +mtime+ was actually present
      # in the listing (+:day+, +:minute+, or +:second+); missing
      # components are filled deterministically and must not be mistaken
      # for real data.
      class ListEntry
        # Attributes shared by every dialect.
        COMMON_ATTRIBUTES = %i[
          raw name type size mtime mtime_precision
          owner group mode nlink link_target dialect
        ].freeze

        # Additional attributes used by the VMS dialect.
        VMS_ATTRIBUTES =
          %i[blocks_used blocks_allocated version extension].freeze

        ATTRIBUTES = (COMMON_ATTRIBUTES + VMS_ATTRIBUTES).freeze

        attr_reader(*ATTRIBUTES)

        def initialize(attrs)
          ATTRIBUTES.each do |attribute|
            instance_variable_set("@#{attribute}".to_sym,
                                  attrs[attribute])
          end
        end

        # Returns +true+ if the entry is a regular file.
        def file?
          @type == :file
        end

        # Returns +true+ if the entry is a directory.
        def directory?
          @type == :directory
        end

        # Returns +true+ if the entry is a symbolic link.
        def symlink?
          @type == :symlink
        end

        def inspect
          "#<#{self.class} #{name.inspect} type=#{type}>"
        end
      end

      # A LIST line that could not be parsed.
      #
      # +line+ is the original, untouched text of the line and +reason+ is
      # a human-readable explanation suitable for logging.
      class ListDiagnostic
        attr_reader :line, :reason, :dialect

        def initialize(line, reason, dialect = nil)
          @line = line
          @reason = reason
          @dialect = dialect
        end

        def inspect
          "#<#{self.class} #{line.inspect}: #{reason}>"
        end
      end

      # The result of parsing a LIST response.
      class ListResult
        include Enumerable

        # The dialect used for parsing, or +nil+ when detection failed.
        attr_reader :dialect
        attr_reader :entries
        attr_reader :diagnostics

        def initialize(entries, diagnostics, dialect)
          @entries = entries
          @diagnostics = diagnostics
          @dialect = dialect
        end

        # Returns +true+ if every non-header line was parsed.
        def success?
          @diagnostics.empty?
        end

        def each(&block)
          @entries.each(&block)
        end

        def to_a
          @entries.dup
        end
      end

      class << self
        # Parses +input+ (a String or an Array of lines).
        #
        # +dialect+ may be one of the ListParser::DIALECTS, or +nil+ (the
        # default) to detect it from the sample.  When more than one
        # dialect matches the sample, or none does, no entries are guessed:
        # every meaningful line comes back as a diagnostic instead.
        #
        # +reference_time+ is used to interpret Unix timestamps that omit
        # the year (the common +ls -l+ recent-file format).  It defaults to
        # the current time; tests should always pass a fixed value.
        #
        # +timezone+ is the server timezone, used for listings without a
        # zone offset.  It may be a Numeric offset in seconds, a short
        # String offset such as +"UTC"+ or +"+09:00"+, or an object
        # responding to +base_utc_offset(reference_time)+ (e.g. a TZInfo
        # timezone).  IANA names like +"Asia/Shanghai"+ require TZInfo.
        # It defaults to the offset of +reference_time+.
        def parse(input, dialect = nil,
                  reference_time: nil, timezone: nil)
          dialect = normalize_dialect(dialect)
          lines = to_lines(input)
          reference_time = reference_time || Time.now
          offset = timezone_offset(timezone, reference_time)

          if dialect
            entries, diagnostics =
              parse_with(dialect, lines, reference_time, offset)
          else
            entries, diagnostics, dialect =
              detect_and_parse(lines, reference_time, offset)
          end

          ListResult.new(entries, diagnostics, dialect)
        end

        # Detects the dialect of +input+ without parsing it.
        #
        # Returns a dialect Symbol, +nil+ when nothing recognizable is
        # found, or +:ambiguous+ when more than one dialect matches.
        def detect_dialect(input)
          candidates = []
          to_lines(input).each do |line|
            dialects = classify(line)
            candidates.concat(dialects) unless dialects == :neutral
          end
          candidates.uniq!
          if candidates.length == 1
            candidates.first
          elsif candidates.empty?
            nil
          else
            :ambiguous
          end
        end

        private

        def normalize_dialect(dialect)
          return nil if dialect.nil?
          symbol = dialect.to_sym
          unless DIALECTS.include?(symbol)
            raise DialectError,
                  "unknown LIST dialect: #{dialect.inspect} "
                  "(expected one of #{DIALECTS.inspect})"
          end
          symbol
        end

        def to_lines(input)
          case input
          when String
            # Listing text may contain bytes that are invalid in the
            # source encoding; never raise while splitting lines.
            if input.valid_encoding?
              input.split(/\r?\n/)
            else
              input.b.split(/\r?\n/n).map(&:b)
            end
          when Array
            input.map(&:to_s)
          else
            input.to_str.to_s.split(/\r?\n/)
          end
        end

        def timezone_offset(timezone, reference_time)
          case timezone
          when nil
            reference_time.utc_offset
          when Numeric
            Integer(timezone)
          when String
            offset = Time.zone_offset(timezone)
            unless offset
              raise TimezoneError,
                    "unknown timezone: #{timezone.inspect}"
            end
            offset
          else
            if timezone.respond_to?(:base_utc_offset)
              timezone.base_utc_offset(reference_time)
            elsif timezone.respond_to?(:utc_offset)
              timezone.utc_offset
            else
              raise TimezoneError,
                    "unsupported timezone: #{timezone.inspect}"
            end
          end
        end

        def detect_and_parse(lines, reference_time, offset)
          dialect = detect_dialect(lines)
          case dialect
          when :ambiguous
            return [], ambiguous_diagnostics(lines), nil
          when nil
            return [], unrecognized_diagnostics(lines), nil
          else
            entries, diagnostics =
              parse_with(dialect, lines, reference_time, offset)
            return entries, diagnostics, dialect
          end
        end

        def ambiguous_diagnostics(lines)
          lines.filter_map do |line|
            next if neutral?(line)
            dialects = classify(line)
            if dialects == :neutral || dialects.empty?
              ListDiagnostic.new(line, "unrecognized LIST line")
            else
              ListDiagnostic.new(
                line,
                "LIST dialect could not be determined " +
                "(sample matches #{dialects.inspect})")
            end
          end
        end

        def unrecognized_diagnostics(lines)
          lines.filter_map do |line|
            next if neutral?(line)
            ListDiagnostic.new(line, "unrecognized LIST line")
          end
        end

        def parse_with(dialect, lines, reference_time, offset)
          send("parse_#{dialect}", lines, reference_time, offset)
        end

        # Classifies a single line for dialect detection.
        #
        # Returns +:neutral+ for blank/header lines, an empty Array for
        # unknown lines, or an Array of the dialects the line could belong
        # to (usually a single element).
        def classify(line)
          return :neutral if line.strip.empty?
          return :neutral if neutral_header?(line)
          dialects = []
          dialects << :unix if unix_line?(line)
          dialects << :dos if dos_line?(line)
          dialects << :vms if vms_entry_line?(line) ||
                             vms_fragment_line?(line)
          return dialects unless dialects.empty?
          []
        end

        def neutral?(line)
          line.strip.empty? || neutral_header?(line)
        end

        def neutral_header?(line)
          unix_neutral?(line) || dos_neutral?(line) || vms_neutral?(line)
        end

        def failure(line, reason, dialect)
          ListDiagnostic.new(line, reason, dialect)
        end

        #----------------------------------------------------------------
        # Unix "ls -l"
        #----------------------------------------------------------------

        UNIX_TOTAL_RE = /\Atotal\s+\d+\s*\z/.freeze
        UNIX_MODE_RE =
          /\A[dlcbps-][-rwxsStT]{9}[@+.eE]?\z/.freeze
        UNIX_ISO_DATE_RE =
          /\A(\d{4})-(\d{2})-(\d{2})\z/.freeze
        UNIX_LINK_INDICATOR = " -> ".freeze

        def unix_neutral?(line)
          UNIX_TOTAL_RE.match?(line)
        end

        def unix_line?(line)
          !parse_unix_line(line, Time.now, Time.now.utc_offset).nil?
        end

        def parse_unix(lines, reference_time, offset)
          entries = []
          diagnostics = []
          lines.each do |line|
            next if line.strip.empty? || unix_neutral?(line)
            parsed = parse_unix_line(line, reference_time, offset)
            if parsed
              entries << parsed
            else
              diagnostics << failure(line, "unrecognized Unix LIST line",
                                    :unix)
            end
          end
          return entries, diagnostics
        end

        def parse_unix_line(line, reference_time, offset)
          fields = line.split(/[ \t]+/)
          # Classic "ls -l" has 9+ fields; ISO dates use 8.
          return nil if fields.length < 8

          mode_text = fields[0]
          mode_char = mode_text[0]
          return nil unless UNIX_MODE_RE.match?(mode_text)
          return nil unless fields[1] =~ /\A\d+\z/
          size_index = if fields[4] =~ /\A\d+\z/
                         4
                       elsif fields[4] =~ /\A\d+,\z/ &&
                             fields[5] =~ /\A\d+\z/
                         # Device nodes show "major, minor" instead of a
                         # byte size.
                         4
                       end

          numeric_size_index =
            fields[4] =~ /\A\d+\z/ ? 4 : nil
          # A device node occupies two fields ("major,", "minor").
          date_search_index =
            numeric_size_index || (size_index ? 5 : 4)
          date_index, date_kind =
            unix_date_index(fields, date_search_index)
          return nil unless date_index

          name = fields[(date_index + date_kind)..-1].join(" ")
          return nil if name.empty?

          type = case mode_char
                 when ?d then :directory
                 when ?l then :symlink
                 when ?- then :file
                 else :other
                 end

          link_target = nil
          if type == :symlink
            link_position = name.index(UNIX_LINK_INDICATOR)
            if link_position
              link_target =
                name[(link_position + UNIX_LINK_INDICATOR.length)..-1]
              name = name[0, link_position]
              return nil if name.empty? || link_target.empty?
            end
          end

          mtime, precision =
            unix_mtime(fields, date_index, date_kind,
                       reference_time, offset)
          return nil unless mtime

          ListEntry.new(
            raw: line,
            name: name,
            type: type,
            size: numeric_size_index ? decimal(fields[4]) : nil,
            mtime: mtime,
            mtime_precision: precision,
            owner: fields[2],
            group: fields[3],
            mode: unix_mode(mode_text),
            nlink: decimal(fields[1]),
            link_target: link_target,
            dialect: :unix)
        end

        # Returns [index, kind] of the date fields, where kind is the
        # number of tokens consumed (2 or 3).
        def unix_date_index(fields, size_index)
          index = size_index + 1
          return nil unless fields[index]
          if MONTHS.key?(fields[index].downcase)
            # "Mon day  hh:mm" or "Mon day  yyyy"
            if fields[index + 1] =~ /\A\d{1,2}\z/
              third = fields[index + 2]
              if third && (third =~ /\A\d{1,2}:\d{2}(?::\d{2})?\z/ ||
                           third =~ /\A\d{4}\z/)
                return [index, 3]
              end
            end
          elsif UNIX_ISO_DATE_RE.match?(fields[index])
            # ISO dates are followed by a time token.
            if fields[index + 1] =~ /\A\d{1,2}:\d{2}(?::\d{2})?\z/
              return [index, 2]
            end
          end
          nil
        end

        def unix_mtime(fields, index, kind, reference_time, offset)
          if MONTHS.key?(fields[index].downcase)
            month = MONTHS[fields[index].downcase]
            day = decimal(fields[index + 1])
            third = fields[index + 2]
            if third =~ /\A(\d{1,2}):(\d{2})(?::(\d{2}))?\z/
              hour = decimal(Regexp.last_match(1))
              minute = decimal(Regexp.last_match(2))
              second = Regexp.last_match(3) ?
                decimal(Regexp.last_match(3)) : 0
              year = unix_infer_year(reference_time, month, day,
                                     hour, minute, second, offset)
              precision = Regexp.last_match(3) ? :second : :minute
              time = build_time(year, month, day, hour, minute, second,
                               offset)
              return [time, precision] if time
            elsif third =~ /\A\d{4}\z/
              year = decimal(third)
              time = build_time(year, month, day, 0, 0, 0, offset)
              return [time, :day] if time
            end
          else
            match = UNIX_ISO_DATE_RE.match(fields[index])
            year = decimal(match[1])
            month = decimal(match[2])
            day = decimal(match[3])
            time_token = fields[index + 1]
            if time_token =~ /\A(\d{1,2}):(\d{2})(?::(\d{2}))?\z/
              hour = decimal(Regexp.last_match(1))
              minute = decimal(Regexp.last_match(2))
              second = Regexp.last_match(3) ?
                decimal(Regexp.last_match(3)) : 0
              precision = Regexp.last_match(3) ? :second : :minute
              built = build_time(year, month, day, hour, minute, second,
                                offset)
              return [built, precision] if built
            end
          end
          nil
        end

        # Chooses the year for a year-less Unix timestamp.  The candidate is
        # the reference year; if it is more than a day in the future the
        # timestamp is assumed to be from the previous year.
        def unix_infer_year(reference_time, month, day,
                            hour, minute, second, offset)
          year = reference_time.year
          candidate = build_time(year, month, day, hour, minute, second,
                                 offset)
          if candidate - reference_time > 86400
            year -= 1
          end
          year
        end

        def unix_mode(mode_text)
          value = 0
          special_bits = {2 => 0o4000, 5 => 0o2000, 8 => 0o1000}
          9.times do |position|
            char = mode_text[position + 1]
            bit = 256 >> position
            case char
            when ?r, ?w then value |= bit
            when ?x then value |= bit
            when ?s, ?t
              value |= bit
              value |= special_bits[position]
            when ?S, ?T
              value |= special_bits[position]
            end
          end
          value
        end

        #----------------------------------------------------------------
        # MS-DOS / Windows "dir"
        #----------------------------------------------------------------

        DOS_DIR_HEADER_RE =
          /\A\s*(Directory of|Directory:|Volume (Serial Number|in drive|label is))/i.freeze
        DOS_FOOTER_RE =
          /\A\s*\d[\d,]*\s+File\(s\)/i.freeze
        DOS_BYTES_FREE_RE =
          /\A\s*\d[\d,]*\s+Dir\(s\)/i.freeze
        DOS_LINE_RE = /\A
          \s*
          (?<date>\d{1,4}[-\/.]\d{1,2}[-\/.]\d{2,4})\s+
          (?<time>\d{1,2}:\d{2}(?::\d{2})?\s*(?:[AaPp][Mm])?)\s+
          (?:(?<size>[\d,]+)|<(?<tag>[^>]+)>)\s+
          (?<name>\S.*?)
          (?:\s+\[(?<target>[^\]]*)\])?
          \s*\z/x.freeze
        DOS_DATE_SPLIT_RE = /[-\/.]/
        DOS_DIRECTORY_TAGS = %w[DIR D].freeze
        DOS_SYMLINK_TAGS = %w[SYMLINK SYMLINKD JUNCTION].freeze

        def dos_neutral?(line)
          DOS_DIR_HEADER_RE.match?(line) ||
            DOS_FOOTER_RE.match?(line) ||
            DOS_BYTES_FREE_RE.match?(line)
        end

        def dos_line?(line)
          !!DOS_LINE_RE.match(line)
        end

        def parse_dos(lines, reference_time, offset)
          entries = []
          diagnostics = []
          lines.each do |line|
            next if line.strip.empty? || dos_neutral?(line)
            match = DOS_LINE_RE.match(line)
            unless match
              diagnostics << failure(line, "unrecognized DOS LIST line",
                                    :dos)
              next
            end
            entry = dos_entry(match, line, reference_time, offset)
            if entry
              entries << entry
            else
              diagnostics << failure(line, "unrecognized DOS LIST line",
                                    :dos)
            end
          end
          return entries, diagnostics
        end

        def dos_entry(match, line, reference_time, offset)
          name = match[:name]
          tag = match[:tag]
          size = match[:size]
          return nil if name.nil? || name.empty?

          mtime, precision =
            dos_mtime(match[:date], match[:time], reference_time, offset)
          return nil unless mtime

          if tag
            upcased = tag.upcase
            if DOS_DIRECTORY_TAGS.include?(upcased)
              type = :directory
            elsif DOS_SYMLINK_TAGS.include?(upcased)
              type = :symlink
            else
              return nil
            end
            file_size = nil
          else
            return nil unless size
            type = :file
            file_size = decimal(size.delete(","))
          end

          ListEntry.new(
            raw: line,
            name: name,
            type: type,
            size: file_size,
            mtime: mtime,
            mtime_precision: precision,
            link_target: match[:target],
            dialect: :dos)
        end

        def dos_mtime(date_text, time_text, reference_time, offset)
          parts = date_text.split(DOS_DATE_SPLIT_RE).map { |part|
            decimal(part) rescue nil
          }
          return nil if parts.any?(&:nil?)
          first, second, third = parts
          return nil unless parts.length == 3
          year, month, day =
            if third >= 1000
              # YYYY-MM-DD (or MM/DD/YYYY, handled below)
              if first >= 1000
                [first, second, third]
              else
                [third, first, second]
              end
            else
              # MM-DD-YY is the conventional DOS/Windows order.
              [dos_two_digit_year(third, reference_time), first, second]
            end

          normalized = time_text.strip
          pm = false
          if normalized.sub!(/[AaPp][Mm]\z/, "")
            normalized.strip!
            pm = time_text =~ /[Pp][Mm]\z/
          end
          time_parts = normalized.split(":").map(&:strip).map { |part|
            decimal(part) rescue nil
          }
          return nil if time_parts.any?(&:nil?)
          hour, minute = time_parts[0], time_parts[1]
          second = time_parts[2] || 0
          precision = time_parts[2] ? :second : :minute
          if pm
            hour = hour == 12 ? 12 : hour + 12
          elsif hour == 12
            hour = 0
          end
          time = build_time(year, month, day, hour, minute, second, offset)
          time ? [time, precision] : nil
        end

        def dos_two_digit_year(two_digit_year, reference_time)
          century = (reference_time.year / 100) * 100
          candidate = century + two_digit_year
          if candidate - reference_time.year > 50
            candidate - 100
          elsif reference_time.year - candidate > 50
            candidate + 100
          else
            candidate
          end
        end

        #----------------------------------------------------------------
        # OpenVMS / VMS "DIRECTORY"
        #----------------------------------------------------------------
        #
        # A VMS file entry can span multiple physical lines:
        #
        #   NAME.EXT;N                    used/allocated    dd-MMM-yyyy [hh:mm:ss] [CC]
        #                                | <DD-MMM-yyyy ...>              (continuation)
        #
        # NAME.EXT;N holds the explicit version number N; directories
        # use the .DIR;1 suffix.  Continuation lines only add metadata
        # and are folded into the entry started on the preceding line.

        VMS_HEADER_RE =
          /\A\s*(Directory\s|%DIRECTORY-I|Total of\s)/i.freeze
        VMS_GRAND_TOTAL_RE =
          /\A\s*Grand total/i.freeze
        # A VMS name starts in column 0, contains an extension, and ends
        # with an explicit version: NAME.EXT;N (spaces allowed inside).
        VMS_ENTRY_RE = /\A
          (?<name>\S.*?\.[^\s.;]*?)
          ;(?<version>\d+)
          (?<tail>\s.*)?
        \z/x.freeze
        VMS_BLOCKS_RE =
          /\A\s*(?<used>\d+)(?:\/(?<allocated>\d+))?/.freeze
        VMS_DATE_SEARCH_RE =
          /\d{1,2}-[A-Za-z]{3,9}-\d{2,4}
           (?:\s+\d{1,2}:\d{2}(?::\d{2})?)?
           (?:\s+\d+\.\d+)?/x.freeze
        VMS_DATE_RE = /\A
          (?<day>\d{1,2})-(?<month>[A-Za-z]{3,9})-(?<year>\d{2,4})
          (?:\s+(?<hour>\d{1,2}):(?<min>\d{2})(?::(?<sec>\d{2}))?)?
          (?:\s+\d+\.\d+)?(?:\s+\[[^\]]*\])?\s*\z/x.freeze

        def vms_neutral?(line)
          VMS_HEADER_RE.match?(line) ||
            VMS_GRAND_TOTAL_RE.match?(line)
        end

        def vms_entry_line?(line)
          !!VMS_ENTRY_RE.match(line)
        end

        # A continuation line starts with whitespace (so it cannot begin
        # a VMS name) and carries a block count or a date fragment.
        def vms_fragment_line?(line)
          return false unless line.start_with?(?\s)
          text = line.strip
          !!VMS_DATE_SEARCH_RE.match(text) ||
            !!VMS_BLOCKS_RE.match(text)
        end

        def parse_vms(lines, reference_time, offset)
          entries = []
          diagnostics = []
          pending = nil
          raw_lines = []

          flush = -> {
            if pending
              entry = vms_finish_entry(pending, raw_lines,
                                      reference_time, offset)
              if entry
                entries << entry
              else
                diagnostics << failure(raw_lines.join("\n"),
                                      "incomplete or invalid VMS entry",
                                      :vms)
              end
              pending = nil
              raw_lines = []
            end
          }

          lines.each do |line|
            if line.strip.empty?
              flush.call
              next
            end
            if vms_neutral?(line)
              flush.call
              next
            end
            match = VMS_ENTRY_RE.match(line)
            if match
              flush.call
              pending = {
                name: match[:name],
                version: decimal(match[:version]),
                fragments: match[:tail] ? [match[:tail].strip] : [],
              }
              raw_lines << line
            elsif pending && vms_fragment_line?(line)
              pending[:fragments] << line.strip
              raw_lines << line
            else
              flush.call
              diagnostics << failure(line, "unrecognized VMS LIST line",
                                    :vms)
            end
          end
          flush.call
          return entries, diagnostics
        end

        def vms_finish_entry(pending, raw_lines, reference_time, offset)
          used = nil
          allocated = nil
          date_text = nil

          pending[:fragments].each do |fragment|
            fragment_used, fragment_allocated, fragment_date =
              vms_scan_fragment(fragment)
            used ||= fragment_used
            allocated ||= fragment_allocated
            date_text ||= fragment_date
          end

          return nil unless date_text
          mtime, precision = vms_mtime(date_text, reference_time, offset)
          return nil unless mtime

          full_name = pending[:name]
          directory = full_name.split("/").last
          extension = vms_extension(directory)
          is_directory = extension&.upcase == "DIR"
          base = directory

          ListEntry.new(
            raw: raw_lines.join("\n"),
            name: base,
            type: is_directory ? :directory : :file,
            size: used ? used * 512 : nil,
            mtime: mtime,
            mtime_precision: precision,
            blocks_used: used,
            blocks_allocated: allocated,
            version: pending[:version],
            extension: extension,
            dialect: :vms)
        end

        def vms_extension(name)
          position = name.rindex(".")
          position ? name[(position + 1)..-1] : nil
        end

        # Extracts [used, allocated, date_text] from one physical line
        # fragment.  Block counts are at the start of the first fragment;
        # the date may be bare, inside <...>, or followed by [attributes].
        def vms_scan_fragment(fragment)
          text = fragment.strip
          used = nil
          allocated = nil

          blocks = VMS_BLOCKS_RE.match(text)
          if blocks
            used = decimal(blocks[:used])
            allocated = blocks[:allocated] ?
              decimal(blocks[:allocated]) : nil
            text = text[blocks.end(0)..-1].strip
          end

          if text.start_with?(?<)
            close = text.index(?>)
            text = close ? text[1, close - 1] : text[1..-1].to_s
          end

          date_match = VMS_DATE_SEARCH_RE.match(text)
          date_string = date_match ? date_match[0] : nil
          [used, allocated, date_string]
        end

        def vms_mtime(date_text, reference_time, offset)
          match = VMS_DATE_RE.match(date_text.strip)
          return nil unless match
          month = MONTHS[match[:month][0, 3].downcase]
          return nil unless month
          year = decimal(match[:year])
          if year < 100
            year = dos_two_digit_year(year, reference_time)
          end
          hour = match[:hour] ? decimal(match[:hour]) : 0
          minute = match[:min] ? decimal(match[:min]) : 0
          second = match[:sec] ? decimal(match[:sec]) : 0
          precision = if match[:sec]
                        :second
                      elsif match[:min]
                        :minute
                      else
                        :day
                      end
          time = build_time(year, month, decimal(match[:day]),
                           hour, minute, second, offset)
          time ? [time, precision] : nil
        end

        #----------------------------------------------------------------
        # Shared time helpers
        #----------------------------------------------------------------

        def build_time(year, month, day, hour, minute, second, offset)
          return nil unless (1..12).cover?(month) &&
                            (1..31).cover?(day) &&
                            (0..23).cover?(hour) &&
                            (0..59).cover?(minute) &&
                            (0..60).cover?(second)
          # Date.new validates the calendar day (rejecting e.g.
          # Feb 29 in a non-leap year) without time rollover.
          Date.new(year, month, day)
          Time.new(year, month, day, hour, minute, second, offset)
        rescue ArgumentError
          nil
        end

        # Integer() parses a leading zero as octal; LIST numbers are
        # always decimal.
        def decimal(value)
          Integer(value, 10)
        end
      end
    end
  end
end
