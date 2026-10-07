# frozen_string_literal: true

module Net
  class FTP
    #
    # ListEntry represents a single entry parsed from a raw FTP LIST
    # response by Net::FTP::ListParser.
    #
    # Each entry has a pathname, a type (:file, :directory, or :symlink),
    # and the original raw text it was parsed from.  Depending on the
    # dialect, size, mtime, link target, and VMS version number may also
    # be available.
    #
    class ListEntry
      # The name of the entry, exactly as it appeared in the listing.
      # Interior spaces and "->" text are preserved.
      attr_reader :pathname

      # One of :file, :directory, or :symlink.
      attr_reader :type

      # The size of the entry, or nil if the dialect did not report one.
      # For Unix and DOS listings this is a byte count; for VMS listings
      # it is the number of used (512-byte) blocks as reported by the
      # server.
      attr_reader :size

      # The modification time as a Time, or nil if not reported.
      attr_reader :mtime

      # The precision of the information originally present in the
      # listing: :day, :minute, or :second.  For example, a Unix
      # timestamp shown as "Oct  8 12:34" has :minute precision; no
      # seconds were invented while parsing.  nil when mtime is nil.
      attr_reader :mtime_precision

      # For symlinks, the link target text exactly as it appeared after
      # the " -> " arrow; nil otherwise.
      attr_reader :link_target

      # For VMS listings, the integer file version number (the ";n"
      # suffix); nil otherwise.
      attr_reader :version

      # The original line(s) this entry was parsed from.  VMS entries
      # that spanned multiple physical lines contain them joined by
      # "\n".
      attr_reader :raw

      def initialize(pathname:, type:, raw:, size: nil, mtime: nil,
                     mtime_precision: nil, link_target: nil, version: nil)
        @pathname = pathname
        @type = type
        @size = size
        @mtime = mtime
        @mtime_precision = mtime_precision
        @link_target = link_target
        @version = version
        @raw = raw
      end

      def file?
        @type == :file
      end

      def directory?
        @type == :directory
      end

      def symlink?
        @type == :symlink
      end

      def entry?
        true
      end

      def diagnostic?
        false
      end
    end

    #
    # ListParseDiagnostic describes a LIST response line that could not
    # be parsed into a ListEntry.  The original text is always preserved
    # in #raw so callers can log or fall back to their own handling.
    #
    class ListParseDiagnostic
      # The original line, unmodified.
      attr_reader :raw

      # A human-readable explanation of why the line was not parsed.
      attr_reader :message

      # The 1-based number of the line within the parsed input.
      attr_reader :line_number

      def initialize(raw:, message:, line_number: nil)
        @raw = raw
        @message = message
        @line_number = line_number
      end

      def entry?
        false
      end

      def diagnostic?
        true
      end
    end

    #
    # ListParser parses raw FTP LIST responses (as returned by
    # Net::FTP#list) into structured ListEntry objects.  It exists for
    # servers without MLSD support and understands the common Unix,
    # DOS, and VMS listing dialects.
    #
    # The parser is independent of Net::FTP#list: it never changes the
    # raw strings returned by that method.  Feed those strings to
    # ListParser.parse explicitly:
    #
    #   lines = ftp.list
    #   results = Net::FTP::ListParser.parse(lines, dialect: :unix,
    #                                          now: Time.now,
    #                                          utc_offset: "+08:00")
    #
    # parse returns an array in line order containing ListEntry objects
    # for recognized lines and ListParseDiagnostic objects for lines
    # that could not be recognized.  Blank lines are skipped.
    #
    # Dialect selection:
    #
    # [dialect: :unix, :dos, or :vms]
    #   Parses every line with the given dialect.  Lines that do not
    #   match produce diagnostics.
    # [dialect: :auto (default)]
    #   Examines the whole (multi-line) sample and uses a dialect only
    #   when exactly one dialect parses every non-blank line.  Mixed or
    #   ambiguous samples yield diagnostics for every line instead of
    #   seemingly complete but guessed entries.
    #
    # Unix timestamps shown without a year ("Oct  8 12:34") are
    # interpreted relative to the +now+ reference time: the reference
    # year is used, moving back one year when the result would be in
    # the future.  Such times are taken to be in the server's timezone,
    # given by +utc_offset+ (anything Time.new accepts, e.g. "+08:00"
    # or seconds; defaults to the offset of +now+).
    #
    module ListParser
      DIALECTS = [:unix, :dos, :vms].freeze

      MONTHS = {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4,
        "may" => 5, "jun" => 6, "jul" => 7, "aug" => 8,
        "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
      }.freeze

      UNIX_RE = /\A(?<kind>[-dl])(?<perms>[rwxstST-]{9})\+?\s+
                 (?<nlink>\d+)\s+(?<owner>\S+)\s+(?<group>\S+)\s+
                 (?<size>\d+)\s+
                 (?<month>[A-Za-z]{3})\s+(?<day>\d{1,2})\s+
                 (?<timeyear>\d{1,2}:\d{2}|\d{4})\s+
                 (?<name>.+)\z/x

      DOS_RE = /\A(?<month>\d{2})-(?<day>\d{2})-(?<year>\d{2})\s+
                (?<hour>\d{2}):(?<min>\d{2})(?<ampm>AM|PM)\s+
                (?:(?<dir><DIR>)|(?<size>\d+))\s+
                (?<name>.+)\z/xi

      VMS_RE = /\A(?<name>\S+);(?<version>\d+)\s+
                (?<used>\d+)(?:\/(?<allocated>\d+))?\s+
                (?<day>\d{1,2})-(?<month>[A-Za-z]{3})-(?<year>\d{4})\s+
                (?<hour>\d{1,2}):(?<min>\d{2})
                (?::(?<sec>\d{2})(?<frac>\.\d+)?)?
                (?:\s+(?<rest>.*))?\z/x

      # A VMS name/version alone on a line: the entry continues on the
      # next physical line.
      VMS_PENDING_RE = /\A(?<name>\S+);(?<version>\d+)\s*\z/

      module_function

      #
      # Parses LIST response lines.  +input+ may be an array of lines or
      # a single string.  Returns an array of ListEntry and
      # ListParseDiagnostic objects in line order.  See the ListParser
      # module documentation for the keyword arguments.
      #
      def parse(input, dialect: :auto, now: Time.now, utc_offset: nil)
        lines = input.is_a?(String) ? input.split(/\r\n|\r|\n/) : input.to_a
        utc_offset = now.utc_offset if utc_offset.nil?
        dialect = dialect.to_sym
        if dialect == :auto
          detected = detect(lines, now, utc_offset)
          if detected
            parse_lines(lines, detected, now, utc_offset)
          else
            lines.each_with_index.each_with_object([]) do |(line, idx), out|
              next if line.strip.empty?
              out << ListParseDiagnostic.new(
                raw: line,
                line_number: idx + 1,
                message: "could not determine the LIST dialect of this " \
                         "sample (mixed, ambiguous, or unrecognized input)"
              )
            end
          end
        else
          unless DIALECTS.include?(dialect)
            raise ArgumentError,
                  "unknown LIST dialect: #{dialect.inspect} " \
                  "(expected :auto, :unix, :dos, or :vms)"
          end
          parse_lines(lines, dialect, now, utc_offset)
        end
      end

      # Returns the detected dialect symbol, or nil when zero or more
      # than one dialect can parse the whole sample.
      def detect(lines, now, utc_offset)
        viable = DIALECTS.select do |dialect|
          results = parse_lines(lines, dialect, now, utc_offset)
          results.any?(&:entry?) && results.none?(&:diagnostic?)
        end
        viable.length == 1 ? viable.first : nil
      end
      private_class_method :detect

      def parse_lines(lines, dialect, now, utc_offset)
        results = []
        pending = nil # [raw_line, line_number] of an incomplete VMS entry
        lines.each_with_index do |line, idx|
          next if line.strip.empty?
          if dialect == :vms
            pending = parse_vms_line(line, idx, pending, results,
                                     now, utc_offset)
          else
            entry = dialect == :unix ?
              parse_unix(line, now, utc_offset) :
              parse_dos(line, utc_offset)
            results << (entry || unrecognized(line, idx, dialect))
          end
        end
        if pending
          results << ListParseDiagnostic.new(
            raw: pending[0],
            line_number: pending[1],
            message: "VMS entry continues on the next line, but the " \
                     "listing ended before the continuation arrived"
          )
        end
        results
      end
      private_class_method :parse_lines

      def parse_vms_line(line, idx, pending, results, now, utc_offset)
        if pending
          entry = parse_vms("#{pending[0]} #{line.strip}",
                            now, utc_offset,
                            raw: "#{pending[0]}\n#{line}")
          if entry
            results << entry
            return nil
          end
          results << ListParseDiagnostic.new(
            raw: pending[0],
            line_number: pending[1],
            message: "VMS entry continuation could not be parsed"
          )
        end
        entry = parse_vms(line, now, utc_offset, raw: line)
        if entry
          results << entry
          nil
        elsif VMS_PENDING_RE.match?(line)
          [line, idx + 1]
        else
          results << unrecognized(line, idx, :vms)
          nil
        end
      end
      private_class_method :parse_vms_line

      def unrecognized(line, idx, dialect)
        ListParseDiagnostic.new(
          raw: line,
          line_number: idx + 1,
          message: "line does not match the #{dialect} LIST format"
        )
      end
      private_class_method :unrecognized

      def parse_unix(line, now, utc_offset)
        match = UNIX_RE.match(line) or return nil
        month = MONTHS[match[:month].downcase] or return nil
        day = match[:day].to_i
        return nil unless day.between?(1, 31)
        timeyear = match[:timeyear]
        if timeyear.include?(":")
          hour, min = timeyear.split(":").map!(&:to_i)
          return nil unless hour.between?(0, 23) && min.between?(0, 59)
          year = now.year
          year -= 1 if Time.new(year, month, day, hour, min, 0,
                                utc_offset) > now
          mtime = Time.new(year, month, day, hour, min, 0, utc_offset)
          precision = :minute
        else
          mtime = Time.new(timeyear.to_i, month, day, 0, 0, 0, utc_offset)
          precision = :day
        end
        name = match[:name]
        case match[:kind]
        when "d"
          type = :directory
          target = nil
        when "l"
          type = :symlink
          name, target = name.split(" -> ", 2)
          return nil unless target
        else
          type = :file
          target = nil
        end
        ListEntry.new(pathname: name, type: type, raw: line,
                      size: match[:size].to_i, mtime: mtime,
                      mtime_precision: precision, link_target: target)
      end
      private_class_method :parse_unix

      def parse_dos(line, utc_offset)
        match = DOS_RE.match(line) or return nil
        month = match[:month].to_i
        day = match[:day].to_i
        hour = match[:hour].to_i
        min = match[:min].to_i
        return nil unless month.between?(1, 12) && day.between?(1, 31)
        return nil unless hour.between?(1, 12) && min.between?(0, 59)
        hour = hour % 12
        hour += 12 if match[:ampm].casecmp("PM").zero?
        year = match[:year].to_i
        year += year < 80 ? 2000 : 1900
        mtime = Time.new(year, month, day, hour, min, 0, utc_offset)
        ListEntry.new(pathname: match[:name],
                      type: match[:dir] ? :directory : :file,
                      raw: line,
                      size: match[:dir] ? nil : match[:size].to_i,
                      mtime: mtime, mtime_precision: :minute)
      end
      private_class_method :parse_dos

      def parse_vms(text, now, utc_offset, raw:)
        match = VMS_RE.match(text) or return nil
        month = MONTHS[match[:month].downcase] or return nil
        day = match[:day].to_i
        hour = match[:hour].to_i
        min = match[:min].to_i
        return nil unless day.between?(1, 31) &&
                          hour.between?(0, 23) && min.between?(0, 59)
        sec = match[:sec]
        if sec
          return nil unless sec.to_i.between?(0, 59)
          sec = sec.to_i + (match[:frac] ? match[:frac].to_r : 0)
          precision = :second
        else
          sec = 0
          precision = :minute
        end
        mtime = Time.new(match[:year].to_i, month, day, hour, min, sec,
                         utc_offset)
        name = match[:name]
        if name.sub!(/\.DIR\z/i, "")
          type = :directory
        else
          type = :file
        end
        ListEntry.new(pathname: name, type: type, raw: raw,
                      size: match[:used].to_i, mtime: mtime,
                      mtime_precision: precision,
                      version: match[:version].to_i)
      end
      private_class_method :parse_vms
    end
  end
end
