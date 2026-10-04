# frozen_string_literal: true

class CSV
  # The result of dialect sniffing, returned by CSV.sniff.
  #
  # A Sniffing reports the candidate column separators (+delimiters+,
  # best guess first), the detected +quote_char+ and the detected
  # +row_separator+, together with a machine readable +status+ and
  # human readable +notes+ that explain ambiguous or problematic
  # situations.
  #
  # +status+ is one of:
  #
  # [:ok]              The dialect was determined. There may still be
  #                    informational notes.
  # [:ambiguous]       More than one delimiter explains the sample
  #                    equally well. +delimiters+ lists all of them,
  #                    and +notes+ explains the tie.
  # [:need_more_data]  The sample (bounded by the read limit) ended
  #                    before enough complete records were seen, for
  #                    example in the middle of a quoted field. This
  #                    is *not* a format error: sniff again with a
  #                    larger +limit+.
  # [:malformed]       The sample violates the CSV structure (for
  #                    example an unterminated quoted field at end of
  #                    input, or stray characters after a closing
  #                    quote). More data will not fix this.
  #
  # When the sniffed input is an IO that cannot be rewound, the bytes
  # consumed while sniffing are available as +sample+, and +io+
  # returns a stream that replays +sample+ before delegating to the
  # original IO, so no data (in particular not the first line) is
  # lost for the subsequent parser:
  #
  #   dialect = CSV.sniff(source)          # source may be non-seekable
  #   csv = CSV.new(dialect.io, **dialect.to_options)
  class Sniffing
    # Default upper bound of bytes CSV.sniff reads from the input.
    DEFAULT_LIMIT = 64 * 1024

    # Candidate column separators, best guess first. May be empty
    # (single column input).
    attr_reader :delimiters
    # The detected quote character.
    attr_reader :quote_char
    # The detected row separator: "\r\n", "\n", "\r" or :auto when it
    # could not be determined.
    attr_reader :row_separator
    # One of :ok, :ambiguous, :need_more_data or :malformed.
    attr_reader :status
    # Human readable explanations of ambiguities and problems.
    attr_reader :notes
    # The prefix of the input that was consumed while sniffing.
    attr_reader :sample
    # The read limit that was in effect.
    attr_reader :limit

    def initialize(delimiters:, quote_char:, row_separator:, status:,
                   notes:, sample:, limit:, truncated:, stream:) # :nodoc:
      @delimiters = delimiters.freeze
      @quote_char = quote_char
      @row_separator = row_separator
      @status = status
      @notes = notes.freeze
      @sample = sample
      @limit = limit
      @truncated = truncated
      @stream = stream
    end

    # The best delimiter guess (the first entry of +delimiters+), or
    # nil when there are no candidates.
    def delimiter
      @delimiters.first
    end

    def ok?
      @status == :ok
    end

    def ambiguous?
      @status == :ambiguous
    end

    def need_more_data?
      @status == :need_more_data
    end

    def malformed?
      @status == :malformed
    end

    # Whether the sample was cut off by the read limit.
    def truncated?
      @truncated
    end

    # Returns a Hash of CSV.new options (+col_sep+, +quote_char+ and
    # +row_sep+) built from the best guesses.
    def to_options
      options = {}
      options[:col_sep] = @delimiters.first if @delimiters.first
      options[:quote_char] = @quote_char if @quote_char
      options[:row_sep] = @row_separator if @row_separator.is_a?(String)
      options
    end

    # Returns an IO positioned at the beginning of the sniffed data,
    # ready to be handed to CSV.new. For non-seekable inputs this is a
    # stream that replays the consumed +sample+ before reading on from
    # the original IO, so the first line is not lost.
    def io
      @stream
    end
  end

  # :call-seq:
  #   sniff(string, limit: CSV::Sniffing::DEFAULT_LIMIT) -> CSV::Sniffing
  #   sniff(io,      limit: CSV::Sniffing::DEFAULT_LIMIT) -> CSV::Sniffing
  #
  # Guesses the dialect of CSV data whose format is not known in
  # advance, for example a file uploaded by a supplier that may use
  # commas, semicolons or tabs as column separators.
  #
  # At most +limit+ bytes are read from the input. The scan is quote
  # aware: separators and line endings inside quoted fields do not
  # count as field or record boundaries.
  #
  # Returns a CSV::Sniffing describing the candidate delimiters, the
  # quote character and the line ending style, and explaining
  # ambiguous situations:
  #
  #   dialect = CSV.sniff("a;b\n1;2\n")
  #   dialect.delimiters    # => [";"]
  #   dialect.quote_char    # => "\""
  #   dialect.row_separator # => "\n"
  #   dialect.status        # => :ok
  #
  # When the sample ends in the middle of a record because of the read
  # +limit+, the result reports <tt>:need_more_data</tt> rather than a
  # format error; genuinely broken input reports <tt>:malformed</tt>.
  #
  # The input may be a non-seekable IO (a pipe, a socket, ...). The
  # consumed prefix is handed back to the caller: CSV::Sniffing#io
  # returns a stream that replays it, so nothing is lost:
  #
  #   dialect = CSV.sniff(io)
  #   CSV.new(dialect.io, **dialect.to_options).each do |row|
  #     # ...
  #   end
  #
  # For a seekable IO the original position is restored, so the IO can
  # be passed to CSV.new directly.
  def self.sniff(input, limit: Sniffing::DEFAULT_LIMIT)
    Sniffer.sniff(input, limit)
  end
end
class CSV
  class Sniffer # :nodoc:
    CANDIDATE_DELIMITERS = [",", ";", "\t", "|", ":"].freeze
    QUOTE_CHARACTERS = ['"', "'"].freeze
    DELIMITER_BYTES = CANDIDATE_DELIMITERS.each_with_object({}) do |delimiter, hash|
      hash[delimiter.getbyte(0)] = delimiter
    end.freeze
    ROW_SEPARATOR_NAMES = {"\r\n" => "CRLF", "\n" => "LF", "\r" => "CR"}.freeze
    CR = 13
    LF = 10

    Scan = Struct.new(:delimiter_counts,
                      :row_separators,
                      :errors,
                      :quoted_fields,
                      :complete_records,
                      :ended,
                      :keyword_init => true)

    def self.sniff(input, limit)
      new(input, limit).sniff
    end

    def initialize(input, limit)
      unless limit.is_a?(Integer) and limit > 0
        raise ArgumentError, "limit must be a positive Integer"
      end
      @input = input
      @limit = limit
    end

    def sniff
      sample, truncated, stream = read_sample
      bytes = sample.b
      scans = QUOTE_CHARACTERS.collect do |quote_char|
        [quote_char, scan(bytes, quote_char, truncated)]
      end
      quote_char, scan = choose_scan(scans)
      delimiters, delimiter_note, delimiter_ambiguous = score_delimiters(scan)
      notes = []
      notes.concat(error_notes(scan))
      row_separator = decide_row_separator(scan, notes)
      notes.concat(sample_notes(scan, truncated))
      notes << delimiter_note if delimiter_note
      status = decide_status(scan, truncated, delimiter_ambiguous)
      Sniffing.new(:delimiters => delimiters,
                   :quote_char => quote_char,
                   :row_separator => row_separator,
                   :status => status,
                   :notes => notes,
                   :sample => sample,
                   :limit => @limit,
                   :truncated => truncated,
                   :stream => stream)
    end

    private

    def read_sample
      if @input.is_a?(String)
        sample = @input.byteslice(0, @limit) || +""
        truncated = @input.bytesize > @limit
        return [sample, truncated, StringIO.new(@input)]
      end

      position = begin
        @input.pos
      rescue IOError, SystemCallError, NoMethodError
        nil
      end

      sample = nil
      loop do
        remaining = @limit - (sample ? sample.bytesize : 0)
        break if remaining <= 0
        chunk = @input.read(remaining)
        break if chunk.nil? or chunk.empty?
        sample ? sample << chunk : sample = chunk.dup
      end
      sample ||= +""
      truncated = sample.bytesize >= @limit

      stream = nil
      unless position.nil?
        begin
          @input.pos = position
          stream = @input
        rescue IOError, SystemCallError
          stream = nil
        end
      end
      stream ||= PrefixIO.new(sample, @input)
      [sample, truncated, stream]
    end

    # Quote aware scan of the sample. Separators and line endings
    # inside quoted fields are not counted as boundaries.
    def scan(bytes, quote_char, truncated)
      quote_byte = quote_char.getbyte(0)
      delimiter_counts = {}
      CANDIDATE_DELIMITERS.each {|delimiter| delimiter_counts[delimiter] = []}
      current_counts = Hash.new(0)
      row_separators = {"\r\n" => 0, "\n" => 0, "\r" => 0}
      errors = []
      quoted_fields = 0
      complete_records = 0
      in_quotes = false
      after_quote = false
      field_has_content = false
      record_has_content = false
      quote_opened_at = nil

      index = 0
      size = bytes.bytesize
      while index < size
        byte = bytes.getbyte(index)
        if in_quotes
          if byte == quote_byte
            if bytes.getbyte(index + 1) == quote_byte
              index += 1 # escaped quote: skip both bytes
            else
              in_quotes = false
              after_quote = true
            end
          end
        elsif (delimiter = DELIMITER_BYTES[byte])
          current_counts[delimiter] += 1
          after_quote = false
          field_has_content = false
          record_has_content = true
        elsif byte == CR or byte == LF
          if byte == CR and bytes.getbyte(index + 1) == LF
            row_separators["\r\n"] += 1
            index += 1
          elsif byte == CR
            row_separators["\r"] += 1
          else
            row_separators["\n"] += 1
          end
          CANDIDATE_DELIMITERS.each do |candidate|
            delimiter_counts[candidate] << current_counts[candidate]
          end
          current_counts = Hash.new(0)
          complete_records += 1
          after_quote = false
          field_has_content = false
          record_has_content = false
        elsif after_quote
          errors << [:stray_character_after_quote, index]
          after_quote = false
          field_has_content = true
          record_has_content = true
        elsif byte == quote_byte and !field_has_content
          in_quotes = true
          quoted_fields += 1
          quote_opened_at = index
          record_has_content = true
        else
          field_has_content = true
          record_has_content = true
        end
        index += 1
      end

      ended =
        if in_quotes
          :in_quotes
        elsif record_has_content or after_quote
          :mid_record
        else
          :clean
        end

      if ended == :in_quotes and !truncated
        errors << [:unterminated_quote, quote_opened_at]
      elsif ended == :mid_record and !truncated
        # A final record without a trailing line ending is complete.
        CANDIDATE_DELIMITERS.each do |candidate|
          delimiter_counts[candidate] << current_counts[candidate]
        end
        complete_records += 1
      end

      Scan.new(:delimiter_counts => delimiter_counts,
               :row_separators => row_separators,
               :errors => errors,
               :quoted_fields => quoted_fields,
               :complete_records => complete_records,
               :ended => ended)
    end

    # Prefer a quote character that actually quoted something; among
    # those, prefer the scan with the fewest structural errors; break
    # remaining ties by the order of QUOTE_CHARACTERS.
    def choose_scan(scans)
      effective = scans.select {|_quote_char, scan| scan.quoted_fields > 0}
      pool = effective.empty? ? scans : effective
      pool.each_with_index.min_by do |(_quote_char, scan), index|
        [scan.errors.size, index]
      end.first
    end

    def score_delimiters(scan)
      scored = []
      CANDIDATE_DELIMITERS.each do |delimiter|
        counts = scan.delimiter_counts[delimiter]
        next if counts.nil? or counts.empty?
        frequencies = Hash.new(0)
        counts.each {|count| frequencies[count] += 1}
        mode_count, mode_frequency = frequencies.max_by do |count, frequency|
          [frequency, count]
        end
        next if mode_count.nil? or mode_count.zero?
        scored << [delimiter, mode_frequency, mode_count]
      end
      scored.sort_by! do |delimiter, frequency, count|
        [-frequency, -count, CANDIDATE_DELIMITERS.index(delimiter)]
      end

      note = nil
      ambiguous = false
      if scored.empty?
        if scan.complete_records > 0
          note = "no delimiter candidate appeared; " \
                 "the input looks like a single column"
        end
      else
        best_frequency = scored.first[1]
        best_count = scored.first[2]
        tied = scored.select do |_delimiter, frequency, count|
          frequency == best_frequency and count == best_count
        end
        if tied.size > 1
          names = tied.collect {|delimiter, _f, _c| delimiter.inspect}.join(" and ")
          note = "delimiter is ambiguous: " + names +
                 " each produce " + (best_count + 1).to_s +
                 " consistent column(s) in " + best_frequency.to_s + " record(s)"
          ambiguous = true
        end
      end
      [scored.collect {|delimiter, _f, _c| delimiter}, note, ambiguous]
    end

    def error_notes(scan)
      notes = []
      stray = scan.errors.select {|type, _position| type == :stray_character_after_quote}
      unless stray.empty?
        note = "unexpected character after a closing quote at byte " +
               stray.first[1].to_s
        note += " (and " + (stray.size - 1).to_s + " more)" if stray.size > 1
        notes << note
      end
      unterminated = scan.errors.find {|type, _position| type == :unterminated_quote}
      if unterminated
        notes << "unterminated quoted field opened at byte " +
                 unterminated[1].to_s +
                 "; the input ends inside a quoted value"
      end
      notes
    end

    def decide_row_separator(scan, notes)
      counts = scan.row_separators
      total = counts.values.inject(0, :+)
      return :auto if total.zero?

      ranked = counts.sort_by {|_separator, count| -count}
      top_separator = ranked.first[0]
      top_count = ranked.first[1]
      rest = total - top_count
      return top_separator if rest.zero?

      description = counts.select {|_separator, count| count > 0}.collect do |separator, count|
        count.to_s + "x " + ROW_SEPARATOR_NAMES[separator]
      end.join(", ")
      if ranked[1][1] == top_count
        notes << "mixed line endings (" + description + "); could not decide, "                  "row separator left as :auto"
        :auto
      else
        notes << "mixed line endings (" + description + "); "                  "using the majority (" + ROW_SEPARATOR_NAMES[top_separator] + ")"
        top_separator
      end
    end

    def sample_notes(scan, truncated)
      notes = []
      if truncated and scan.ended != :clean
        detail =
          if scan.ended == :in_quotes
            "inside a quoted field"
          else
            "in the middle of a record"
          end
        notes << "the sample of " + @limit.to_s + " byte(s) ends " + detail
      end
      if scan.complete_records.zero? and !truncated and scan.ended == :clean
        notes << "the input contains no records"
      elsif scan.complete_records == 1 and !truncated
        notes << "only 1 record available; delimiter consistency "                  "across records could not be verified"
      end
      notes
    end

    def decide_status(scan, truncated, delimiter_ambiguous)
      return :malformed if scan.errors.any?
      return :need_more_data if truncated and scan.complete_records < 2
      return :ok if scan.complete_records.zero?
      return :ambiguous if delimiter_ambiguous
      :ok
    end
    # An IO-like wrapper that replays the bytes consumed while
    # sniffing before delegating to the original, non-seekable
    # stream, so that no input (in particular not the first line)
    # is lost for the subsequent parser.
    class PrefixIO
      def initialize(prefix, io)
        @buffer = prefix.dup
        @io = io
      end

      def gets(separator = $/, limit = nil)
        return +"" if limit == 0
        if separator.nil?
          fill_until_eof
          return nil if @buffer.empty?
          return shift_bytes(limit || @buffer.bytesize)
        end

        loop do
          index = @buffer.index(separator)
          break if index and (limit.nil? or index + separator.bytesize <= limit)
          break if limit and @buffer.bytesize >= limit
          chunk = @io.gets(separator)
          break if chunk.nil?
          @buffer << chunk
        end

        return nil if @buffer.empty?
        index = @buffer.index(separator)
        if index and (limit.nil? or index + separator.bytesize <= limit)
          shift_bytes(index + separator.bytesize)
        elsif limit and @buffer.bytesize > limit
          shift_bytes(limit)
        else
          shift_bytes(@buffer.bytesize)
        end
      end

      def read(length = nil, outbuf = nil)
        result =
          if length.nil?
            fill_until_eof
            @buffer.empty? ? nil : shift_bytes(@buffer.bytesize)
          elsif length.zero?
            +""
          else
            fill_to(length)
            @buffer.empty? ? nil : shift_bytes([length, @buffer.bytesize].min)
          end
        if outbuf
          outbuf.replace(result || +"")
          outbuf
        else
          result
        end
      end

      def eof?
        @buffer.empty? and (!@io.respond_to?(:eof?) or @io.eof?)
      end

      def method_missing(name, *args, &block)
        if @io.respond_to?(name)
          @io.__send__(name, *args, &block)
        else
          super
        end
      end

      def respond_to_missing?(name, include_private = false)
        @io.respond_to?(name, include_private) || super
      end

      private

      def fill_until_eof
        loop do
          chunk = @io.read(8192)
          break if chunk.nil? or chunk.empty?
          @buffer << chunk
        end
      end

      def fill_to(length)
        while @buffer.bytesize < length
          chunk = @io.read(length - @buffer.bytesize)
          break if chunk.nil? or chunk.empty?
          @buffer << chunk
        end
      end

      def shift_bytes(count)
        result = @buffer.byteslice(0, count)
        @buffer = @buffer.byteslice(count, @buffer.bytesize - count) || +""
        result
      end
    end
  end
end
