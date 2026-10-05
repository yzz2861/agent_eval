# coding: US-ASCII
# frozen_string_literal: true

require "stringio"
require "strscan"

require_relative 'encoding'

module REXML
  if StringScanner::Version < "1.0.0"
    module StringScannerCheckScanString # :nodoc:
      refine StringScanner do
        def check(pattern)
          pattern = /#{Regexp.escape(pattern)}/ if pattern.is_a?(String)
          super(pattern)
        end

        def scan(pattern)
          pattern = /#{Regexp.escape(pattern)}/ if pattern.is_a?(String)
          super(pattern)
        end

        def match?(pattern)
          pattern = /#{Regexp.escape(pattern)}/ if pattern.is_a?(String)
          super(pattern)
        end

        def skip(pattern)
          pattern = /#{Regexp.escape(pattern)}/ if pattern.is_a?(String)
          super(pattern)
        end
      end
    end
    using StringScannerCheckScanString
  end

  # Generates Source-s.  USE THIS CLASS.
  class SourceFactory # :nodoc:
    # Generates a Source object
    # @param arg Either a String, or an IO
    # @return a Source, or nil if a bad argument was given
    def SourceFactory::create_from(arg)
      if arg.respond_to? :read and
          arg.respond_to? :readline and
          arg.respond_to? :nil? and
          arg.respond_to? :eof?
        IOSource.new(arg)
      elsif arg.respond_to? :to_str
        IOSource.new(StringIO.new(arg))
      elsif arg.kind_of? Source
        arg
      else
        raise "#{arg.class} is not a valid input stream.  It must walk \n"+
          "like either a String, an IO, or a Source."
      end
    end
  end

  # A Source can be searched for patterns, and wraps buffers and other
  # objects and provides consumption of text
  class Source # :nodoc: all
    include Encoding
    # The line number of the last consumed text
    attr_reader :line
    attr_reader :encoding

    module Private
      SPACES_PATTERN = /\s+/um
      SCANNER_RESET_SIZE = 100000
      PRE_DEFINED_TERM_PATTERNS = {}
      pre_defined_terms = ["'", '"', "<", "]]>", "?>"]
      if StringScanner::Version < "3.1.1"
        pre_defined_terms.each do |term|
          PRE_DEFINED_TERM_PATTERNS[term] = /#{Regexp.escape(term)}/
        end
      else
        pre_defined_terms.each do |term|
          PRE_DEFINED_TERM_PATTERNS[term] = term
        end
      end
      PRE_DEFINED_TERM_PATTERNS.freeze
    end
    private_constant :Private

    # Constructor
    # @param arg must be a String, and should be a valid XML document
    # @param encoding if non-null, sets the encoding of the source to this
    # value, overriding all encoding detection
    def initialize(arg, encoding=nil)
      @orig = arg
      @scanner = StringScanner.new(@orig)
      if encoding
        self.encoding = encoding
      else
        detect_encoding
      end
      @line = 0
      @encoded_terms = {}
    end

    # The current buffer (what we're going to read next)
    def buffer
      @scanner.rest
    end

    def drop_parsed_content
      if @scanner.pos > Private::SCANNER_RESET_SIZE
        @scanner.string = @scanner.rest
      end
    end

    def buffer_encoding=(encoding)
      @scanner.string.force_encoding(encoding)
    end

    # Inherited from Encoding
    # Overridden to support optimized en/decoding
    def encoding=(enc)
      return unless super
      encoding_updated
    end

    def read(term = nil)
    end

    def read_until(term)
      pattern = Private::PRE_DEFINED_TERM_PATTERNS[term] || /#{Regexp.escape(term)}/
      data = @scanner.scan_until(pattern)
      unless data
        data = @scanner.rest
        @scanner.pos = @scanner.string.bytesize
      end
      data
    end

    def ensure_buffer
    end

    def match(pattern, cons=false)
      if cons
        @scanner.scan(pattern).nil? ? nil : @scanner
      else
        @scanner.check(pattern).nil? ? nil : @scanner
      end
    end

    def match?(pattern, cons=false)
      if cons
        !@scanner.skip(pattern).nil?
      else
        !@scanner.match?(pattern).nil?
      end
    end

    def skip_spaces
      @scanner.skip(Private::SPACES_PATTERN) ? true : false
    end

    def position
      @scanner.pos
    end

    def position=(pos)
      @scanner.pos = pos
    end

    def peek_byte
      @scanner.peek_byte
    end

    def scan_byte
      @scanner.scan_byte
    end

    # @return true if the Source is exhausted
    def empty?
      @scanner.eos?
    end

    # @return the current line in the source
    def current_line
      lines = @orig.split
      res = lines.grep @scanner.rest[0..30]
      res = res[-1] if res.kind_of? Array
      lines.index( res ) if res
    end

    private
    # Appends data while keeping the scanner contents valid UTF-8.
    # A multi byte character split across chunks leaves its leading
    # bytes in @pending_bytes until the rest arrives.
    def append_data(data)
      bytes = data.b
      bytes = @pending_bytes + bytes unless @pending_bytes.empty?
      @pending_bytes = +"".b
      bytes = split_incomplete_utf8(bytes)
      @scanner << bytes
    end

    # Everything already accepted is valid UTF-8, so a freshly appended
    # chunk can only split the single multi byte character that straddles
    # the junction.  Find its lead byte among the final four bytes and,
    # if it lacks all its continuation bytes, park the partial bytes
    # in @pending_bytes.  Constant work regardless of buffer size.
    def split_incomplete_utf8(bytes)
      total = bytes.bytesize
      start = [0, total - 4].max
      index = total
      while index > start
        index -= 1
        byte = bytes.getbyte(index)
        next if byte >= 0x80 && byte <= 0xBF
        if byte < 0x80
          break
        end
        expected = if byte >= 0xF0 then 4
                   elsif byte >= 0xE0 then 3
                   else 2
                   end
        if total - index < expected
          @pending_bytes = bytes.byteslice(index, total - index).b
          return bytes.byteslice(0, index).force_encoding(::Encoding::UTF_8)
        end
        break
      end
      bytes.force_encoding(::Encoding::UTF_8)
    end


    def detect_encoding
      scanner_encoding = @scanner.rest.encoding
      detected_encoding = "UTF-8"
      begin
        @scanner.string.force_encoding("ASCII-8BIT")
        if @scanner.scan(/\xfe\xff/n)
          detected_encoding = "UTF-16BE"
        elsif @scanner.scan(/\xff\xfe/n)
          detected_encoding = "UTF-16LE"
        elsif @scanner.scan(/\xef\xbb\xbf/n)
          detected_encoding = "UTF-8"
        end
      ensure
        @scanner.string.force_encoding(scanner_encoding)
      end
      self.encoding = detected_encoding
    end

    def encoding_updated
      if @encoding != 'UTF-8'
        @scanner.string = decode(@scanner.rest)
        @to_utf = true
      else
        @to_utf = false
        @scanner.string.force_encoding(::Encoding::UTF_8)
      end
    end
  end

  # A Source that wraps an IO.  See the Source class for method
  # documentation
  class IOSource < Source # :nodoc:
    #attr_reader :block_size

    # block_size has been deprecated
    def initialize(arg, block_size=500, encoding=nil)
      @er_source = @source = arg
      @to_utf = false
      @pending_buffer = nil

      if encoding
        super(+"", encoding)
      else
        super(@source.read(3) || +"")
      end

      if !@to_utf and
          @orig.respond_to?(:force_encoding) and
          @source.respond_to?(:external_encoding) and
          @source.external_encoding != ::Encoding::UTF_8
        @force_utf8 = true
      else
        @force_utf8 = false
      end
    end

    def read(term = nil, min_bytes = 1)
      term = encode(term) if term
      begin
        str = readline(term)
        @scanner << str
        read_bytes = str.bytesize
        begin
          while read_bytes < min_bytes
            str = readline(term)
            @scanner << str
            read_bytes += str.bytesize
          end
        rescue IOError
        end
        true
      rescue Exception, NameError
        @source = nil
        false
      end
    end

    def read_until(term)
      pattern = Private::PRE_DEFINED_TERM_PATTERNS[term] || /#{Regexp.escape(term)}/
      term = @encoded_terms[term] ||= encode(term)
      until str = @scanner.scan_until(pattern)
        break if @source.nil?
        break if @source.eof?
        @scanner << readline(term)
      end
      if str
        read if @scanner.eos? and @source and !@source.eof?
        str
      else
        rest = @scanner.rest
        @scanner.pos = @scanner.string.bytesize
        rest
      end
    end

    def ensure_buffer
      read if @scanner.eos? && @source
    end

    def match( pattern, cons=false )
      # To avoid performance issue, we need to increase bytes to read per scan
      min_bytes = 1
      while true
        if cons
          md = @scanner.scan(pattern)
        else
          md = @scanner.check(pattern)
        end
        break if md
        return nil if pattern.is_a?(String)
        return nil if @source.nil?
        return nil unless read(nil, min_bytes)
        min_bytes *= 2
      end

      md.nil? ? nil : @scanner
    end

    def match?( pattern, cons=false )
      # To avoid performance issue, we need to increase bytes to read per scan
      min_bytes = 1
      while true
        if cons
          n_matched_bytes = @scanner.skip(pattern)
        else
          n_matched_bytes = @scanner.match?(pattern)
        end
        return true if n_matched_bytes
        return false if pattern.is_a?(String)
        return false if @source.nil?
        return false unless read(nil, min_bytes)
        min_bytes *= 2
      end
    end

    def empty?
      super and ( @source.nil? || @source.eof? )
    end

    # @return the current line in the source
    def current_line
      begin
        pos = @er_source.pos        # The byte position in the source
        lineno = @er_source.lineno  # The XML < position in the source
        @er_source.rewind
        line = 0                    # The \r\n position in the source
        begin
          while @er_source.pos < pos
            @er_source.readline
            line += 1
          end
        rescue
        end
        @er_source.seek(pos)
      rescue IOError, SystemCallError
        pos = -1
        line = -1
      end
      [pos, lineno, line]
    end

    private
    def readline(term = nil)
      if @pending_buffer
        begin
          str = @source.readline(term || @line_break)
        rescue IOError
        end
        if str.nil?
          str = @pending_buffer
        else
          str = @pending_buffer + str
        end
        @pending_buffer = nil
      else
        str = @source.readline(term || @line_break)
      end
      return nil if str.nil?

      if @to_utf
        decode(str)
      else
        str.force_encoding(::Encoding::UTF_8) if @force_utf8
        str
      end
    end

    def encoding_updated
      case @encoding
      when "UTF-16BE", "UTF-16LE"
        @source.binmode
        @source.set_encoding(@encoding, @encoding)
      end
      @line_break = encode(">")
      @pending_buffer, @scanner.string = @scanner.rest, +""
      @pending_buffer.force_encoding(@encoding)
      super
    end
  end

  # A Source for incremental parsing.  Data is pushed into the parser
  # with #feed instead of being read from an IO, so the parser never
  # blocks waiting for input.
  class FeedSource < Source # :nodoc: all
    # Signaled internally when the parser reaches the end of the data
    # that has been fed so far while it is in the middle of a construct.
    class NeedMoreData < StandardError # :nodoc: all
    end

    # Minimum consumed prefix before it is worth rebuilding the
    # scanner string.
    TRIM_THRESHOLD = 4096

    def initialize(data=nil, encoding=nil)
      super(+"", encoding)
      @finished = false
      @bom_buffer = nil
      @pending_bytes = +"".b
      feed(data) unless data.nil?
    end

    # Appends the given data to the data already fed to the parser.
    def feed(data)
      raise ArgumentError, "can't feed data after finish" if @finished
      return self if data.nil?
      data = data.to_str
      data = decode(data.dup) if @to_utf
      if @bom_buffer
        data = @bom_buffer + data
        @bom_buffer = nil
      end
      data = consume_bom(data)
      append_data(data)
      self
    end

    # Marks the end of the input.  No more data may be fed after this
    # point, so a parser that reaches the end of the buffer reports the
    # input as malformed instead of asking for more data.
    def finish
      @finished = true
      if @bom_buffer
        @scanner << @bom_buffer
        @bom_buffer = nil
      end
      unless @pending_bytes.empty?
        @scanner << @pending_bytes.force_encoding(::Encoding::UTF_8)
        @pending_bytes = +"".b
      end
      self
    end

    def finished?
      @finished
    end

    # Returns true when all fed data has been consumed.
    def empty?
      @scanner.eos? and @pending_bytes.empty?
    end

    # Called by the parser at the top of an event.  When only an
    # incomplete multi byte character is buffered, more data is needed
    # before it can be interpreted.
    def ensure_buffer
      if @scanner.eos? and not @pending_bytes.empty? and not @finished
        need_more_data
      end
    end

    # Returns true when a failed speculative parse can plausibly be
    # completed by the next chunk.  Inside a construct the decisive
    # terminator is a ">" (markup) or "]]>" (declarations); when the
    # remaining data contains no such terminator, the construct may
    # simply be truncated.  Genuinely malformed input (for example
    # "<bad @>") still contains the terminator and is reported at
    # once.  Whitespace and a single leading "<" do not count either.
    def parsed_to_end?
      rest = @scanner.rest
      stripped = rest.sub(/\A\s+/, "")
      stripped = stripped.sub(/\A</, "")
      stripped = stripped.sub(/\A\s+/, "")
      return true if stripped.empty?
      not stripped.include?(">")
    end

    # Captures the complete parser-visible state so that a speculative
    # parse attempt can be rolled back to the last completed event
    # boundary when it turns out more data is needed.
    def checkpoint
      {
        :position => @scanner.pos,
        :encoding => @encoding,
        :to_utf => @to_utf,
      }
    end

    def restore(checkpoint)
      @scanner.pos = checkpoint[:position]
      unless @encoding == checkpoint[:encoding]
        self.encoding = checkpoint[:encoding]
      end
      @to_utf = checkpoint[:to_utf]
    end

    # No-op: BaseParser#pull calls this at the start of every event,
    # but the feed parser has already saved a checkpoint before that
    # call.  Trimming here would invalidate the saved position before
    # a possible rollback.  The consumed prefix is trimmed once the
    # event is successfully committed (see FeedParser).
    def drop_parsed_content
    end

    # Drops the consumed prefix after an event has been committed.
    # Unlike #drop_parsed_content this is only called when the parser
    # knows the consumed bytes will never be scanned again.
    def trim!
      trim_parsed_prefix
    end

    def current_line
      [nil, nil, @line]
    end

    # Raised when a multi byte character (for example a UTF-8
    # character) is split across two chunks.
    def peek_byte
      ensure_complete_character
      @scanner.peek_byte
    end

    def scan_byte
      ensure_complete_character
      @scanner.scan_byte
    end

    def read_until(term)
      pattern = Private::PRE_DEFINED_TERM_PATTERNS[term] || /#{Regexp.escape(term)}/
      term = @encoded_terms[term] ||= encode(term)
      data = @scanner.scan_until(pattern)
      unless data
        need_more_data unless @finished
        data = @scanner.rest
        @scanner.pos = @scanner.string.bytesize
      end
      data
    end

    def match(pattern, cons=false)
      if pattern.is_a?(String)
        match_literal(pattern, cons)
      else
        if cons
          result = @scanner.scan(pattern)
        else
          result = @scanner.check(pattern)
        end
        result.nil? ? nil : @scanner
      end
    end

    def match?(pattern, cons=false)
      if pattern.is_a?(String)
        !match_literal(pattern, cons).nil?
      else
        if cons
          matched = !@scanner.skip(pattern).nil?
        else
          matched = !@scanner.check(pattern).nil?
        end
        matched
      end
    end

    def skip_spaces
      matched = @scanner.skip(Private::SPACES_PATTERN)
      if matched
        true
      else
        need_more_data unless @finished
        false
      end
    end

    private

    # Drops the consumed prefix in bounded chunks so that the cost is
    # amortized (O(1) per event) instead of copying the whole growing
    # remainder on every event.
    def trim_parsed_prefix
      pos = @scanner.pos
      return if pos.zero?
      # At an event boundary pos points at the next event, so the
      # whole prefix up to it is committed.  Rebuild when the prefix
      # is large enough to be worth copying, which keeps the retained
      # buffer small and the copying amortized (O(1) per byte).
      @scanner.string = @scanner.rest if pos >= TRIM_THRESHOLD
    end

    # StringScanner#peek_byte returns the raw byte even when a multi
    # byte character is truncated at the end of the buffer.  Detect a
    # trailing incomplete UTF-8 sequence and wait for the rest of the
    # character.
    def ensure_complete_character
      return if @finished
      string = @scanner.string
      return unless string.encoding == ::Encoding::UTF_8
      pos = @scanner.pos
      byte = string.getbyte(pos)
      return if byte.nil? || byte < 0x80
      expected = if byte >= 0xF0
                   4
                 elsif byte >= 0xE0
                   3
                 else
                   2
                 end
      available = string.bytesize - pos
      if available < expected
        need_more_data
      end
      # Validate only the expected continuation bytes, not the whole
      # buffer, so this stays constant in the buffer size.
      expected.times do |index|
        next_byte = string.getbyte(pos + index)
        if index.zero?
          valid_lead = byte >= 0xC2 && byte <= 0xF4
          need_more_data unless valid_lead
        elsif next_byte.nil? || next_byte < 0x80 || next_byte > 0xBF
          need_more_data
        end
      end
    end

    # Matches a fixed string.  When the available data ends with a
    # prefix of the string (for example a quote or "?" at the end of a
    # chunk), more data is requested instead of treating the construct
    # as malformed.
    def match_literal(literal, cons)
      encoded = encode(literal)
      if literal_at?(encoded, @scanner.pos)
        @scanner.pos += encoded.bytesize if cons
        return @scanner
      end
      unless @finished
        # A partial prefix is only ambiguous when it is all the data
        # left: the next chunk may complete the literal.  A prefix in
        # the middle of the buffer is a real mismatch (for example a
        # "<" that starts an element while looking for "<?").
        remaining = @scanner.string.bytesize - @scanner.pos
        limit = [encoded.bytesize, remaining].min
        prefix = @scanner.string.byteslice(@scanner.pos, limit)
        if prefix && encoded.start_with?(prefix) && limit == remaining
          need_more_data
        end
      end
      nil
    end

    # Checks whether the given (already encoded) literal appears at
    # +position+ without copying the remaining buffer.
    def literal_at?(encoded, position)
      length = encoded.bytesize
      return false if position + length > @scanner.string.bytesize
      @scanner.string.byteslice(position, length) == encoded
    end

    # Handles a leading BOM, which may itself be split across chunks.
    # Only UTF-8 and UTF-16 BOMs are detected; the bytes are consumed
    # exactly as IOSource does at construction time.
    def consume_bom(data)
      raw = data.dup.force_encoding("ASCII-8BIT")
      bom = nil
      ["\xef\xbb\xbf", "\xfe\xff", "\xff\xfe"].each do |candidate|
        if raw.start_with?(candidate)
          bom = candidate
          break
        end
      end
      if bom
        if bom == "\xef\xbb\xbf"
          self.encoding = "UTF-8"
        elsif bom == "\xfe\xff"
          self.encoding = "UTF-16BE"
        else
          self.encoding = "UTF-16LE"
        end
        rest = data.byteslice(bom.bytesize, data.bytesize)
        return rest || "".b
      end
      # Keep a partial BOM prefix until more bytes arrive.
      3.downto(1) do |size|
        prefix = raw.byteslice(0, size)
        candidates = ["\xef\xbb\xbf", "\xfe\xff", "\xff\xfe"]
        if candidates.any? { |candidate| candidate.start_with?(prefix) }
          @bom_buffer = data.byteslice(0, size).b
          rest = data.byteslice(size, data.bytesize)
          return rest || +("".b)
        end
      end
      data
    end

    def need_more_data
      raise NeedMoreData
    end

    # FeedSource never transcends the buffered data itself, so keep the
    # data exactly as it was fed after an encoding update.
    def encoding_updated
      if @encoding != 'UTF-8'
        @scanner.string = decode(@scanner.rest)
        @to_utf = true
      else
        @to_utf = false
        @scanner.string.force_encoding(::Encoding::UTF_8)
      end
    end
  end
end
