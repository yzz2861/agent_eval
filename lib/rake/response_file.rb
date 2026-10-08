# frozen_string_literal: true

module Rake

  # Expands response file references (arguments of the form <tt>@path</tt>)
  # into a plain argv list using a published, shell-like quoting grammar.
  #
  # Expansion is opt-in: file references are only followed when the caller
  # (the +--response-files+ command line option, or an explicit call to
  # ResponseFile.expand) enables them.
  #
  # Quoting grammar (each referenced file is read as UTF-8):
  #
  # * Arguments are separated by whitespace; newlines act as whitespace.
  #   Whitespace inside a task argument list (between an unquoted [ and its
  #   matching ]) belongs to the task argument, so a whole task specification
  #   such as <tt>task['a b', c]</tt> is one argument.
  # * Outside quotes, a backslash escapes the next character. A backslash
  #   immediately before a newline is a line continuation and removes the
  #   newline. A dangling backslash at end of file is an error.
  # * Single quotes preserve every character literally, including
  #   backslashes, dollar signs and backticks.
  # * Double quotes preserve whitespace. A backslash inside double quotes
  #   escapes only another backslash, a double quote, a dollar sign, a
  #   backtick (or acts as a line continuation before a newline); it is
  #   otherwise literal.
  # * There is no variable or command substitution: <tt>$VAR</tt>,
  #   <tt>$(...)</tt> and backticks are passed through verbatim.
  # * A token whose first character, outside quotes, is <tt>@</tt> includes
  #   another response file (the remainder of the token is the path, which
  #   may contain quoted sections). A bare <tt>@</tt> or a quoted leading
  #   <tt>@</tt> is a literal argument.
  # * Relative paths are resolved against the directory of the file that
  #   contains the reference; command line references use the current
  #   working directory.
  #
  # Commas and brackets that were protected by quotes or backslashes inside
  # task arguments are re-emitted with the existing task-argument escapes,
  # so they survive Application#parse_task_string unchanged.
  class ResponseFile
    # Raised for any response file expansion failure.  #locations lists the
    # file location of the failure followed by the inclusion chain, and
    # #argument_index is the zero-based position of the originating
    # command-line argument.
    class Error < StandardError
      attr_reader :locations, :argument_index, :token_number

      def initialize(message, locations, argument_index, token_number=nil)
        @locations = locations
        @argument_index = argument_index
        @token_number = token_number
        super(message)
      end

      def to_s
        context = []
        context << "token #{@token_number}" if @token_number
        if @argument_index
          context << "command-line argument #{@argument_index + 1}"
        end

        message = super
        message += " (#{context.join(", ")})" unless context.empty?
        file_locations = @locations.reject { |loc|
          loc.path == "<command line>"
        }
        unless file_locations.empty?
          head, *rest = file_locations
          message += " at #{format_location(head)}"
          rest.each do |loc|
            message += ", included from #{format_location(loc)}"
          end
        end
        message
      end

      private

      def format_location(location)
        "#{location.path}:#{location.line}:#{location.column}"
      end
    end

    # A file/line/column position.
    Location = Struct.new(:path, :line, :column)

    # A tokenized argument.  +parts+ is a list of [text, protected?] pairs;
    # protected text came from quotes or a backslash escape.
    Token = Struct.new(:parts, :start_location, :number,
                       :leading_reference) do
      def value
        parts.map(&:first).join
      end

      # A reference begins with an unquoted @ and names a nonempty path.
      def reference?
        leading_reference && value.length > 1
      end

      def path
        value[1..-1]
      end
    end

    # Maximum nesting depth of file inclusions (command line is level 0).
    MAX_DEPTH = 10

    # Maximum total number of bytes read while expanding one command line.
    MAX_TOTAL_BYTES = 1 << 20

    # Expand response file references in +argv+.  Returns a new argv array;
    # arguments without references are copied through unchanged.
    def self.expand(argv, base_dir: Dir.pwd,
                    max_depth: MAX_DEPTH, max_total_bytes: MAX_TOTAL_BYTES)
      new(base_dir: base_dir, max_depth: max_depth,
          max_total_bytes: max_total_bytes).expand(argv)
    end

    def initialize(base_dir:, max_depth:, max_total_bytes:)
      @base_dir = base_dir
      @max_depth = max_depth
      @max_total_bytes = max_total_bytes
      @total_bytes = 0
      @included_real_paths = []
    end

    def expand(argv)
      argv.each_with_index.flat_map do |token, index|
        if command_line_reference?(token)
          reference_location = Location.new("<command line>", 0, 0)
          include_file(token[1..-1], reference_location, 0, index, [],
                       @base_dir)
        else
          [token]
        end
      end
    end

    private

    # Command line tokens carry no quote information (the invoking shell
    # consumed it), so only a leading @ followed by a path marks one.
    def command_line_reference?(token)
      token.start_with?("@") && token.length > 1
    end

    def include_file(path, reference_location, depth, argument_index,
                    parents, base_dir)
      if depth >= @max_depth
        raise_error("response file inclusion too deep " \
                    "(maximum #{@max_depth} files)",
                    reference_location, argument_index, parents)
      end

      full_path = File.expand_path(path, base_dir)
      bytes =
        begin
          File.binread(full_path)
        rescue SystemCallError => ex
          raise_error("cannot read response file #{path.inspect}: " \
                      "#{ex.class.name.split("::").last} - #{ex.message}",
                      reference_location, argument_index, parents)
        end

      account_bytes!(bytes, reference_location, argument_index, parents)

      real_path = begin
        File.realpath(full_path)
      rescue SystemCallError
        full_path
      end
      if @included_real_paths.include?(real_path)
        raise_error("cyclic response file inclusion of #{real_path.inspect}",
                    reference_location, argument_index, parents)
      end
      @included_real_paths.push(real_path)

      begin
        content = decode_utf8(bytes, full_path, argument_index, parents)
        location = Location.new(full_path, 1, 1)
        tokens = tokenize(content, location, argument_index, parents)
        tokens.flat_map do |token|
          if token.reference?
            child_parents = [Location.new(full_path, token.start_location.line,
                                         token.start_location.column)] + parents
            include_file(token.path, token.start_location, depth + 1,
                         argument_index, child_parents,
                         File.dirname(full_path))
          else
            [protect_task_arguments(token)]
          end
        end
      ensure
        @included_real_paths.delete(real_path)
      end
    end

    def account_bytes!(bytes, location, argument_index, parents)
      @total_bytes += bytes.bytesize
      return unless @total_bytes > @max_total_bytes
      raise_error("response files exceed the #{@max_total_bytes} byte limit",
                  location, argument_index, parents)
    end

    # Validate UTF-8 manually so the reported line and column point at the
    # first invalid byte.
    def decode_utf8(bytes, path, argument_index, parents)
      index = 0
      line = 1
      column = 1
      while index < bytes.bytesize
        length = utf8_char_length(bytes, index)
        unless length
          raise_error("response file is not valid UTF-8",
                      Location.new(path, line, column), argument_index,
                      parents)
        end
        if bytes.getbyte(index) == 0x0A
          line += 1
          column = 1
        else
          column += 1
        end
        index += length
      end
      bytes.force_encoding(Encoding::UTF_8)
    end

    def continuation_byte?(byte)
      byte && (0x80..0xBF).include?(byte)
    end

    def utf8_char_length(bytes, index)
      byte = bytes.getbyte(index)
      second = bytes.getbyte(index + 1)
      third = bytes.getbyte(index + 2)
      fourth = bytes.getbyte(index + 3)

      length =
        if byte <= 0x7F
          1
        elsif (0xC2..0xDF).include?(byte) && continuation_byte?(second)
          2
        elsif byte == 0xE0 && (0xA0..0xBF).include?(second) &&
              continuation_byte?(third)
          3
        elsif ((0xE1..0xEC).include?(byte) || byte == 0xEE || byte == 0xEF) &&
              continuation_byte?(second) && continuation_byte?(third)
          3
        elsif byte == 0xED && (0x80..0x9F).include?(second) &&
              continuation_byte?(third)
          3
        elsif byte == 0xF0 && (0x90..0xBF).include?(second) &&
              continuation_byte?(third) && continuation_byte?(fourth)
          4
        elsif (0xF1..0xF3).include?(byte) && continuation_byte?(second) &&
              continuation_byte?(third) && continuation_byte?(fourth)
          4
        elsif byte == 0xF4 && (0x80..0x8F).include?(second) &&
              continuation_byte?(third) && continuation_byte?(fourth)
          4
        end
      length
    end

    def tokenize(content, start_location, argument_index, parents)
      tokens = []
      parts = []
      token_start = nil
      leading_reference = false
      line = start_location.line
      column = start_location.column
      state = :normal
      index = 0
      bracket_depth = 0

      characters = content.chars

      while index < characters.length
        char = characters[index]
        here = Location.new(start_location.path, line, column)
        consumed = 1

        case state
        when :normal
          if char =~ /\s/ && bracket_depth.zero?
            if token_start
              flush_token(tokens, parts, token_start, leading_reference)
              parts = []
              token_start = nil
              leading_reference = false
            end
          elsif char == "["
            bracket_depth += 1
            token_start ||= here
            add_part(parts, char, false)
          elsif char == "]" && bracket_depth > 0
            bracket_depth -= 1
            token_start ||= here
            add_part(parts, char, false)
          elsif char == "\\"
            token_start ||= here
            if index + 1 >= characters.length
              raise_error("dangling backslash at end of response file", here,
                          argument_index, parents, tokens.length + 1)
            end
            add_part(parts, characters[index + 1], true) unless
              characters[index + 1] == "\n"
            consumed = 2
          elsif char == "'"
            token_start ||= here
            state = :single
          elsif char == '"'
            token_start ||= here
            state = :double
          else
            token_start ||= here
            leading_reference = true if parts.empty? && char == "@"
            add_part(parts, char, false)
          end
        when :single
          if char == "'"
            state = :normal
          else
            add_part(parts, char, true)
          end
        when :double
          case char
          when '"'
            state = :normal
          when "\\"
            if index + 1 >= characters.length
              raise_error("dangling backslash at end of response file", here,
                          argument_index, parents, tokens.length + 1)
            end
            escaped = characters[index + 1]
            if escaped == '"' || escaped == "\\" || escaped == "$" ||
                 escaped == '`'
              add_part(parts, escaped, true)
              consumed = 2
            elsif escaped == "\n"
              consumed = 2
            else
              add_part(parts, char, true)
            end
          else
            add_part(parts, char, true)
          end
        end

        consumed.times do |offset|
          if characters[index + offset] == "\n"
            line += 1
            column = 1
          else
            column += 1
          end
        end
        index += consumed
      end

      unless state == :normal
        quote_name = state == :single ? "single" : "double"
        raise_error("unterminated #{quote_name} quote",
                    token_start || start_location, argument_index, parents,
                    tokens.length + 1)
      end
      flush_token(tokens, parts, token_start, leading_reference)
      tokens
    end

    def flush_token(tokens, parts, start_location, leading_reference)
      return unless start_location
      tokens << Token.new(parts, start_location, tokens.length + 1,
                          leading_reference)
    end

    def add_part(parts, text, protected)
      last = parts.last
      if last && last[1] == protected
        last[0] << text
      else
        parts << [text.dup, protected]
      end
    end

    # Re-encode quote- or backslash-protected commas, brackets and
    # backslashes inside task arguments using the escapes understood by
    # Application#parse_task_string, so protected separators survive the
    # second parsing stage.
    def protect_task_arguments(token)
      value = token.value
      return value if value =~ /\A\w+=/ || value.start_with?("-")
      return value unless task_argument_token?(token)

      result = +""
      depth = 0
      token.parts.each do |text, part_protected|
        text.each_char do |char|
          structural = !part_protected &&
            (char == "[" || char == "]")
          if structural && char == "["
            depth += 1
            result << char
          elsif structural && char == "]" && depth > 0
            depth -= 1
            result << char
          elsif depth > 0 && part_protected && char =~ /[,\[\]\\]/
            result << "\\" << char
          else
            result << char
          end
        end
      end
      result
    end

    def task_argument_token?(token)
      depth = 0
      token.parts.each do |text, part_protected|
        next if part_protected
        text.each_char do |char|
          if char == "["
            depth += 1
          elsif char == "]" && depth > 0
            depth -= 1
            return true if depth == 0
          end
        end
      end
      false
    end

    def raise_error(message, location, argument_index, parents,
                   token_number=nil)
      locations = [location] + parents
      raise Error.new(message, locations, argument_index, token_number)
    end
  end
end
