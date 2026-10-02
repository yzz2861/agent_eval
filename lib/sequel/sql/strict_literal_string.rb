# frozen-string-literal: true

module Sequel
  module SQL
    # Strict placeholder parser for developer-written SQL fragments.  Unlike
    # the loose parsing used by PlaceholderLiteralString, placeholders are
    # only recognized in the SQL code area.  Colons and question marks inside
    # strings, quoted identifiers, and comments are treated as literal text.
    #
    # This is a pure tokenizer: it validates the template at parse time and
    # returns a string/argument array that can be rendered with the existing
    # placeholder array support.
    class StrictPlaceholderParser
      # PostgreSQL dollar-quote opening tag: $tag$, where tag is empty or an
      # identifier-like sequence.
      DOLLAR_OPEN_RE = /\A\$([A-Za-z_][A-Za-z0-9_]*)?\$/.freeze

      # Named placeholder: :name.  Names follow the loose parser's word rules
      # but must start immediately with an identifier character.
      NAMED_RE = /\A:([A-Za-z_][A-Za-z0-9_]*)/.freeze

      # PostgreSQL jsonb/hstore operators that begin with ? but are not
      # positional placeholders.  Multi-character operators are sorted
      # longest first so the longest matching prefix is consumed.  The
      # single-character ? exists/key operator is handled contextually.
      QUESTION_MULTI_OPERATORS = %w'?~# ?~* ?-| ?-# ?~ ?| ?& ?#'.freeze

      # Characters that may directly follow a positional placeholder without
      # changing its meaning (SQL punctuation or whitespace).
      PLACEHOLDER_FOLLOW_CHARS = " \t\n\r\f\v),.;]|=<>+-*/%!".freeze

      # A single ? directly followed (with no whitespace) by one of these is
      # the jsonb/hstore exists/key operator rather than a positional
      # placeholder.
      JSONB_SINGLE_OPERATOR_FOLLOW_RE = /\A[A-Za-z0-9_$'\x60(]/.freeze

      # Prefixes that can appear directly before a string literal (E'...',
      # B'...', X'...', N'...', U&'...').
      STRING_PREFIX_RE = /\A(?:U&|[EBXN])'/i.freeze

      # Parse +str+ and bind the +args+ hash or array to the placeholders.
      # Returns an array of fragments accepted by PlaceholderLiteralString
      # (string fragments with argument objects interleaved).
      def self.parse(str, args)
        new(str, args).parse
      end

      def initialize(str, args)
        @str = str.to_str
        @args = args
        @named = args.is_a?(Hash)
        @frags = []
        @used_keys = []
        @positional_count = 0
        @numbered_placeholders = []
        @positional_positions = []
        @buf = +""
        @i = 0
        @line = 1
        @column = 1
      end

      def parse
        while @i < @str.length
          c = @str[@i]
          case c
          when "-"
            if @str[@i + 1] == '-'
              scan_line_comment
            else
              advance
            end
          when "/"
            if @str[@i + 1] == '*'
              scan_block_comment
            else
              advance
            end
          when "'"
            scan_single_quoted_string
          when '"'
            scan_quoted_identifier('"', '"')
          when '`'
            scan_quoted_identifier('`', '`')
          when '$'
            unless scan_dollar_quoted_string
              advance
            end
          when '?'
            scan_question_mark
          when ':'
            scan_colon
          else
            if prefixed_string?
              scan_prefixed_string
            else
              advance
            end
          end
        end

        finish
      end

      private

      # Add a literal character to the current text fragment.
      def advance
        c = @str[@i]
        @buf << c
        @i += 1
        if c == "\n"
          @line += 1
          @column = 1
        else
          @column += 1
        end
      end

      # Copy +length+ bytes from the current position verbatim, updating the
      # line/column counters.
      def copy(length)
        slice = @str[@i, length]
        slice.each_char do |ch|
          @buf << ch
          if ch == "\n"
            @line += 1
            @column = 1
          else
            @column += 1
          end
        end
        @i += slice.length
      end

      # Advance over +length+ placeholder characters without buffering them.
      def consume(length)
        @str[@i, length].each_char do |ch|
          if ch == "\n"
            @line += 1
            @column = 1
          else
            @column += 1
          end
          @i += 1
        end
      end

      def position
        "line #{@line} column #{@column}"
      end

      def parse_error(message)
        raise Error, "#{message} in SQL fragment at #{position}"
      end

      def scan_line_comment
        copy(2)
        while @i < @str.length && @str[@i] != "\n"
          advance
        end
      end

      def scan_block_comment
        start_line, start_column = @line, @column
        copy(2)
        depth = 1
        while @i < @str.length
          if @str[@i] == '/' && @str[@i + 1] == '*'
            copy(2)
            depth += 1
          elsif @str[@i] == '*' && @str[@i + 1] == '/'
            copy(2)
            depth -= 1
            return if depth == 0
          else
            advance
          end
        end
        raise Error, "unterminated block comment in SQL fragment at line #{start_line} column #{start_column}"
      end

      def scan_single_quoted_string(backslash_escapes=false)
        start_line, start_column = @line, @column
        advance
        while @i < @str.length
          if backslash_escapes && @str[@i] == '\\'
            # In E'...' (and U&'...') strings, a backslash escapes the
            # following character (including the closing quote).
            copy(2)
          elsif @str[@i] == "'"
            if @str[@i + 1] == "'"
              copy(2)
            else
              advance
              return
            end
          else
            advance
          end
        end
        raise Error, "unterminated string literal in SQL fragment at line #{start_line} column #{start_column}"
      end

      def scan_prefixed_string
        # Skip the prefix (E, B, X, N, or U&), then scan the quoted body.
        escaped = @str[@i] =~ /\A[Ee]\z/ || @str[@i, 2] =~ /\AU&/i
        advance until @str[@i] == "'"
        scan_single_quoted_string(escaped)
      end

      def prefixed_string?
        rest = @str[@i, 4]
        rest.match?(STRING_PREFIX_RE)
      end

      def scan_quoted_identifier(open, close)
        start_line, start_column = @line, @column
        advance
        while @i < @str.length
          if @str[@i] == close
            if @str[@i + 1] == close
              copy(2)
            else
              advance
              return
            end
          else
            advance
          end
        end
        kind = open == '`' ? 'backtick quoted identifier' : 'quoted identifier'
        raise Error, "unterminated #{kind} in SQL fragment at line #{start_line} column #{start_column}"
      end

      def scan_dollar_quoted_string
        rest = @str[@i..-1] || String.new
        m = DOLLAR_OPEN_RE.match(rest)
        return false unless m

        tag = m[0]
        start_line, start_column = @line, @column
        copy(tag.length)
        close_at = @str.index(tag, @i)
        unless close_at
          raise Error, "unterminated dollar quoted string (#{tag}...#{tag}) in SQL fragment at line #{start_line} column #{start_column}"
        end
        copy(close_at - @i + tag.length)
        true
      end

      def scan_question_mark
        rest = @str[@i..-1] || String.new
        if (op = QUESTION_MULTI_OPERATORS.find { |o| rest.start_with?(o) })
          copy(op.length)
        elsif rest[1] =~ /\A[0-9]/
          # SQLite numbered placeholder (?NNN).  NNN is 1-based; each
          # distinct number maps to one argument, and repeated numbers reuse
          # the same argument (as in native SQLite).
          if @named
            parse_error("positional placeholder ? used with named arguments")
          end
          run = 1
          run += 1 while rest[run] =~ /\A[0-9]/
          number = rest[1, run - 1].to_i
          parse_error("invalid numbered placeholder #{rest[0, run]} (numbers must be 1-based)") if number < 1
          bind_numbered(number, run)
        elsif rest.length == 1 || PLACEHOLDER_FOLLOW_CHARS.include?(rest[1])
          if @named
            parse_error("positional placeholder ? used with named arguments")
          end
          bind_positional
        elsif rest[1] =~ JSONB_SINGLE_OPERATOR_FOLLOW_RE
          # Single-character jsonb/hstore operator written without
          # whitespace, e.g. +j?'key'+
          advance
        else
          # Unknown trailing character: be strict and treat ? as a placeholder
          # rather than silently swallowing it as an operator.
          if @named
            parse_error("positional placeholder ? used with named arguments")
          end
          bind_positional
        end
      end

      def scan_colon
        rest = @str[@i..-1] || String.new
        if rest.start_with?('::')
          # PostgreSQL/SQLite type cast operator, not a placeholder.
          copy(2)
        elsif (m = NAMED_RE.match(rest))
          name = m[1]
          unless @named
            parse_error("named placeholder :#{name} used with positional arguments")
          end
          bind_named(name.to_sym, m[0])
        else
          # Lone colon not followed by a valid name is literal SQL.
          advance
        end
      end

      def bind_positional(length=1)
        @positional_positions << [@line, @column]
        consume(length)
        @frags << @buf
        @buf = +""
        @frags << @positional_count
        @positional_count += 1
      end

      def bind_numbered(number, length)
        @positional_positions << [@line, @column, number]
        consume(length)
        @frags << @buf
        @buf = +""
        @frags << [:numbered, number]
        @numbered_placeholders << number
      end

      def bind_named(key, source)
        actual_key = key
        if @args.key?(key)
          actual_key = key
        elsif @args.key?(key.to_s)
          actual_key = key.to_s
        else
          parse_error("missing value for named placeholder #{source}")
        end
        consume(source.length)
        @frags << @buf
        @buf = +""
        @frags << actual_key
        @used_keys << actual_key
      end

      def finish
        @frags << @buf

        if @named
          referenced = @used_keys.uniq
          extra_keys = @args.keys.reject { |k| referenced.include?(k) }
          unless extra_keys.empty?
            list = extra_keys.map { |k| ":#{k}" }.sort.join(', ')
            raise Error, "unused named argument(s) #{list} provided to SQL fragment"
          end
          @frags.map! { |f| f.is_a?(String) ? f : @args[f] }
        else
          numbers = @numbered_placeholders.uniq
          unless @positional_count == 0 || numbers.empty?
            raise Error, "cannot mix positional ? placeholders with numbered ?NNN placeholders in SQL fragment"
          end
          count = numbers.empty? ? @positional_count : numbers.max
          if !numbers.empty? && numbers != (1..count).to_a
            raise Error, "numbered placeholders must form a contiguous 1-based sequence in SQL fragment (found #{numbers.map { |n| "?#{n}" }.join(', ')})"
          end
          unless count == @args.length
            if count < @args.length
              line, column = @positional_positions.last
              where = "last placeholder at line #{line} column #{column}"
              raise Error, "too many positional arguments for SQL fragment: #{@args.length} arguments for #{count} placeholder(s) (#{where})"
            else
              spot = @positional_positions[@args.length] || @positional_positions.last
              line, column = spot
              where = "first unbound placeholder at line #{line} column #{column}"
              raise Error, "missing positional argument(s) for SQL fragment: #{@args.length} arguments for #{count} placeholder(s) (#{where})"
            end
          end
          if numbers.empty?
            @frags.map! { |f| f.is_a?(Integer) ? @args[f] : f }
          else
            @frags.map! { |f| f.is_a?(Array) && f[0] == :numbered ? @args[f[1] - 1] : f }
          end
        end

        @frags
      end
    end

    # A PlaceholderLiteralString whose template was parsed strictly:
    # placeholders are recognized only in SQL code areas, and missing, extra,
    # or invalid arguments are detected when the fragment is created rather
    # than when SQL is emitted.
    class StrictPlaceholderLiteralString < PlaceholderLiteralString
      def initialize(str, args, parens=false)
        @parens = parens
        if str.is_a?(Array)
          # Re-entry from with_parens: the template was already compiled.
          @args = args.is_a?(Array) ? args.freeze : Array(args).freeze
          @str = str.freeze
          freeze
          return
        end
        if args.is_a?(Array) && args.length == 1 && args[0].is_a?(Hash)
          args = args[0]
        elsif !args.is_a?(Array) && !args.is_a?(Hash)
          args = [args]
        end
        values = StrictPlaceholderParser.parse(str, args)
        @str = []
        @args = []
        values.each_with_index do |v, i|
          if i.even?
            @str << v
          else
            @args << v
          end
        end
        @str.freeze
        @args.freeze
        freeze
      end
    end
  end
end
