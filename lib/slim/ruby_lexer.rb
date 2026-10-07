# frozen_string_literal: true
require 'ripper'

module Slim
  # Lexical helper for Ruby code embedded in Slim attributes and output
  # expressions.
  #
  # Ripper (shipped with Ruby itself; no external parsing service) is used
  # to recognize strings, regular expressions, comments, percent literals
  # and heredocs, so that delimiters occurring inside those structures are
  # not mistaken for expression boundaries.
  #
  # @api private
  module RubyLexer
    # Events opening a delimited structure and the event which closes it.
    PAIRS = {
      on_lparen: :on_rparen,
      on_lbracket: :on_rbracket,
      on_lbrace: :on_rbrace,
      on_tlambeg: :on_rbrace,
      on_embexpr_beg: :on_embexpr_end,
    }.freeze

    CLOSE_CHARS = {
      on_rparen: ')',
      on_rbracket: ']',
      on_rbrace: '}',
      on_embexpr_end: '}',
    }.freeze

    # Events beginning a string-like literal which must be terminated.
    LITERAL_BEG = {
      on_tstring_beg: 'string literal',
      on_regexp_beg: 'regular expression',
      on_backtick: 'backtick string',
      on_qwords_beg: 'word list',
      on_words_beg: 'word list',
      on_qsymbols_beg: 'symbol list',
      on_symbols_beg: 'symbol list',
      on_embdoc_beg: 'embedded document comment',
    }.freeze


    LITERAL_END = %i[on_tstring_end on_regexp_end on_embdoc_end].freeze

    # Binary operators which cannot legally terminate an expression.
    # `|` is intentionally excluded: it is also the block parameter
    # delimiter (`do |x|`) and cannot be distinguished without context.
    BINARY_OPS = %w[
      + - * / % ** = == === != =~ !~ < > <= >= <=> << >> & ^
      && || += -= *= /= %= **= &= |= ^= <<= >>= &&= ||= &.
    ].freeze

    # Scanner for quoted Slim attribute values. The raw content following
    # the opening quote is scanned directly: outside of an interpolation
    # segment every character is static text, while the code inside
    # `#{...}` is lexed with Ripper so that quotes, regular expressions,
    # comments and nested delimiters keep their Ruby meaning. Backslashes
    # are preserved verbatim because Slim applies its own interpolation
    # handling in a later compilation stage.
    class QuotedString
      def initialize(first_line, first_lineno = 1, opening_column = 0, quote = '"')
        @quote = quote
        @first_lineno = first_lineno
        @lines = [first_line]
        @indents = [opening_column]
        scan!
      end

      def add_line(line, indent = 0)
        @lines << line
        @indents << indent
        scan!
      end

      def line_count
        @lines.size
      end

      # Column of the closing quote on the given physical line.
      #
      # @param line_index [Integer] zero based accumulated line number
      # @return [Integer, nil]
      def closing_column(line_index)
        @closing_columns[line_index]
      end

      # First still open structure as `[lineno, column, description]`.
      #
      # @return [Array(Integer, Integer, String), nil]
      def first_open
        @open.first
      end

      private

      def scan!
        @closing_columns = Array.new(@lines.size)
        @open = []
          embexpr_stack = []
        embexpr_code = nil
        brace_depth = 0

        each_position do |line_index, col, ch|
          next_skip = nil
          if embexpr_stack.empty?
            if ch == '\\'
              next_skip = :skip
            elsif ch == '{'
              brace_depth += 1
            elsif ch == '}' && brace_depth > 0
              brace_depth -= 1
            elsif ch == @quote && brace_depth.zero?
              @closing_columns[line_index] = col
              throw :found
            elsif ch == '#' && char_at(line_index, col + 1) == '{'
              embexpr_stack << [@first_lineno + line_index, col + (@indents[line_index] || 0)]
              embexpr_code = +'{'
              next_skip = :skip
            end
          else
            embexpr_code << ch
            if ch == '}' && embexpr_balanced?(embexpr_code)
              embexpr_stack.pop
              embexpr_code = nil if embexpr_stack.empty?
            end
          end
          next_skip
        end

        embexpr_stack.each do |lineno, column|
          @open << [lineno, column, 'interpolation #{ ... }']
        end
      end

      # Checks whether the accumulated interpolation segment is balanced,
      # using Ripper to ignore braces appearing in strings, regexps,
      # comments and nested interpolation.
      def embexpr_balanced?(code)
        depth = 0
        Ripper.lex(code).each do |_pos, event, _token, _state|
          depth += 1 if event == :on_lbrace || event == :on_embexpr_beg
          depth -= 1 if event == :on_rbrace || event == :on_embexpr_end
        end
        depth.zero?
      end

      def each_position
        catch(:found) do
          @lines.each_with_index do |line, line_index|
            col = 0
            while col < line.size
              ch = line[col]
              skip = yield(line_index, col, ch)
              col += skip == :skip ? 2 : 1
            end
          end
        end
      end

      def char_at(line_index, col)
        @lines[line_index][col]
      end
    end

    # Accumulates a Ruby expression spanning one or several physical lines.
    #
    # The accumulated source is re-lexed with Ripper whenever a physical
    # line is appended. Heredoc bodies belong to the physical lines after
    # their introducer, so re-lexing the complete prefix naturally consumes
    # exactly the heredoc content visible up to the current line.
    class Expression
      attr_reader :code

      # @param first_line [String] content of the first physical line
      # @param first_lineno [Integer] template line number of the first line
      # @param first_indent [Integer] leading whitespace stripped from the first line
      def initialize(first_line, first_lineno = 1, first_indent = 0, strip_backslash: false)
        @first_lineno = first_lineno
        @indents = [first_indent]
        @line_count = 1
        @raw_lines = [first_line]
        @strip_backslash = strip_backslash
        @structures = []
        @tokens = []
        rebuild_code!
        rescan!
      end

      # Append another physical line and update the lexical state.
      #
      # @param line [String] stripped content of the physical line
      # @param indent [Integer] leading whitespace stripped from the physical line
      # @return [void]
      def add_line(line, indent = 0)
        @indents << indent
        @raw_lines << line
        @line_count += 1
        rebuild_code!
        rescan!
      end

      # Explicit backslash continuation characters are removed from the
      # accumulated code before Ripper sees it: they are a Slim line
      # joining device, not Ruby syntax.
      def rebuild_code!
        # Backslash line continuations are valid Ruby and are kept; Ripper
        # lexes `\\\n` as whitespace inside the expression.
        @code = @raw_lines.each_with_index.map do |physical, index|
          if @strip_backslash && index < @raw_lines.size - 1 && physical.rstrip.end_with?('\\')
            physical.rstrip[0...-1] + ' '
          else
            physical
          end
        end.join("\n")
      end

      # @return [Integer] number of accumulated physical lines
      attr_reader :line_count

      # Whether the accumulated code ends with a heredoc terminator; code
      # appended after it must start on a new line to stay valid Ruby.
      #
      # @return [Boolean]
      def ends_with_heredoc?
        @tokens.any? do |(line, _col), event, _token, _state|
          event == :on_heredoc_end && line == line_count
        end
      end

      # Whether the last physical line ends with a line comment; code
      # appended after it (such as a wrapping closing parenthesis) has to
      # start on a new line to remain valid Ruby.
      #
      # @return [Boolean]
      def ends_with_comment?
        @tokens.any? do |(line, _col), event, token, _state|
          line == line_count && event == :on_comment && token.end_with?("\n") == false
        end
      end

      # The accumulated code is a complete expression which can end here.
      #
      # Explicit comma/backslash continuation is handled by the parser to
      # preserve the existing single line syntax; this only covers lexical
      # completeness.
      #
      # @return [Boolean]
      def complete?
        @structures.empty? && !dangling?
      end

      # Whether the value continues on the following physical line, either
      # because it is lexically incomplete or through an explicit comma or
      # backslash continuation.
      #
      # @return [Boolean]
      def continues?
        !complete? || explicit_continuation?
      end

      # Trailing comma or backslash forces continuation (Slim single line
      # syntax kept for backwards compatibility).
      def explicit_continuation?
        last = @code.lines.last.to_s.rstrip
        last.end_with?(',') || last.end_with?('\\')
      end

      # The expression ends with an operator that needs another operand.
      #
      # @return [Boolean]
      def dangling?
        event, token = last_significant
        event == :on_period ||
          (event == :on_op && BINARY_OPS.include?(token)) ||
          (event == :on_comma)
      end

      # First still open structure as `[lineno, column, description]`.
      #
      # Positions refer to template line numbers; the column is a character
      # offset on the (already stripped) accumulated physical line.
      #
      # @return [Array(Integer, Integer, String), nil]
      def first_open
        # Report the innermost still open structure: an unterminated string
        # or regular expression inside parentheses is the actual problem,
        # not the surrounding parentheses.
        entry = @structures.last
        entry && [entry[:lineno], entry[:column], entry[:description]]
      end

      # Whether the given physical line contributes to an open structure at
      # its beginning, i.e. whether the expression may legally continue even
      # if the line starts with indentation whitespace.
      #
      # @param line_index [Integer] zero based physical line number
      # @return [Boolean]
      def line_continues?(line_index)
        depth_before(line_index) > 0 || heredoc_body?(line_index)
      end

      # Whether the given physical line is the body (or terminator) of a
      # heredoc which is still pending, i.e. its leading indentation is
      # significant Ruby content and must not be stripped.
      #
      # @param line_index [Integer] zero based line number of the next line
      # @return [Boolean]
      def heredoc_pending_on_line?(line_index)
        target = line_index
        pending = false
        @tokens.each do |(t_line, _col), event, _token, _state|
          break if t_line > target
          pending = true if event == :on_heredoc_beg && t_line <= target
          pending = false if event == :on_heredoc_end
        end
        pending
      end

      # Structure depth active at the beginning of a physical line.
      #
      # @param line_index [Integer] zero based physical line number
      # @return [Integer]
      def depth_before(line_index)
        depth = 0
        @tokens.each do |(t_line, _col), event, _token, _state|
          break if t_line > line_index
          if PAIRS.key?(event) || LITERAL_BEG.key?(event)
            depth += 1
          elsif CLOSE_CHARS.key?(event) || LITERAL_END.include?(event)
            depth -= 1 if depth > 0
          end
        end
        depth
      end

      # Heredoc bodies are supplied through the following physical lines and
      # may therefore begin with indentation even at depth zero.
      def heredoc_body?(line_index)
        target = line_index + 1
        @tokens.any? { |(t_line, _c), event, _t, _s| t_line == target && event == :on_tstring_content }
      end

      # Find the end of the expression on the given accumulated physical
      # line, i.e. the column of the first stop character at structure depth
      # zero (outside of strings, regexps, comments and heredocs).
      #
      # @param line_index [Integer] zero based accumulated line number
      # @param stop_chars [Array<String>] characters that terminate the value
      # @return [Integer, nil] column on the line where the value ends
      # @param allow_leading_space [Boolean] leading indentation is part of
      #   the value (explicit continuation), do not stop on it
      def end_column_on_line(line_index, stop_chars, allow_leading_space: false)
        depth = depth_before(line_index)
        target = line_index + 1
        seen_nonspace = false
        # On the introducer line tokens following `<<~TAG` (such as the
        # outer delimiter) are still normal code; only the subsequent body
        # lines are consumed wholesale.
        heredoc_pending = line_index > 0 && heredoc_pending_at_start?(line_index)
        open_heredocs_on_line = 0
        @tokens.each do |(t_line, t_col), event, token, _state|
          next if t_line < target
          break if t_line > target

          whitespace = event == :on_sp || event == :on_nl || event == :on_ignored_nl ||
                       event == :on_ignored_sp || event == :on_comment || token =~ /\A\s+\Z/
          at_leading_indent = t_col.zero? && !seen_nonspace
          next if whitespace && at_leading_indent && allow_leading_space
          if depth == 0 && !heredoc_pending && open_heredocs_on_line.zero?
            if whitespace && (seen_nonspace || line_index.zero? ||
               (at_leading_indent && !allow_leading_space && !line_continues?(line_index)))
              return t_col
            elsif !whitespace && stop_chars.include?(token)
              return t_col
            end
          end

          if PAIRS.key?(event) || LITERAL_BEG.key?(event)
            depth += 1
          elsif CLOSE_CHARS.key?(event) || LITERAL_END.include?(event)
            depth -= 1 if depth > 0
          end
          open_heredocs_on_line += 1 if event == :on_heredoc_beg
          open_heredocs_on_line -= 1 if event == :on_heredoc_end
          seen_nonspace = true unless whitespace
        end
        nil
      end

      # Whether a heredoc is still waiting for its body at the beginning of
      # the given physical line (an introducer on an earlier line whose
      # terminator has not been seen yet).
      def heredoc_pending_at_start?(line_index)
        pending = false
        @tokens.each do |(t_line, _col), event, _token, _state|
          break if t_line > line_index
          pending = true if event == :on_heredoc_beg && t_line < line_index + 1
          pending = false if event == :on_heredoc_end && t_line <= line_index
        end
        pending
      end

      private

      def last_significant
        token = @tokens.reverse_each.find do |_pos, event, text|
          !%i[on_sp on_nl on_ignored_nl on_ignored_sp on_comment].include?(event) &&
            text !~ /\A\s+\Z/
        end
        token && [token[1], token[2]]
      end

      def rescan!
        @tokens = Ripper.lex(@code)
        @structures = []

        @tokens.each do |(line, col), event, token, _state|
          register(line, col, event, token)
        end
      end

      def register(line, col, event, token)
        lineno = @first_lineno + line - 1
        column = col + (@indents[line - 1] || 0)
        if (close_event = PAIRS[event])
          @structures << { lineno: lineno, column: column, close: close_event,
                           description: "delimiter #{CLOSE_CHARS.fetch(close_event, '}')}", kind: :pair }
        elsif CLOSE_CHARS.key?(event)
          close_structure { |s| s[:kind] == :pair && s[:close] == event }
        elsif event == :on_symbeg && token == ':'
          # Bare symbol syntax (`:name`) has no separate end token; the
          # symbol is completed by the following identifier and does not
          # open a structure which needs balancing.
        elsif (description = LITERAL_BEG[event])
          @structures << { lineno: lineno, column: column,
                           description: description, kind: :literal }
        elsif LITERAL_END.include?(event)
          close_structure { |s| s[:kind] == :literal }
        elsif event == :on_heredoc_beg
          @structures << { lineno: lineno, column: column,
                           description: "heredoc #{heredoc_tag(token)}", kind: :heredoc }
        elsif event == :on_heredoc_end
          close_structure { |s| s[:kind] == :heredoc }
        end
      end

      def close_structure
        index = @structures.rindex { |entry| yield(entry) }
        @structures.delete_at(index) if index
      end

      def heredoc_tag(token)
        name = token.sub(/\A\s*<<[-~]?/, '')
        name = name[1..-2] if name.length > 1 && name.start_with?('"', "'", '`')
        name
      end
    end
  end
end
