# frozen_string_literal: true
require 'ripper'

module Slim
  # Parses Slim code and transforms it to a Temple expression
  # @api private
  class Parser < Temple::Parser
    define_options :file,
                   :default_tag,
                   tabsize: 4,
                   code_attr_delims: {
                     '(' => ')',
                     '[' => ']',
                     '{' => '}',
                   },
                   attr_list_delims: {
                     '(' => ')',
                     '[' => ']',
                     '{' => '}',
                   },
                   shortcut: {
                     '#' => { attr: 'id' },
                     '.' => { attr: 'class' }
                   },
                   splat_prefix: '*'

    class SyntaxError < StandardError
      attr_reader :error, :file, :line, :lineno, :column

      def initialize(error, file, line, lineno, column)
        @error = error
        @file = file || '(__TEMPLATE__)'
        @line = line.to_s
        @lineno = lineno
        @column = column
      end

      def to_s
        line = @line.lstrip
        column = @column + line.size - @line.size
        %{#{error}
  #{file}, Line #{lineno}, Column #{@column}
    #{line}
    #{' ' * column}^
}
      end
    end

    def initialize(opts = {})
      super
      @attr_list_delims = options[:attr_list_delims]
      @code_attr_delims = options[:code_attr_delims]
      tabsize = options[:tabsize]
      if tabsize > 1
        @tab_re = /\G((?: {#{tabsize}})*) {0,#{tabsize - 1}}\t/
        @tab = '\1' + ' ' * tabsize
      else
        @tab_re = "\t"
        @tab = ' '
      end
      @tag_shortcut, @attr_shortcut, @additional_attrs = {}, {}, {}
      options[:shortcut].each do |k,v|
        raise ArgumentError, 'Shortcut requires :tag and/or :attr' unless (v[:attr] || v[:tag]) && (v.keys - [:attr, :tag, :additional_attrs]).empty?
        @tag_shortcut[k] = v[:tag] || options[:default_tag]
        if v.include?(:attr) || v.include?(:additional_attrs)
          raise ArgumentError, 'You can only use special characters for attribute shortcuts' if k =~ /(\p{Word}|-)/
        end
        if v.include?(:attr)
          @attr_shortcut[k] = v[:attr].is_a?(Proc) ? v[:attr] : [v[:attr]].flatten
        end
        if v.include?(:additional_attrs)
          @additional_attrs[k] = v[:additional_attrs]
        end
      end
      keys = Regexp.union @attr_shortcut.keys.sort_by { |k| -k.size }
      @attr_shortcut_re = /\A(#{keys}+)((?:\p{Word}|-|\/\d+|:(\w|-)+)*)/
      keys = Regexp.union @tag_shortcut.keys.sort_by { |k| -k.size }
      @tag_re = /\A(?:#{keys}|\*(?=[^\s]+)|(\p{Word}(?:\p{Word}|:|-)*\p{Word}|\p{Word}+))/
      keys = Regexp.escape @code_attr_delims.keys.join
      @code_attr_delims_re = /\A[#{keys}]/
      keys = Regexp.escape @attr_list_delims.keys.join
      @attr_list_delims_re = /\A\s*([#{keys}])/
      @embedded_re = /\A(#{Regexp.union(Embedded.engines.keys.map(&:to_s))})(?:\s*(?:(.*)))?:(\s*)/
      keys = Regexp.escape ('"\'></='.split(//) + @attr_list_delims.flatten + @code_attr_delims.flatten).uniq.join
      @attr_name = "\\A\\s*([^\\0\\s#{keys}]+)"
      @quoted_attr_re = /#{@attr_name}\s*=(=?)\s*("|')/
      @code_attr_re = /#{@attr_name}\s*=(=?)\s*/

      splat_prefix = Regexp.escape(options[:splat_prefix])
      splat_regexp_source = '\A\s*' + splat_prefix + '(?=[^\s]+)'
      @splat_attrs_regexp = Regexp.new(splat_regexp_source)
    end

    # Compile string to Temple expression
    #
    # @param [String] str Slim code
    # @return [Array] Temple expression representing the code
    def call(str)
      result = [:multi]
      reset(str.split(/\r?\n/), [result])

      parse_line while next_line

      reset
      result
    end

    protected

    def reset(lines = nil, stacks = nil)
      # Since you can indent however you like in Slim, we need to keep a list
      # of how deeply indented you are. For instance, in a template like this:
      #
      #   doctype       # 0 spaces
      #   html          # 0 spaces
      #    head         # 1 space
      #       title     # 4 spaces
      #
      # indents will then contain [0, 1, 4] (when it's processing the last line.)
      #
      # We uses this information to figure out how many steps we must "jump"
      # out when we see an de-indented line.
      @indents = []

      # Whenever we want to output something, we'll *always* output it to the
      # last stack in this array. So when there's a line that expects
      # indentation, we simply push a new stack onto this array. When it
      # processes the next line, the content will then be outputted into that
      # stack.
      @stacks = stacks

      @lineno = 0
      @lines = lines
      @line = @orig_line = nil
    end

    def next_line
      if @lines.empty?
        @orig_line = @line = nil
      else
        @orig_line = @lines.shift
        @lineno += 1
        @line = @orig_line.dup
      end
    end

    def get_indent(line)
      # Figure out the indentation. Kinda ugly/slow way to support tabs,
      # but remember that this is only done at parsing time.
      line[/\A[ \t]*/].gsub(@tab_re, @tab).size
    end

    def parse_line
      if @line =~ /\A\s*\Z/
        @stacks.last << [:newline]
        return
      end

      indent = get_indent(@line)

      # Choose first indentation yourself
      @indents << indent if @indents.empty?

      # Remove the indentation
      @line.lstrip!

      # If there's more stacks than indents, it means that the previous
      # line is expecting this line to be indented.
      expecting_indentation = @stacks.size > @indents.size

      if indent > @indents.last
        # This line was actually indented, so we'll have to check if it was
        # supposed to be indented or not.
        syntax_error!('Unexpected indentation') unless expecting_indentation

        @indents << indent
      else
        # This line was *not* indented more than the line before,
        # so we'll just forget about the stack that the previous line pushed.
        @stacks.pop if expecting_indentation

        # This line was deindented.
        # Now we're have to go through the all the indents and figure out
        # how many levels we've deindented.
        while indent < @indents.last && @indents.size > 1
          @indents.pop
          @stacks.pop
        end

        # This line's indentation happens to lie "between" two other line's
        # indentation:
        #
        #   hello
        #       world
        #     this      # <- This should not be possible!
        syntax_error!('Malformed indentation') if indent != @indents.last
      end

      parse_line_indicators
    end

    def parse_line_indicators
      case @line
      when /\A\/!( ?)/
        # HTML comment
        @stacks.last << [:html, :comment, [:slim, :text, :verbatim, parse_text_block($', @indents.last + $1.size + 2)]]
      when /\A\/\[\s*(.*?)\s*\]\s*\Z/
        # HTML conditional comment
        block = [:multi]
        @stacks.last << [:html, :condcomment, $1, block]
        @stacks << block
      when /\A\//
        # Slim comment
        parse_comment_block
      when /\A([\|'])([<>]{1,2}(?: |\z)| ?)/
        # Found verbatim text block.
        leading_ws = $2.include?('<'.freeze)
        trailing_ws = ($1 == "'") || $2.include?('>'.freeze)
        @stacks.last << [:static, ' '] if leading_ws
        @stacks.last << [:slim, :text, :verbatim, parse_text_block($', @indents.last + $2.count(' ') + 1)]
        @stacks.last << [:static, ' '] if trailing_ws
      when /\A</
        # Inline html
        block = [:multi]
        @stacks.last << [:multi, [:slim, :interpolate, @line], block]
        @stacks << block
      when /\A-/
        # Found a code block.
        # We expect the line to be broken or the next line to be indented.
        @line.slice!(0)
        block = [:multi]
        @stacks.last << [:slim, :control, parse_broken_line, block]
        @stacks << block
      when /\A=(=?)([<>]*)/
        # Found an output block.
        # We expect the line to be broken or the next line to be indented.
        @line = $'
        leading_ws = $2.include?('<'.freeze)
        trailing_ws = $2.include?('>'.freeze)
        block = [:multi]
        @stacks.last << [:static, ' '] if leading_ws
        @stacks.last << [:slim, :output, $1.empty?, parse_broken_line, block]
        @stacks.last << [:static, ' '] if trailing_ws
        @stacks << block
      when @embedded_re
        # Embedded template detected. It is treated as block.
        @line = $2
        attrs = parse_attributes
        @stacks.last << [:slim, :embedded, $1, parse_text_block($', @orig_line.size - $'.size + $2.size), attrs]
      when /\Adoctype\b/
        # Found doctype declaration
        @stacks.last << [:html, :doctype, $'.strip]
      when @tag_re
        # Found a HTML tag.
        @line = $' if $1
        parse_tag($&)
      else
        unknown_line_indicator
      end
      @stacks.last << [:newline]
    end

    # Unknown line indicator found. Overwrite this method if
    # you want to add line indicators to the Slim parser.
    # The default implementation throws a syntax error.
    def unknown_line_indicator
      syntax_error! 'Unknown line indicator'
    end

    def parse_comment_block
      while !@lines.empty? && (@lines.first =~ /\A\s*\Z/ || get_indent(@lines.first) > @indents.last)
        next_line
        @stacks.last << [:newline]
      end
    end

    def parse_text_block(first_line = nil, text_indent = nil)
      result = [:multi]
      if !first_line || first_line.empty?
        text_indent = nil
      else
        result << [:slim, :interpolate, first_line]
      end

      empty_lines = 0
      until @lines.empty?
        if @lines.first =~ /\A\s*\Z/
          next_line
          result << [:newline]
          empty_lines += 1 if text_indent
        else
          indent = get_indent(@lines.first)
          break if indent <= @indents.last

          if empty_lines > 0
            result << [:slim, :interpolate, "\n" * empty_lines]
            empty_lines = 0
          end

          next_line
          @line.lstrip!

          # The text block lines must be at least indented
          # as deep as the first line.
          offset = text_indent ? indent - text_indent : 0
          if offset < 0
            text_indent += offset
            offset = 0
          end
          result << [:newline] << [:slim, :interpolate, (text_indent ? "\n" : '') + (' ' * offset) + @line]

          # The indentation of first line of the text block
          # determines the text base indentation.
          text_indent ||= indent
        end
      end
      result
    end

    def parse_broken_line
      code = @line.strip
      start_lineno = @lineno
      start_column = @orig_line.size - @line.lstrip.size
      code_lines = [code]
      source_lines = [@orig_line]
      loop do
        offset, opener, heredoc = ruby_code_end_offset(code, nil, true)
        if opener
          unclosed_ruby_code!(opener, code_lines, source_lines, start_lineno, start_column) if @lines.empty?
          next_line
          code_lines << @line
          source_lines << @orig_line
          code = "#{code}\n#{@line}"
        else
          code = code.byteslice(0...offset) if offset
          # The code generator appends tokens after the expression, so a
          # heredoc terminator must be followed by a newline of its own
          code = "#{code}\n" if heredoc
          return code
        end
      end
    end

    def parse_tag(tag)
      if @tag_shortcut[tag]
        @line.slice!(0, tag.size) unless @attr_shortcut[tag]
        tag = @tag_shortcut[tag]
      end

      # Find any shortcut attributes
      attributes = [:html, :attrs]
      while @line =~ @attr_shortcut_re
        # The class/id attribute is :static instead of :slim :interpolate,
        # because we don't want text interpolation in .class or #id shortcut
        syntax_error!('Illegal shortcut') unless shortcut = @attr_shortcut[$1]

        if shortcut.is_a?(Proc)
          shortcut.call($2).each { |a, v| attributes << [:html, :attr, a, [:static, v]] }
        else
          shortcut.each {|a| attributes << [:html, :attr, a, [:static, $2]] }
        end

        if additional_attr_pairs = @additional_attrs[$1]
          additional_attr_pairs.each do |k,v|
            attributes << [:html, :attr, k.to_s, [:static, v]]
          end
        end
        @line = $'
      end

      @line =~ /\A[<>']*/
      @line = $'
      trailing_ws = $&.include?('>'.freeze)
      leading_ws = $&.include?('<'.freeze)

      parse_attributes(attributes)

      tag = [:html, :tag, tag, attributes]

      @stacks.last << [:static, ' '] if leading_ws
      @stacks.last << tag
      @stacks.last << [:static, ' '] if trailing_ws

      case @line
      when /\A\s*:\s*/
        # Block expansion
        @line = $'
        if @line =~ @embedded_re

          # Parse attributes
          @line = $2
          attrs = parse_attributes
          tag << [:slim, :embedded, $1, parse_text_block($', @orig_line.size - $'.size + $2.size), attrs]
        else
          (@line =~ @tag_re) || syntax_error!('Expected tag')
          @line = $' if $1
          content = [:multi]
          tag << content
          i = @stacks.size
          @stacks << content
          parse_tag($&)
          @stacks.delete_at(i)
        end
      when /\A\s*=(=?)(['<>]*)/
        # Handle output code
        @line = $'
        trailing_ws2 = $2.include?('>'.freeze)
        block = [:multi]
        @stacks.last.insert(-2, [:static, ' ']) if !leading_ws && $2.include?('<'.freeze)
        tag << [:slim, :output, $1 != '=', parse_broken_line, block]
        @stacks.last << [:static, ' '] if !trailing_ws && trailing_ws2
        @stacks << block
      when /\A\s*\/\s*/
        # Closed tag. Do nothing
        @line = $'
        syntax_error!('Unexpected text after closed tag') unless @line.empty?
      when /\A\s*\Z/
        # Empty content
        content = [:multi]
        tag << content
        @stacks << content
      when /\A ?/
        # Text content
        tag << [:slim, :text, :inline, parse_text_block($', @orig_line.size - $'.size)]
      end
    end

    def parse_attributes(attributes = [:html, :attrs])
      # Check to see if there is a delimiter right after the tag name
      delimiter = nil
      if @line =~ @attr_list_delims_re
        delimiter = @attr_list_delims[$1]
        @line = $'
      end

      if delimiter
        boolean_attr_re = /#{@attr_name}(?=(\s|#{Regexp.escape delimiter}|\Z))/
        end_re = /\A\s*#{Regexp.escape delimiter}/
      end

      while true
        case @line
        when @splat_attrs_regexp
          # Splat attribute
          @line = $'
          attributes << [:slim, :splat, parse_ruby_code(delimiter)]
        when @quoted_attr_re
          # Value is quoted (static)
          @line = $'
          attributes << [:html, :attr, $1,
                         [:escape, $2.empty?, [:slim, :interpolate, parse_quoted_attribute($3)]]]
        when @code_attr_re
          # Value is ruby code
          @line = $'
          name = $1
          escape = $2.empty?
          value = parse_ruby_code(delimiter)
          syntax_error!('Invalid empty attribute') if value.empty?
          attributes << [:html, :attr, name, [:slim, :attrvalue, escape, value]]
        else
          break unless delimiter

          case @line
          when boolean_attr_re
            # Boolean attribute
            @line = $'
            attributes << [:html, :attr, $1, [:multi]]
          when end_re
            # Find ending delimiter
            @line = $'
            break
          else
            # Found something where an attribute should be
            @line.lstrip!
            syntax_error!('Expected attribute') unless @line.empty?

            # Attributes span multiple lines
            @stacks.last << [:newline]
            syntax_error!("Expected closing delimiter #{delimiter}") if @lines.empty?
            next_line
          end
        end
      end
      attributes || [:html, :attrs]
    end

    def parse_ruby_code(outer_delimiter)
      start_lineno = @lineno
      start_column = @orig_line.size - @line.size
      code_lines = [code = @line]
      source_lines = [@orig_line]
      loop do
        offset, opener, heredoc = ruby_code_end_offset(code, outer_delimiter)
        if opener
          unclosed_ruby_code!(opener, code_lines, source_lines, start_lineno, start_column) if @lines.empty?
          next_line
          code_lines << @line
          source_lines << @orig_line
          code = "#{code}\n#{@line}"
        else
          if offset
            @line = code.byteslice(offset..-1) || ''.dup
            code = code.byteslice(0...offset)
          else
            @line = ''.dup
          end
          # The code generator appends tokens after the expression, so a
          # heredoc terminator must be followed by a newline of its own
          code = "#{code}\n" if heredoc
          return code
        end
      end
    end

    # Finds the end of the Ruby expression at the beginning of +code+.
    # Ruby's own lexer (Ripper) is used so that delimiters inside strings,
    # regular expressions, comments and heredocs are not mistaken for
    # expression boundaries.
    #
    # Returns [offset, nil, heredoc] if the expression ends at the byte
    # offset (the terminating whitespace or +outer_delimiter+ is not
    # included), [nil, nil, heredoc] if the whole of +code+ is the
    # expression, or [nil, opener, heredoc] if the expression is
    # incomplete and more input is required. +opener+ describes the
    # unclosed structure and is :continuation if the line simply ends
    # with ',' or '\'. +heredoc+ is true if the code contains a heredoc.
    def ruby_code_end_offset(code, outer_delimiter, eol_only = false)
      stack = []
      heredocs = []
      heredoc = false
      line_offsets = nil
      prev_token = nil
      tokens = Ripper.lex(code)
      tokens.each do |(lineno, column), type, token, _state|
        if stack.empty? && heredocs.empty?
          # A space only terminates the expression if it does not belong to
          # the indentation of a continued line
          if type == :on_nl ||
             (!eol_only && type == :on_sp && !token.include?("\n") && !(prev_token && prev_token.include?("\n"))) ||
             (!eol_only && outer_delimiter && token == outer_delimiter)
            line_offsets ||= ruby_line_offsets(code)
            return [line_offsets[lineno - 1] + column, nil]
          end
        end

        case type
        when :on_lparen
          stack << [type, token, lineno, column, ')']
        when :on_lbracket
          stack << [type, token, lineno, column, ']']
        when :on_lbrace, :on_tlambeg, :on_embexpr_beg
          stack << [type, token, lineno, column, '}']
        when :on_symbeg
          # Only quoted symbols (:"...") are closed by a string end token
          stack << [type, token, lineno, column, nil] if token.size > 1
        when :on_tstring_beg, :on_regexp_beg, :on_words_beg, :on_qwords_beg,
             :on_symbols_beg, :on_qsymbols_beg, :on_backtick, :on_embdoc_beg
          stack << [type, token, lineno, column, nil]
        when :on_heredoc_beg
          # Heredoc bodies start after the current line, so they are
          # tracked separately from the nested structures on the line itself
          heredoc = true
          heredocs << [type, token, lineno, column, nil]
        when :on_heredoc_end
          heredocs.pop
        when :on_rparen, :on_rbracket, :on_rbrace, :on_tstring_end, :on_regexp_end,
             :on_embexpr_end, :on_embdoc_end
          stack.pop
        end
        prev_token = token
      end

      opener = heredocs.first || stack.last
      return [nil, opener, heredoc] if opener
      return [nil, :continuation, heredoc] if code =~ /[,\\]\s*\Z/
      [nil, nil, heredoc]
    end

    # Byte offsets of the beginning of each line in +code+
    def ruby_line_offsets(code)
      offsets = [0]
      code.bytes.each_with_index do |byte, index|
        offsets << index + 1 if byte == 0x0A
      end
      offsets
    end

    # Raises a syntax error for an unclosed Ruby structure, pointing at
    # the beginning of the structure rather than at a later line
    def unclosed_ruby_code!(opener, code_lines, source_lines, start_lineno, start_column)
      syntax_error!('Unexpected end of file') if opener == :continuation
      type, token, lineno, column, closer = opener
      message =
        case type
        when :on_lparen, :on_lbracket, :on_lbrace, :on_tlambeg, :on_embexpr_beg
          "Expected closing delimiter #{closer}"
        when :on_regexp_beg
          'Unterminated regexp literal'
        when :on_heredoc_beg
          "Unterminated heredoc #{token}"
        when :on_embdoc_beg
          'Unterminated embedded document'
        else
          'Unterminated string literal'
        end
      column = code_lines[lineno - 1].byteslice(0...column).to_s.size
      column += start_column if lineno == 1
      syntax_error_at!(message, source_lines[lineno - 1], start_lineno + lineno - 1, column)
    end

    def parse_quoted_attribute(quote)
      value, count = ''.dup, 0

      until count == 0 && @line[0] == quote[0]
        if @line =~ /\A(\\)?\Z/
          value << ($1 ? ' ' : "\n")
          expect_next_line
        else
          if @line[0] == '{'
            count += 1
          elsif @line[0] == '}'
            count -= 1
          end
          value << @line.slice!(0)
        end
      end

      @line.slice!(0)
      value
    end

    # Helper for raising exceptions
    def syntax_error!(message)
      syntax_error_at!(message, @orig_line, @lineno,
                       @orig_line && @line ? @orig_line.size - @line.size : 0)
    end

    # Helper for raising exceptions at an explicit location
    def syntax_error_at!(message, line, lineno, column)
      raise SyntaxError.new(message, options[:file], line, lineno, column)
    rescue SyntaxError => ex
      # HACK: Manipulate stacktrace for Rails and other frameworks
      # to find the right file.
      ex.backtrace.unshift "#{options[:file]}:#{lineno}"
      raise
    end

    def expect_next_line
      next_line || syntax_error!('Unexpected end of file')
      @line.strip!
    end
  end
end
