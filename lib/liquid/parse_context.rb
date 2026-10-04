# frozen_string_literal: true

module Liquid
  class ParseContext
    attr_accessor :locale, :line_number, :trim_whitespace, :depth
    attr_reader :partial, :warnings, :error_mode, :environment

    def initialize(options = Const::EMPTY_HASH)
      @environment = options.fetch(:environment, Environment.default)
      @template_options = options ? options.dup : {}

      @locale   = @template_options[:locale] ||= I18n.new
      @warnings = []

      # constructing new StringScanner in Lexer, Tokenizer, etc is expensive
      # This StringScanner will be shared by all of them
      @string_scanner = StringScanner.new("")

      @expression_cache = if options[:expression_cache].nil?
        {}
      elsif options[:expression_cache].respond_to?(:[]) && options[:expression_cache].respond_to?(:[]=)
        options[:expression_cache]
      elsif options[:expression_cache]
        {}
      end

      self.depth   = 0
      self.partial = false
    end

    def [](option_key)
      @options[option_key]
    end

    def new_block_body
      Liquid::BlockBody.new
    end

    def new_parser(input)
      @string_scanner.string = input
      Parser.new(@string_scanner, reject_bare_brackets: @error_mode == :strict2 || @error_mode == :rigid)
    end

    def new_tokenizer(source, start_line_number: nil, for_liquid_tag: false)
      Tokenizer.new(
        source: source,
        string_scanner: @string_scanner,
        line_number: start_line_number,
        for_liquid_tag: for_liquid_tag,
      )
    end

    def safe_parse_expression(parser)
      Expression.safe_parse(parser, @string_scanner, @expression_cache)
    end

    def parse_expression(markup, safe: false)
      if !safe && @error_mode == :strict2
        # parse_expression is a widely used API. To maintain backward
        # compatibility while raising awareness about strict2 parser standards,
        # the safe flag supports API users make a deliberate decision.
        #
        # In strict2 mode, markup MUST come from a string returned by the parser
        # (e.g., parser.expression). We're not calling the parser here to
        # prevent redundant parser overhead.
        raise Liquid::InternalError, "unsafe parse_expression cannot be used in strict2 mode"
      end

      Expression.parse(markup, @string_scanner, @expression_cache)
    end

    def partial=(value)
      @partial = value
      @options = value ? partial_options : @template_options

      @error_mode = @options[:error_mode] || @environment.error_mode

      # Loop labels must not leak across a render/include boundary: a
      # partial is parsed as its own template, so break/continue inside
      # it cannot control loops of the outer template.
      if value
        @outer_loop_label_stack = @loop_label_stack
        @loop_label_stack = []
      else
        @loop_label_stack = @outer_loop_label_stack
        @outer_loop_label_stack = nil
      end
    end

    # Loop labels declared by enclosing `for` tags, innermost last.
    # Used at parse time to validate break/continue label references
    # and to reject duplicate declarations in nested loops.
    def push_loop_label(label)
      @loop_label_stack ||= []
      if label && @loop_label_stack.include?(label)
        raise SyntaxError, locale.t("errors.syntax.loop_label_duplicate", label: label)
      end
      @loop_label_stack.push(label)
    end

    def pop_loop_label
      @loop_label_stack&.pop
    end

    def loop_label_visible?(label)
      !!@loop_label_stack&.include?(label)
    end

    # Parses the optional loop label of a break/continue tag and validates
    # that it refers to a loop label visible at this point in the template.
    def parse_loop_label(markup, tag_name)
      label = markup.strip
      return nil if label.empty?

      unless label.match?(/\A#{VariableSegment}+\z/o)
        raise SyntaxError, locale.t("errors.syntax.loop_label_invalid", tag: tag_name, label: label)
      end
      unless loop_label_visible?(label)
        raise SyntaxError, locale.t("errors.syntax.loop_label_unknown", tag: tag_name, label: label)
      end
      label
    end

    def partial_options
      @partial_options ||= begin
        dont_pass = @template_options[:include_options_blacklist]
        if dont_pass == true
          { locale: locale }
        elsif dont_pass.is_a?(Array)
          @template_options.reject { |k, _v| dont_pass.include?(k) }
        else
          @template_options
        end
      end
    end
  end
end
