# frozen_string_literal: true

module Liquid
  # Holds variables. Variables are only loaded "just in time"
  # and are not evaluated as part of the render stage
  #
  #   {{ monkey }}
  #   {{ user.name }}
  #
  # Variables can be combined with filters:
  #
  #   {{ user | link }}
  #
  class Variable
    FilterMarkupRegex        = /#{FilterSeparator}\s*(.*)/om
    FilterParser             = /(?:\s+|#{QuotedFragment}|#{ArgumentSeparator})+/o
    FilterArgsRegex          = /(?:#{FilterArgumentSeparator}|#{ArgumentSeparator})\s*((?:\w+\s*\:\s*)?#{QuotedFragment})/o
    JustTagAttributes        = /\A#{TagAttributes}\z/o
    MarkupWithQuotedFragment = /(#{QuotedFragment})(.*)/om

    attr_accessor :filters, :name, :line_number
    attr_reader :parse_context
    alias_method :options, :parse_context

    include ParserSwitching

    def initialize(markup, parse_context)
      @markup        = markup
      @name          = nil
      @parse_context = parse_context
      @line_number   = parse_context.line_number

      strict_parse_with_error_mode_fallback(markup)
    end

    def raw
      @markup
    end

    def ==(other)
      self.class == other.class && name == other.name && filters == other.filters
    end

    def markup_context(markup)
      "in \"{{#{markup}}}\""
    end

    def lax_parse(markup)
      @filters = []
      return unless markup =~ MarkupWithQuotedFragment

      name_markup   = Regexp.last_match(1)
      filter_markup = Regexp.last_match(2)
      @name         = parse_context.parse_expression(name_markup)
      if filter_markup =~ FilterMarkupRegex
        filters = Regexp.last_match(1).scan(FilterParser)
        filters.each do |f|
          next unless f =~ /\w+/
          filtername = Regexp.last_match(0)
          filterargs = f.scan(FilterArgsRegex).flatten
          @filters << lax_parse_filter_expressions(filtername, filterargs)
        end
      end
    end

    def strict_parse(markup)
      @filters = []
      p = @parse_context.new_parser(markup)

      return if p.look(:end_of_string)

      @name = parse_context.safe_parse_expression(p)
      while p.consume?(:pipe)
        filtername = p.consume(:id)
        filterargs = p.consume?(:colon) ? parse_filterargs(p) : Const::EMPTY_ARRAY
        @filters << lax_parse_filter_expressions(filtername, filterargs)
      end
      p.consume(:end_of_string)
    end

    def strict2_parse(markup)
      @filters = []
      p = @parse_context.new_parser(markup)

      return if p.look(:end_of_string)

      @name = parse_context.safe_parse_expression(p)
      @filters << strict2_parse_filter_expressions(p) while p.consume?(:pipe)
      p.consume(:end_of_string)
    end

    def parse_filterargs(p)
      # first argument
      filterargs = [p.argument]
      # followed by comma separated others
      filterargs << p.argument while p.consume?(:comma)
      filterargs
    end

    def render(context)
      obj = context.evaluate(@name)

      @filters.each do |filter_name, filter_args, filter_kwargs|
        filter_args = evaluate_filter_expressions(context, filter_args, filter_kwargs)
        obj = apply_filter(context, filter_name, obj, filter_args)
      end

      obj = context.apply_global_filter(obj)
      normalize_result(obj, Safety.guarantees(obj))
    end

    def render_to_output_buffer(context, output)
      obj = render(context)
      render_obj_to_output(obj, output, context.output_mode)
      output
    end

    def render_obj_to_output(obj, output, mode = Safety::CLASSIC)
      case obj
      when NilClass
        # Do nothing
      when Array
        obj.each do |o|
          render_obj_to_output(o, output, mode)
        end
      else
        output << render_scalar(obj, mode)
      end
    end

    private

    # Runs one filter and recomputes the guarantees attached to the result
    # from the filter's declared spec. Filters without a declared spec strip
    # every guarantee from string results.
    def apply_filter(context, filter_name, obj, filter_args)
      input_guarantees = Safety.guarantees(obj)
      raw_result       = context.invoke(filter_name, obj, *filter_args)
      spec             = context.filter_safety_spec(filter_name)

      if spec
        argument_guarantees = filter_args.flat_map { |arg| argument_guarantees_for(arg) }
        guarantees = Safety.apply_spec(spec, input_guarantees, argument_guarantees)
      else
        guarantees = nil
      end

      normalize_result(raw_result, guarantees)
    end

    # String arguments participate in guarantee preservation: an unmarked
    # string argument blocks preservation. Non-string arguments (numbers,
    # booleans, nil) cannot inject markup and impose no restriction.
    # Returns one entry per string-bearing argument: its guarantee set, or
    # nil when it is an unmarked string (which then blocks preservation).
    def argument_guarantees_for(arg)
      case arg
      when Safety::SafeValue
        [arg.guarantees]
      when String
        [nil]
      when Array
        arg.flat_map { |item| argument_guarantees_for(item) }
      when Hash
        arg.values.flat_map { |item| argument_guarantees_for(item) }
      else
        []
      end
    end

    def normalize_result(result, guarantees)
      case result
      when String then Safety.mark(Safety.strip(result), guarantees)
      else result
      end
    end

    # Converts a single output value to text for the active output mode,
    # escaping untrusted content unless the value carries the matching
    # guarantee for the current context.
    def render_scalar(obj, mode)
      str       = Liquid::Utils.to_s(obj)
      guarantee = Safety.guarantee_for_mode(mode)

      if guarantee && !Safety.safe_for?(obj, guarantee)
        Safety.escape_for_mode(str, mode)
      else
        str
      end
    end

    def disabled?(_context)
      false
    end

    def disabled_tags
      []
    end

    def lax_parse_filter_expressions(filter_name, unparsed_args)
      filter_args  = []
      keyword_args = nil
      unparsed_args.each do |a|
        if (matches = a.match(JustTagAttributes))
          keyword_args           ||= {}
          keyword_args[matches[1]] = parse_context.parse_expression(matches[2])
        else
          filter_args << parse_context.parse_expression(a)
        end
      end
      result = [filter_name, filter_args]
      result << keyword_args if keyword_args
      result
    end

    # Surprisingly, positional and keyword arguments can be mixed.
    #
    # filter = filtername [":" filterargs?]
    # filterargs = argument ("," argument)*
    # argument = (positional_argument | keyword_argument)
    # positional_argument = expression
    # keyword_argument = id ":" expression
    def strict2_parse_filter_expressions(p)
      filtername = p.consume(:id)
      filter_args = []
      keyword_args = {}

      if p.consume?(:colon)
        # Parse first argument (no leading comma)
        argument(p, filter_args, keyword_args) unless end_of_arguments?(p)

        # Parse remaining arguments (with leading commas) and optional trailing comma
        argument(p, filter_args, keyword_args) while p.consume?(:comma) && !end_of_arguments?(p)
      end

      result = [filtername, filter_args]
      result << keyword_args unless keyword_args.empty?
      result
    end

    def argument(p, positional_arguments, keyword_arguments)
      if p.look(:id) && p.look(:colon, 1)
        key = p.consume(:id)
        p.consume(:colon)
        value = parse_context.safe_parse_expression(p)
        keyword_arguments[key] = value
      else
        positional_arguments << parse_context.safe_parse_expression(p)
      end
    end

    def end_of_arguments?(p)
      p.look(:pipe) || p.look(:end_of_string)
    end

    def evaluate_filter_expressions(context, filter_args, filter_kwargs)
      parsed_args = filter_args.map { |expr| context.evaluate(expr) }
      if filter_kwargs
        parsed_kwargs = {}
        filter_kwargs.each do |key, expr|
          parsed_kwargs[key] = context.evaluate(expr)
        end
        parsed_args << parsed_kwargs
      end
      parsed_args
    end

    class ParseTreeVisitor < Liquid::ParseTreeVisitor
      def children
        [@node.name] + @node.filters.flatten
      end
    end
  end
end
