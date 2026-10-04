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
      try_constant_fold
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
      obj = if fold_valid_for?(context)
        @folded_value
      else
        value = context.evaluate(@name)

        @filters.each do |filter_name, filter_args, filter_kwargs|
          filter_args = evaluate_filter_expressions(context, filter_args, filter_kwargs)
          value = context.invoke(filter_name, value, *filter_args)
        end

        value
      end

      context.apply_global_filter(obj)
    end

    def render_to_output_buffer(context, output)
      obj = render(context)
      render_obj_to_output(obj, output)
      output
    end

    def render_obj_to_output(obj, output)
      case obj
      when NilClass
        # Do nothing
      when Array
        obj.each do |o|
          render_obj_to_output(o, output)
        end
      else
        output << Liquid::Utils.to_s(obj)
      end
    end

    def disabled?(_context)
      false
    end

    def disabled_tags
      []
    end

    private

    # Compile-time constant folding for filter chains made entirely of
    # literals. A fold only happens when the input and every filter argument
    # are literals and every filter was explicitly registered as pure (no
    # context dependency, no side effects). Undeclared filters and dynamic
    # arguments are always left for runtime evaluation.
    def try_constant_fold
      return if @filters.empty?
      return unless literal_expression?(@name)

      strainer_class = @parse_context.environment.strainer_template

      @filters.each do |filter_name, filter_args, filter_kwargs|
        return unless strainer_class.pure_filter?(filter_name)
        return unless filter_args.all? { |arg| literal_expression?(arg) }
        return if filter_kwargs && !filter_kwargs.each_value.all? { |arg| literal_expression?(arg) }
      end

      strainer = strainer_class.new(nil)
      value = @name

      @filters.each do |filter_name, filter_args, filter_kwargs|
        args = filter_kwargs ? filter_args + [filter_kwargs] : filter_args
        value = strainer.invoke(filter_name, value, *args).to_liquid
      end

      @fold_strainer_class = strainer_class
      @fold_version = strainer_class.filter_version
      @folded_value = value.freeze
    rescue ::StandardError
      # If evaluating the literal chain fails at parse time, leave it to the
      # runtime so that errors surface through the normal error handling path.
      @fold_strainer_class = nil
    end

    # The cached constant is only valid for a render context whose strainer is
    # exactly the one the fold was computed with (same environment, no
    # context-local filters) and whose filter registry has not changed since.
    def fold_valid_for?(context)
      @fold_strainer_class &&
        context.strainer.class.equal?(@fold_strainer_class) &&
        @fold_strainer_class.filter_version == @fold_version
    end

    def literal_expression?(expr)
      !expr.respond_to?(:evaluate)
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
