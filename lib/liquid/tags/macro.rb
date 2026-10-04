# frozen_string_literal: true

module Liquid
  class Macro < Block
    Parameter = Struct.new(:name, :default, keyword_init: true)

    attr_reader :macro_name, :parameters

    def initialize(tag_name, markup, options)
      super
      parse_with_selected_parser(markup)
    end

    def render_to_output_buffer(context, output)
      macro = MacroObject.new(
        name: @macro_name,
        body: @body,
        parameters: @parameters,
        closure_scopes: context.scopes.map(&:dup),
      )
      macro.closure_scopes.last[@macro_name] = macro
      context[@macro_name] = macro
      output
    end

    def blank?
      true
    end

    protected

    def lax_parse(markup)
      strict2_parse(markup)
    end

    def strict_parse(markup)
      strict2_parse(markup)
    end

    def strict2_parse(markup)
      signature = markup.strip
      identifier = Lexer::IDENTIFIER.source
      signature_pattern = /\A(?<name>#{identifier})(?:\s*\((?<parameters>.*)\)\s*)?\z/m
      match = signature.match(signature_pattern)
      unless match
        raise SyntaxError, "invalid macro signature #{markup.strip}"
      end

      @macro_name = match[:name]
      @parameters = match[:parameters] ? parse_parameters(match[:parameters]) : []
    end

    private

    def parse_parameters(parameter_markup)
      parameters = []
      split_parameters(parameter_markup).each do |parameter_source|
        parameter_pattern = /\A\s*(?<name>#{Lexer::IDENTIFIER.source})\s*(?:=\s*(?<default>.+))?\z/m
        match = parameter_source.match(parameter_pattern)
        unless match
          raise SyntaxError, "invalid macro parameter #{parameter_source.strip}"
        end

        name = match[:name]
        if parameters.any? { |parameter| parameter.name == name }
          raise SyntaxError, "duplicate macro parameter #{name}"
        end

        default = match[:default] ? parse_expression(match[:default], safe: true) : nil
        parameters << Parameter.new(name: name, default: default)
      end
      parameters
    end

    def split_parameters(markup)
      parameters = []
      buffer = +''
      depth = 0
      quote = nil
      markup.each_char do |character|
        if quote
          quote = nil if character == quote
        elsif character == '"' || character == "'"
          quote = character
        else
          depth += 1 if character == '(' || character == '['
          depth -= 1 if character == ')' || character == ']'
        end

        if character == ',' && depth.zero? && quote.nil?
          parameters << buffer
          buffer = +''
        else
          buffer << character
        end
      end
      parameters << buffer unless buffer.strip.empty?
      parameters
    end

    class ParseTreeVisitor < Liquid::ParseTreeVisitor
      def children
        @node.parameters.map(&:default).compact + super
      end
    end
  end

  class MacroObject
    attr_reader :name, :parameters, :closure_scopes

    def initialize(name:, body:, parameters:, closure_scopes:)
      @name = name
      @body = body
      @parameters = parameters
      @closure_scopes = closure_scopes
    end

    def scopes_for_invocation
      closure_scopes.dup
    end

    def environment_scopes_for_invocation
      []
    end

    def static_environments_for_invocation
      []
    end

    def render_to_output_buffer(context, output)
      @body.render_to_output_buffer(context, output)
    end

    def to_liquid
      self
    end

    def to_s
      ""
    end
  end

  class MacroCall < Tag
    include ParserSwitching

    Argument = Struct.new(:name, :expression, :keyword, keyword_init: true)

    attr_reader :macro_name, :arguments

    def initialize(tag_name, markup, options)
      super
      parse_with_selected_parser(markup)
    end

    def render_to_output_buffer(context, output)
      macro = context[@macro_name]
      unless macro.is_a?(MacroObject)
        raise ArgumentError, "undefined macro #{@macro_name}"
      end

      call_context = context.new_macro_subcontext(macro)
      call_context.stack({}) do
        bind_arguments(macro, context, call_context)
        macro.render_to_output_buffer(call_context, output)
      end
    end

    def lax_parse(markup)
      strict2_parse(markup)
    end

    def strict_parse(markup)
      strict2_parse(markup)
    end

    def strict2_parse(markup)
      parser = @parse_context.new_parser(markup.strip)
      @macro_name = parser.consume(:id)
      parenthesized = parser.consume?(:open_round)
      @arguments = parse_arguments(parser, parenthesized)
      parser.consume(:close_round) if parenthesized
      parser.consume(:end_of_string)
    end

    private

    def parse_arguments(parser, parenthesized)
      arguments = []
      seen_keyword = false
      while argument?(parser, parenthesized)
        keyword = keyword_argument?(parser)
        if keyword
          name = parser.consume(:id)
          parser.consume(:colon)
          seen_keyword = true
        else
          name = arguments.count { |argument| !argument.keyword }.to_s
          if seen_keyword
            raise SyntaxError, "positional argument after keyword argument"
          end
        end

        if arguments.any? { |argument| argument.name == name }
          label = keyword ? " #{name}" : ""
          raise SyntaxError, "duplicate#{label} argument"
        end

        arguments << Argument.new(
          name: name,
          expression: parse_argument_expression(parser),
          keyword: keyword,
        )
        break unless parser.consume?(:comma)
      end
      arguments
    end

    def argument?(parser, parenthesized)
      !(parenthesized ? parser.look(:close_round) : parser.look(:end_of_string))
    end

    def keyword_argument?(parser)
      parser.look(:id) && parser.look(:colon, 1)
    end

    def parse_argument_expression(parser)
      variable = safe_parse_expression(parser)
      filters = []
      while parser.consume?(:pipe)
        filter_name = parser.consume(:id)
        positional, keywords = parse_filter_arguments(parser) if parser.consume?(:colon)
        filters << [filter_name, positional || [], keywords]
      end
      filters.empty? ? variable : MacroArgumentExpression.new(variable, filters)
    end

    def parse_filter_arguments(parser)
      positional = []
      keywords = {}
      parse_filter_argument(parser, positional, keywords)
      while parser.consume?(:comma)
        parse_filter_argument(parser, positional, keywords)
      end
      [positional, keywords.empty? ? nil : keywords]
    end

    def parse_filter_argument(parser, positional, keywords)
      if parser.look(:id) && parser.look(:colon, 1)
        name = parser.consume(:id)
        parser.consume(:colon)
        keywords[name] = safe_parse_expression(parser)
      else
        positional << safe_parse_expression(parser)
      end
    end

    def bind_arguments(macro, context, evaluation_context = context)
      positional = @arguments.reject(&:keyword)
      keywords = @arguments.select(&:keyword)

      if positional.length > macro.parameters.length
        raise ArgumentError, "wrong number of arguments for macro #{macro.name}"
      end
      macro.parameters.each_with_index do |parameter, index|
        if positional[index]
          parameter_name = parameter.name
          if keywords.any? { |keyword| keyword.name == parameter_name }
            raise ArgumentError, "duplicate #{parameter_name} argument for macro #{macro.name}"
          end
          value = context.evaluate(positional[index].expression)
          evaluation_context.scopes.first[parameter.name] = value
        elsif (keyword = keywords.find { |argument| argument.name == parameter.name })
          value = context.evaluate(keyword.expression)
          evaluation_context.scopes.first[parameter.name] = value
        elsif parameter.default
          value = evaluation_context.evaluate(parameter.default)
          evaluation_context.scopes.first[parameter.name] = value
        else
          raise ArgumentError, "missing argument #{parameter.name} for macro #{macro.name}"
        end
      end

      keywords.each do |argument|
        unless macro.parameters.any? { |parameter| parameter.name == argument.name }
          raise ArgumentError, "unknown argument #{argument.name} for macro #{macro.name}"
        end
      end
    end

    class ParseTreeVisitor < Liquid::ParseTreeVisitor
      def children
        @node.arguments.map(&:expression)
      end
    end
  end

  class MacroArgumentExpression
    def initialize(name, filters)
      @name = name
      @filters = filters
    end

    def evaluate(context)
      initial_value = context.evaluate(@name)
      @filters.reduce(initial_value) do |result, (filter_name, arguments, keyword_arguments)|
        filter_arguments = arguments.map { |argument| context.evaluate(argument) }
        if keyword_arguments
          keyword_values = keyword_arguments.transform_values do |argument|
            context.evaluate(argument)
          end
          filter_arguments << keyword_values
        end
        context.invoke(filter_name, result, *filter_arguments)
      end
    end
  end
end
