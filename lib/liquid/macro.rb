# frozen_string_literal: true

module Liquid
  module MacroArgumentParser
    private

    def parse_variable_expression(parser)
      expression = safe_parse_expression(parser)
      filters = []

      while parser.consume?(:pipe)
        filter_name = parser.consume(:id)
        filter_args = []
        keyword_args = {}

        if parser.consume?(:colon)
          until macro_argument_terminator?(parser)
            if parser.look(:id) && parser.look(:colon, 1)
              key = parser.consume(:id)
              parser.consume(:colon)
              keyword_args[key] = safe_parse_expression(parser)
            else
              filter_args << safe_parse_expression(parser)
            end
            next_argument = parser.look(:comma) && parser.look(:id, 1) && parser.look(:colon, 2)
            parser.consume?(:comma) unless next_argument
          end
        end

        filters << [filter_name, filter_args].then do |filter|
          keyword_args.empty? ? filter : filter + [keyword_args]
        end
      end

      MacroArgument.new(expression, filters)
    end

    def macro_argument_terminator?(parser)
      parser.look(:close_round) || parser.look(:end_of_string) ||
        (parser.look(:comma) && parser.look(:id, 1) && parser.look(:colon, 2))
    end
  end

  class MacroArgument
    def initialize(name, filters)
      @name = name
      @filters = filters
    end

    def evaluate(context)
      value = context.evaluate(@name)
      @filters.each do |filter_name, filter_args, filter_kwargs|
        args = filter_args.map { |expression| context.evaluate(expression) }
        args << filter_kwargs.transform_values { |expression| context.evaluate(expression) } if filter_kwargs
        value = context.invoke(filter_name, value, *args)
      end
      value
    end
  end

  class Macro < Block
    include MacroArgumentParser

    attr_reader :name, :parameters, :default_arguments

    def initialize(tag_name, markup, parse_context)
      super
      parse_with_selected_parser(markup)
    end

    def parse(tokens)
      super
      freeze
    end

    def render_to_output_buffer(context, output)
      context[@name] = MacroReference.new(self, context)
      output
    end

    def render_call(definition_context, caller_context, arguments, output)
      missing = parameters.select do |name|
        !arguments.key?(name) && !default_arguments.key?(name)
      end
      unless missing.empty?
        raise ArgumentError, "macro '#{name}' is missing argument(s): #{missing.join(', ')}"
      end

      extra = arguments.keys - parameters
      unless extra.empty?
        raise ArgumentError, "macro '#{name}' does not accept argument(s): #{extra.join(', ')}"
      end

      values = {}
      arguments.each do |name, expression|
        values[name] = evaluate_argument(caller_context, expression)
      end

      macro_depth = caller_context.registers[:macro_depth] || 0
      macro_depth += 1
      raise StackLevelError, "Nesting too deep" if macro_depth > Block::MAX_DEPTH
      caller_context.registers[:macro_depth] = macro_depth
      macro_context = caller_context.new_macro_subcontext(definition_context)

      parameters.each do |parameter|
        if values.key?(parameter)
          macro_context[parameter] = values.fetch(parameter)
        else
          macro_context[parameter] = evaluate_argument(macro_context, default_arguments.fetch(parameter))
        end
      end

      begin
        @body.render_to_output_buffer(macro_context, output)
      ensure
        caller_context.registers[:macro_depth] = (caller_context.registers[:macro_depth] || 1) - 1
      end
      output
    end

    def blank?
      true
    end

    private

    def strict2_parse(markup)
      parser = @parse_context.new_parser(markup.strip)
      @name = parser.consume(:id)
      consume_optional_parameter_list_open(parser)

      @parameters = []
      @default_arguments = {}
      parse_parameter(parser) unless parser.look(:close_round) || parser.look(:end_of_string)
      while parser.consume?(:comma)
        break if parser.look(:close_round) || parser.look(:end_of_string)
        parse_parameter(parser)
      end

      consume_matching_parameter_list_close(parser)
      parser.consume(:end_of_string)
    end

    def strict_parse(markup)
      strict2_parse(markup)
    end

    def lax_parse(markup)
      strict2_parse(markup)
    end

    def parse_parameter(parser)
      parameter = parser.consume(:id)
      has_default = parser.consume?(:colon)
      add_parameter(parameter, has_default)
      @default_arguments[parameter] = parse_variable_expression(parser) if has_default
    end

    def add_parameter(parameter, has_default)
      if @parameters.include?(parameter)
        raise SyntaxError, "macro '#{@name}' has duplicate parameter: #{parameter}"
      end
      if @default_arguments.any? && !has_default
        raise SyntaxError, "macro '#{@name}' required parameters must precede default parameters"
      end
      @parameters << parameter
    end

    def consume_optional_parameter_list_open(parser)
      @has_parameter_list = !!parser.consume?(:open_round)
    end

    def consume_matching_parameter_list_close(parser)
      parser.consume(:close_round) if @has_parameter_list
    end

    def evaluate_argument(context, expression)
      expression.respond_to?(:evaluate) ? expression.evaluate(context) : context.evaluate(expression)
    end

    class ParseTreeVisitor < Liquid::ParseTreeVisitor
      def children
        @node.default_arguments.values
      end
    end
  end

  class MacroCall < Tag
    include MacroArgumentParser

    attr_reader :name, :arguments

    def initialize(tag_name, markup, parse_context)
      super
      parse_with_selected_parser(markup)
    end

    def render_to_output_buffer(context, output)
      macro = context.find_variable(@name, raise_on_not_found: false)
      unless macro.is_a?(MacroReference)
        raise ArgumentError, "macro '#{@name}' is not defined"
      end

      macro.render_call(context, @arguments, output)
    end

    private

    def strict2_parse(markup)
      parser = @parse_context.new_parser(markup.strip)
      @name = parser.consume(:id)
      consume_optional_argument_list_open(parser)

      @arguments = {}
      parse_argument(parser) unless parser.look(:close_round) || parser.look(:end_of_string)
      while parser.consume?(:comma)
        break if parser.look(:close_round) || parser.look(:end_of_string)
        parse_argument(parser)
      end

      consume_matching_argument_list_close(parser)
      parser.consume(:end_of_string)
    end

    def strict_parse(markup)
      strict2_parse(markup)
    end

    def lax_parse(markup)
      strict2_parse(markup)
    end

    def parse_argument(parser)
      unless parser.look(:id) && parser.look(:colon, 1)
        raise SyntaxError, "macro call arguments must be named"
      end

      argument = parser.consume(:id)
      parser.consume(:colon)
      add_argument(argument, parse_variable_expression(parser))
    end

    def add_argument(argument, expression)
      if @arguments.key?(argument)
        raise SyntaxError, "macro call has duplicate argument: #{argument}"
      end
      @arguments[argument] = expression
    end

    def consume_optional_argument_list_open(parser)
      @has_argument_list = !!parser.consume?(:open_round)
    end

    def consume_matching_argument_list_close(parser)
      parser.consume(:close_round) if @has_argument_list
    end

    class ParseTreeVisitor < Liquid::ParseTreeVisitor
      def children
        @node.arguments.values
      end
    end
  end

  class MacroReference
    attr_reader :macro, :definition_context, :lexical_scopes

    def initialize(macro, definition_context)
      @macro = macro
      @definition_context = definition_context
      @lexical_scopes = definition_context.scopes.dup
    end

    def render_call(caller_context, arguments, output)
      @macro.render_call(self, caller_context, arguments, output)
    end

    def to_liquid
      self
    end
  end
end
