# frozen_string_literal: true

module Liquid
  # @liquid_public_docs
  # @liquid_type tag
  # @liquid_category iteration
  # @liquid_name continue
  # @liquid_summary
  #   Causes a [`for` loop](/docs/api/liquid/tags/for) to skip to the next iteration.
  # @liquid_syntax
  #   {% continue %}
  #   {% continue label %}
  class Continue < Tag
    INTERRUPT = ContinueInterrupt.new.freeze
    Syntax = /\A(?:(#{VariableSegment}+))?\s*\z/o

    attr_reader :label

    def initialize(tag_name, markup, options)
      super
      if markup =~ Syntax
        @label = Regexp.last_match(1)
      else
        raise SyntaxError, options[:locale].t("errors.syntax.tag_unexpected_args", tag: tag_name)
      end
    end

    def parse(_tokens)
      parse_context.validate_loop_label!(@label, @tag_name)
    rescue SyntaxError => e
      e.line_number    = line_number
      e.markup_context = markup_context(@markup)
      raise e
    end

    def render_to_output_buffer(context, output)
      context.push_interrupt(@label ? ContinueInterrupt.new(@label).freeze : INTERRUPT)
      output
    end
  end
end
