# frozen_string_literal: true

module Liquid
  # Break tag to be used to break out of a for loop.
  #
  # == Basic Usage:
  #    {% for item in collection %}
  #      {% if item.condition %}
  #        {% break %}
  #      {% endif %}
  #    {% endfor %}
  #
  # @liquid_public_docs
  # @liquid_type tag
  # @liquid_category iteration
  # @liquid_name break
  # @liquid_summary
  #   Stops a [`for` loop](/docs/api/liquid/tags/for) from iterating.
  # @liquid_syntax
  #   {% break %}
  #   {% break label %}
  class Break < Tag
    INTERRUPT = BreakInterrupt.new.freeze
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
      context.push_interrupt(@label ? BreakInterrupt.new(@label).freeze : INTERRUPT)
      output
    end
  end
end
