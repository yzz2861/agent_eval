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
  class Continue < Tag
    INTERRUPT = ContinueInterrupt.new.freeze

    attr_reader :label

    def initialize(tag_name, markup, options)
      super
      @label = parse_context.parse_loop_label(markup, tag_name)
      @interrupt = @label ? ContinueInterrupt.new(@label).freeze : INTERRUPT
    end

    def render_to_output_buffer(context, output)
      context.push_interrupt(@interrupt)
      output
    end
  end
end
