# frozen_string_literal: true

module Liquid
  # SourceMap records which template nodes produced which parts of the
  # rendered output. It is meant for tooling such as template editors that
  # want to trace a piece of rendered text back to the template node that
  # generated it.
  #
  # To enable source mapping, parse the template with <tt>source_map: true</tt>
  # and read the map from the template after rendering:
  #
  #   template = Liquid::Template.parse(source, source_map: true)
  #   output   = template.render('user' => user)
  #   template.source_map.entries.each do |entry|
  #     entry.output_range  # byte range in +output+ produced by the node
  #     entry.source_range  # byte range of the node in the template source
  #     entry.node          # the template node (String, Liquid::Variable or Liquid::Tag)
  #     entry.stack         # enclosing tags at render time, outermost first
  #   end
  #
  # Nodes inside loops are recorded once per iteration, and byte ranges always
  # reflect the actual output (e.g. after filters changed the value's length).
  #
  # Entries only contain byte offsets and references to template nodes.
  # Rendered text and variable values are never copied into the map, so
  # sensitive data from the render context does not leak into it.
  #
  # When the option is not used there is no extra render-time result:
  # Template#source_map stays nil and rendering behaves exactly as before.
  class SourceMap
    # A record of a single node render.
    class Entry
      attr_reader :node, :template_name, :output_start, :output_length, :source_range, :stack

      def initialize(node:, template_name:, output_start:, output_length:, source_range:, stack:)
        @node          = node
        @template_name = template_name
        @output_start  = output_start
        @output_length = output_length
        @source_range  = source_range
        @stack         = stack
      end

      # Byte range of the output produced by the node.
      def output_range
        @output_start...(@output_start + @output_length)
      end

      # :text for literal template text, :variable for {{ ... }} variables,
      # otherwise the tag name (e.g. "for").
      def node_type
        case @node
        when String
          :text
        when Variable
          :variable
        when Tag
          @node.tag_name
        else
          @node.class.name
        end
      end

      def line_number
        @node.line_number if @node.respond_to?(:line_number)
      end
    end

    attr_reader :entries

    def initialize(output)
      @output  = output
      @entries = []
      @stack   = []
    end

    # Only the output buffer this map was created for is tracked. Nodes
    # rendered into a temporary buffer (e.g. the body of a {% capture %} tag)
    # do not produce entries, since their byte offsets would not refer to
    # the final output.
    def tracking?(output)
      @output.equal?(output)
    end

    # @api private
    def push_frame(node)
      @stack << node
    end

    # @api private
    def pop_frame
      @stack.pop
    end

    # @api private
    def record(context, node, source_range, output_start, output_length)
      @entries << Entry.new(
        node: node,
        template_name: context.template_name,
        output_start: output_start,
        output_length: output_length,
        source_range: source_range,
        stack: @stack.dup.freeze,
      )
    end

    # All entries whose output range covers the given byte offset,
    # innermost (deepest render stack) first.
    def entries_at(byte_offset)
      @entries.select do |entry|
        entry.output_length.positive? &&
          byte_offset >= entry.output_start &&
          byte_offset < entry.output_start + entry.output_length
      end.sort_by { |entry| [-entry.stack.length, entry.output_length] }
    end
  end
end
