# frozen_string_literal: true

module Liquid
  class RenderSourceMap
    Entry = Struct.new(
      :output_byte_range,
      :template_name,
      :template_byte_range,
      :node,
      :render_stack,
      keyword_init: true,
    ) do
      attr_accessor :relative
    end

    RenderFrame = Struct.new(
      :tag_name,
      :template_name,
      :template_byte_range,
      :iteration,
      keyword_init: true,
    )

    attr_reader :entries, :render_stack
    attr_accessor :active_output_buffer_id, :active_output_buffer_offset

    def initialize
      @entries = []
      @render_stack = []
      @active_output_buffer_id = nil
      @active_output_buffer_offset = nil
    end

    def track_output_buffer(output, partial: false, root_render_offset: 0)
      previous_output_buffer_id = @active_output_buffer_id
      previous_output_buffer_offset = @active_output_buffer_offset
      entries_start_index = @entries.length
      starting_output_bytesize = output.bytesize

      @active_output_buffer_id = output.object_id
      @active_output_buffer_offset = if partial && previous_output_buffer_id == output.object_id
        starting_output_bytesize
      elsif previous_output_buffer_id.nil?
        root_render_offset
      else
        0
      end

      yield
    ensure
      if partial && previous_output_buffer_id == output.object_id
        translate_output_byte_ranges(
          entries_start_index,
          starting_output_bytesize,
        )
      end

      @active_output_buffer_id = previous_output_buffer_id
      @active_output_buffer_offset = previous_output_buffer_offset
    end

    def record(node, template_name, output, start_byte)
      end_byte = output.bytesize
      return unless output.object_id == @active_output_buffer_id
      return unless end_byte > start_byte && start_byte >= @active_output_buffer_offset

      entry = Entry.new(
        output_byte_range: (start_byte - @active_output_buffer_offset)...(end_byte - @active_output_buffer_offset),
        template_name: template_name,
        template_byte_range: node.source_range,
        node: node,
        render_stack: @render_stack.map(&:dup),
      )
      entry.relative = @active_output_buffer_offset.positive?
      @entries << entry
    end

    def with_render_frame(node, template_name, iteration: nil)
      @render_stack << RenderFrame.new(
        tag_name: node.tag_name,
        template_name: template_name,
        template_byte_range: node.source_range,
        iteration: iteration,
      )
      yield
    ensure
      @render_stack.pop
    end

    private

    def translate_output_byte_ranges(start_index, offset)
      @entries[start_index..].each do |entry|
        next unless entry.relative

        range = entry.output_byte_range
        entry.output_byte_range = (range.begin + offset)...(range.end + offset)
        entry.relative = false
      end
    end
  end

  class TextNode < String
    attr_accessor :source_range

    def initialize(string, source_range)
      @source_range = source_range
      super(string)
    end
  end

  module ContextRenderSourceMapHook
    attr_accessor :render_source_map, :render_source_map_root_offset

    def new_isolated_subcontext
      new_context = super
      new_context.render_source_map = render_source_map
      new_context.render_source_map_root_offset = render_source_map_root_offset
      new_context
    end
  end
  Context.prepend(ContextRenderSourceMapHook)

  module DocumentRenderSourceMapHook
    def render_to_output_buffer(context, output)
      source_map = context.render_source_map
      return super unless source_map

      source_map.track_output_buffer(output, partial: context.partial, root_render_offset: context.render_source_map_root_offset.to_i) { super }
    end
  end
  Document.prepend(DocumentRenderSourceMapHook)

  module BlockBodyRenderSourceMapHook
    def render_node(context, output, node)
      source_map = context.render_source_map
      return super if source_map.nil?

      start_byte = output.bytesize
      begin
        super
      ensure
        source_map.record(node, context.template_name, output, start_byte)
      end
    end

    def render_text_node(context, output, node)
      source_map = context.render_source_map
      return super if source_map.nil?

      start_byte = output.bytesize
      begin
        super
      ensure
        source_map.record(node, context.template_name, output, start_byte)
      end
    end
  end
  BlockBody.prepend(BlockBodyRenderSourceMapHook)
end
