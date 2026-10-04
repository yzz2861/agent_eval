# frozen_string_literal: true

module Liquid
  module Bytecode
    # Immutable description of a {% for %} tag as parsed by the regular Liquid
    # parser. Keeping this object (rather than re-parsing markup) lets the VM
    # stay perfectly in sync with the tree-walking interpreter for collection
    # slicing, offset continuation registers and resource accounting.
    class LoopDescriptor
      attr_reader :name, :variable_name, :collection_name, :from, :limit, :reversed

      def initialize(for_tag)
        @variable_name = for_tag.variable_name
        @collection_name = for_tag.collection_name
        @from = for_tag.from
        @limit = for_tag.limit
        @reversed = for_tag.reversed?
        @name = for_tag.iteration_name
      end

      # Mirrors Liquid::For#collection_segment so that offset:continue, limit,
      # offset, reversed and range handling behave identically.
      def collection_segment(context)
        offsets = context.registers[:for] ||= {}

        from = if @from == :continue
          offsets[@name].to_i
        else
          from_value = context.evaluate(@from)
          if from_value.nil?
            0
          else
            Utils.to_integer(from_value)
          end
        end

        collection = context.evaluate(@collection_name)

        limit_value = context.evaluate(@limit)
        to = if limit_value.nil?
          nil
        else
          Utils.to_integer(limit_value) + from
        end

        segment = Utils.slice_collection_for_iteration(
          collection, from, to, context.resource_limits, use_range_to_a: true
        )
        segment.reverse! if @reversed

        offsets[@name] = from + segment.length

        segment
      end
    end
  end
end
