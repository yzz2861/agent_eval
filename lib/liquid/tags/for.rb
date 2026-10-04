# frozen_string_literal: true

module Liquid
  # @liquid_public_docs
  # @liquid_type tag
  # @liquid_category iteration
  # @liquid_name for
  # @liquid_summary
  #   Renders an expression for every item in an array.
  # @liquid_description
  #   You can do a maximum of 50 iterations with a `for` loop. If you need to iterate over more than 50 items, then use the
  #   [`paginate` tag](/docs/api/liquid/tags/paginate) to split the items over multiple pages.
  #
  #   > Tip:
  #   > Every `for` loop has an associated [`forloop` object](/docs/api/liquid/objects/forloop) with information about the loop.
  # @liquid_syntax
  #   {% for variable in array %}
  #     expression
  #   {% endfor %}
  # @liquid_syntax_keyword variable The current item in the array.
  # @liquid_syntax_keyword array The array to iterate over.
  # @liquid_syntax_keyword expression The expression to render for each iteration.
  # @liquid_optional_param limit: [number] The number of iterations to perform.
  # @liquid_optional_param offset: [number] The 1-based index to start iterating at.
  # @liquid_optional_param range [untyped] A custom numeric range to iterate over.
  # @liquid_optional_param reversed [untyped] Iterate in reverse order.
  class For < Block
    Syntax = /\A(#{VariableSegment}+)\s+in\s+(#{QuotedFragment}+)\s*(reversed)?/o

    attr_reader :collection_name, :variable_name, :limit, :from

    def initialize(tag_name, markup, options)
      super
      @from = @limit = nil
      parse_with_selected_parser(markup)
      @for_block = new_body
      @else_block = nil
    end

    def parse(tokens)
      if parse_body(@for_block, tokens)
        parse_body(@else_block, tokens)
      end
      if blank?
        @else_block&.remove_blank_strings
        @for_block.remove_blank_strings
      end
      @else_block&.freeze
      @for_block.freeze
    end

    def nodelist
      @else_block ? [@for_block, @else_block] : [@for_block]
    end

    def unknown_tag(tag, markup, tokens)
      return super unless tag == 'else'
      @else_block = new_body
    end

    def render_to_output_buffer(context, output)
      from, to = for_bounds(context)
      collection = context.evaluate(@collection_name)

      if collection.is_a?(::Enumerator)
        raise Liquid::ArgumentError, "cannot reverse an Enumerator" if @reversed

        if enumerator_size(collection).nil?
          normalized_from = [from, 0].max
          physical_from, skip_count = lazy_enumerator_continue(context, collection, normalized_from)
          limit = to && to - normalized_from
          return render_lazy_enumerator(
            context, output, collection, normalized_from, physical_from, skip_count, limit
          )
        end

        return render_eager_enumerator(context, output, collection, from, to)
      end

      segment = collection_segment(context, collection, from, to)

      if segment.empty?
        render_else(context, output)
      else
        render_segment(context, output, segment)
      end

      output
    end

    protected

    def lax_parse(markup)
      if markup =~ Syntax
        @variable_name   = Regexp.last_match(1)
        collection_name  = Regexp.last_match(2)
        @reversed        = !!Regexp.last_match(3)
        @name            = "#{@variable_name}-#{collection_name}"
        @collection_name = parse_expression(collection_name)
        markup.scan(TagAttributes) do |key, value|
          set_attribute(key, value)
        end
      else
        raise SyntaxError, options[:locale].t("errors.syntax.for")
      end
    end

    def strict_parse(markup)
      p = @parse_context.new_parser(markup)
      @variable_name = p.consume(:id)
      raise SyntaxError, options[:locale].t("errors.syntax.for_invalid_in") unless p.id?('in')

      collection_name  = p.expression
      @collection_name = parse_expression(collection_name, safe: true)

      @name     = "#{@variable_name}-#{collection_name}"
      @reversed = p.id?('reversed')

      while p.look(:comma) || p.look(:id)
        p.consume?(:comma)
        unless (attribute = p.id?('limit') || p.id?('offset'))
          raise SyntaxError, options[:locale].t("errors.syntax.for_invalid_attribute")
        end
        p.consume(:colon)
        set_attribute(attribute, p.expression, safe: true)
      end
      p.consume(:end_of_string)
    end

    private

    def strict2_parse(markup)
      strict_parse(markup)
    end

    def for_bounds(context)
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

      limit_value = context.evaluate(@limit)
      to = if limit_value.nil?
        nil
      else
        Utils.to_integer(limit_value) + from
      end

      [from, to]
    end

    def collection_segment(context, collection, from, to)
      offsets = context.registers[:for] ||= {}

      segment = Utils.slice_collection_for_iteration(
        collection, from, to, context.resource_limits, use_range_to_a: true
      )
      segment.reverse! if @reversed

      offsets[@name] = from + segment.length

      segment
    end

    def render_eager_enumerator(context, output, enumerator, from, to)
      segment = collection_segment(context, enumerator, from, to)

      if segment.empty?
        render_else(context, output)
      else
        render_segment(context, output, segment)
      end

      output
    end

    def enumerator_size(collection)
      collection.size if collection.respond_to?(:size)
    end

    def lazy_enumerator_continue(context, enumerator, from)
      states = context.registers[:for_enumerators] ||= {}
      return [from, from] unless @from == :continue

      previous = states[@name]
      return [from, from] unless previous && previous[:enumerator].equal?(enumerator)

      consumed = previous[:consumed_position]
      [consumed, [from - consumed, 0].max]
    end

    def render_lazy_enumerator(
      context, output, enumerator, logical_start, base_position, skip_count, limit = nil
    )
      offsets = context.registers[:for] ||= {}
      states = context.registers[:for_enumerators] ||= {}
      iterator = LazyEnumeratorIterator.new(
        enumerator, logical_start, base_position, skip_count, limit, context.resource_limits
      )
      offsets[@name] = iterator.logical_position
      states[@name] = { enumerator: enumerator, consumed_position: iterator.consumed_position }

      if iterator.empty?
        render_else(context, output)
      else
        for_stack = context.registers[:for_stack] ||= []

        context.stack do
          loop_vars = Liquid::ForloopDrop.new(
            @name,
            nil,
            for_stack[-1],
            last_checker: -> { iterator.last?(loop_vars) },
            length_checker: -> { iterator.known_length },
          )
          for_stack.push(loop_vars)

          begin
            context['forloop'] = loop_vars

            while iterator.current?
              context[@variable_name] = iterator.current
              @for_block.render_to_output_buffer(context, output)

              if context.interrupt?
                interrupt = context.pop_interrupt
                break if interrupt.is_a?(BreakInterrupt)
              end

              loop_vars.send(:increment!)
              break if iterator.at_limit?
              break if iterator.known_last?
              iterator.advance_to_current!
              break unless iterator.current?
            end
          ensure
            for_stack.pop
            context.registers[:for][@name] = iterator.logical_position
            context.registers[:for_enumerators][@name][:consumed_position] =
              iterator.consumed_position
          end
        end
      end

      output
    end

    def render_segment(context, output, segment)
      for_stack = context.registers[:for_stack] ||= []
      length    = segment.length

      context.stack do
        loop_vars = Liquid::ForloopDrop.new(@name, length, for_stack[-1])

        for_stack.push(loop_vars)

        begin
          context['forloop'] = loop_vars

          segment.each do |item|
            context[@variable_name] = item
            @for_block.render_to_output_buffer(context, output)
            loop_vars.send(:increment!)

            # Handle any interrupts if they exist.
            next unless context.interrupt?
            interrupt = context.pop_interrupt
            break if interrupt.is_a?(BreakInterrupt)
            next if interrupt.is_a?(ContinueInterrupt)
          end
        ensure
          for_stack.pop
        end
      end

      output
    end

    def set_attribute(key, expr, safe: false)
      case key
      when 'offset'
        @from = if expr == 'continue'
          :continue
        else
          parse_expression(expr, safe: safe)
        end
      when 'limit'
        @limit = parse_expression(expr, safe: safe)
      end
    end

    def render_else(context, output)
      if @else_block
        @else_block.render_to_output_buffer(context, output)
      else
        output
      end
    end

    class ParseTreeVisitor < Liquid::ParseTreeVisitor
      def children
        (super + [@node.limit, @node.from, @node.collection_name]).compact
      end
    end

    class LazyEnumeratorIterator
      EXHAUSTED = Object.new.freeze

      def initialize(enumerator, logical_start, physical_position, skip_count, limit, resource_limits)
        @enumerator = enumerator
        @resource_limits = resource_limits
        @logical_start = logical_start
        @physical_position = physical_position
        @selected_index = 0
        @limit = limit
        @current = nil
        @has_current = false
        @feed = nil
        @has_feed = false
        @known_last = false

        unless limit && limit <= 0
          skip!(skip_count)
          advance_to_current!
        end
      end

      attr_reader :selected_index

      def current
        @current
      end

      def current?
        @has_current
      end

      def empty?
        !@has_current
      end

      def at_limit?
        !@limit.nil? && @selected_index >= @limit
      end

      def consumed_position
        @physical_position
      end

      def logical_position
        @logical_start + @selected_index
      end

      def known_length
        @limit if !@limit.nil? && @selected_index >= @limit
      end

      def known_last?
        @known_last
      end

      def advance_to_current!
        if @has_feed
          @current = @enumerator.next
          @feed = nil
          @has_feed = false
        else
          current = begin
            @enumerator.next
          rescue StopIteration
            EXHAUSTED
          end
          if current.equal?(EXHAUSTED)
            @has_current = false
            return
          end
          @current = current
          @resource_limits.increment_render_score(1)
          @physical_position += 1
        end

        @selected_index += 1
        @has_current = true
      end

      def last?(loop_vars)
        if at_limit?
          @known_last = true
          loop_vars.send(:set_last!, true)
          return true
        end

        last = peek_next.equal?(EXHAUSTED)
        if last
          @known_last = true
          loop_vars.send(:set_last!, true)
        end
        last
      end

      private

      def skip!(count)
        count.times do
          @enumerator.next
          @resource_limits.increment_render_score(1)
        end
      rescue StopIteration
        # Source ended inside the offset window.
      end

      def peek_next
        unless @has_feed
          begin
            @feed = @enumerator.peek
            @has_feed = true
            @resource_limits.increment_render_score(1)
            @physical_position += 1
          rescue StopIteration
            @feed = EXHAUSTED
            @has_feed = false
          end
        end
        @feed
      end
    end
  end
end
