require 'parslet'

class Parslet::Layout
  # Raised when the indentation in a single parse cannot be interpreted with
  # one tab policy.
  class AmbiguousIndentation < Parslet::ParseFailed; end

  # Transient layout state shared by the layout atoms of one parser run.
  class State
    attr_reader :levels, :enabled, :line_boundary

    def initialize(_source, options)
      @comment = options[:comment]
      @tabs = options.fetch(:tabs, :auto)
      @tab_width = options.fetch(:tab_width, 8)
      unless [:auto, :spaces, :tabs].include?(@tabs)
        raise ArgumentError, "Unsupported tab policy #{@tabs.inspect}"
      end

      @strategy = nil
      @levels = []
      @enabled = true
      @prepared_indent = nil
      @prepared_indent_bytes = nil
      @line_boundary = true
    end

    def snapshot
      [@levels.dup, @enabled]
    end

    def restore(snapshot)
      @levels,
        @enabled = snapshot
    end

    def current_level
      @levels.last || 0
    end

    def prepare(source, context, advance_if_at_line_end: false)
      @line_boundary = source.bytepos.zero? || source.line_and_column.last == 1
      @at_line_end = advance_if_at_line_end && line_ending?(source)
      can_advance = @line_boundary || @at_line_end
      @line_boundary = skip_ignored_lines(source, context) if can_advance
      if !line_boundary
        @prepared_indent = nil
        @prepared_indent_bytes = nil
      elsif source.chars_left.zero?
        @prepared_indent = nil
        @prepared_indent_bytes = nil
      else
        @prepared_indent, @prepared_indent_bytes = measure_indent(source)
      end

      @prepared_indent
    end

    def consume_prepared_indent(source)
      source.bytepos += @prepared_indent_bytes
    end

    def disable!
      @enabled = false
    end

    def disabled?
      !@enabled
    end

    def push(indent)
      @levels << indent
    end

    def pop
      @levels.pop
    end

    def valid_outer_indent?(indent)
      indent.zero? || @levels[0...-1].include?(indent)
    end

    private

    def skip_ignored_lines(source, context)
      line_ending_length = advance_line_ending(source)
      return true if source.chars_left.zero?
      return false if line_ending_length == 0 && !@line_boundary && !@at_line_end

      @line_boundary = true

      loop do
        line_start = source.bytepos
        scan_indentation(source)

        if source.chars_left.zero?
          return true
        end

        if line_ending?(source)
          advance_line_ending(source)
          return true if source.chars_left.zero?
        elsif comment?(source, context)
          skip_line_body(source)
          advance_line_ending(source)
          return true if source.chars_left.zero?
        else
          source.bytepos = line_start
          return true
        end
      end
    end

    def measure_indent(source)
      start = source.bytepos
      indentation = scan_indentation(source)
      source.bytepos = start
      validate_strategy(indentation)
      [width(indentation), indentation.bytesize]
    end

    def scan_indentation(source)
      indentation = +''
      while source.matches?(/[ \t]/)
        indentation << source.consume(1).str
      end
      indentation
    end

    def validate_strategy(indentation)
      return if indentation.empty?

      has_space = indentation.include?(' ')
      has_tab = indentation.include?("\t")
      raise AmbiguousIndentation.new(
        'Indentation mixes tabs and spaces; choose one tab policy for the parse.'
      ) if has_space && has_tab

      actual = has_tab ? :tabs : :spaces
      if @tabs == :spaces && has_tab
        raise AmbiguousIndentation.new(
          'Tab indentation is forbidden by the spaces-only tab policy.'
        )
      elsif @tabs == :tabs && has_space
        raise AmbiguousIndentation.new(
          'Space indentation is forbidden by the tabs-only tab policy.'
        )
      end

      @strategy ||= actual
      return unless @strategy != actual

      raise AmbiguousIndentation.new(
        'Tab policy changed during the parse; use tabs or spaces consistently.'
      )
    end

    def width(indentation)
      indentation.each_char.inject(0) do |column, char|
        next ((column / @tab_width) + 1) * @tab_width if char == "\t"
        column + 1
      end
    end

    def comment?(source, context)
      return false unless @comment

      success, _ = @comment.apply(source, context, false)
      success
    end

    def skip_line_body(source)
      source.consume(1) while source.matches?(/[^\r\n]/)
    end

    def line_ending?(source)
      !!source.matches?(/\r\n|\r|\n/)
    end

    def advance_line_ending(source)
      match = source.matches?(/\r\n|\r|\n/)
      return 0 unless match

      length = match == 1 ? 1 : 2
      source.bytepos += length
      length
    end
  end

  # Parsing context with transactional layout state. Caching is disabled because
  # a cached branch must not replay an indentation-stack change.
  class Context < Parslet::Atoms::Context
    attr_accessor :layout_state

    def initialize(reporter=nil, layout_state: nil)
      super(reporter)
      @layout_state = layout_state
    end

    def try_with_cache(atom, source, consume_all)
      snapshot = @layout_state.snapshot
      result = atom.try(source, self, consume_all)
      result
    rescue AmbiguousIndentation
      @layout_state.restore(snapshot)
      raise
    else
      @layout_state.restore(snapshot) unless result.first
      result
    end
  end

  class BoundParser < Parslet::Atoms::Base
    attr_reader :layout, :root_parslet

    def initialize(layout, root_parslet)
      @layout = layout
      @root_parslet = root_parslet
    end

    def cached?
      false
    end

    def try(source, context, consume_all)
      layout_context = Context.new(
        context.instance_variable_get(:@reporter)
      )
      layout_context.layout_state = State.new(source, layout.options)
      outer_captures = context.captures.instance_variable_get(:@current)
      layout_context.captures.instance_variable_set(:@current, outer_captures)
      @root_parslet.apply(source, layout_context, consume_all)
    rescue AmbiguousIndentation => error
      context.err_at(self, source, error.message, source.pos)
    end

    def to_s_inner(prec)
      "layout { #{@root_parslet.to_s(prec)} }"
    end
  end

  module Atoms
    # Base class for zero-width layout events.
    class Event < Parslet::Atoms::Base
      def initialize(layout)
        @layout = layout
      end

      def cached?
        false
      end

      private

      def state(source, context)
        state = context.layout_state if context.respond_to?(:layout_state)
        return state if state.is_a?(State)

        context.err(
          self,
          source,
          'Layout events can only be used inside Parslet::Layout#wrap.'
        )
      end

      def disabled_failure(source, context)
        context.err(self, source, 'Layout recognition is suspended here.')
      end
    end

    class SameLevel < Event
      def try(source, context, consume_all)
        layout_state = state(source, context)
        return layout_state unless layout_state.is_a?(State)
        return disabled_failure(source, context) if layout_state.disabled?

        indent = layout_state.prepare(source, context)
        if !layout_state.line_boundary || indent.nil? || indent != layout_state.current_level
          return context.err(self, source, 'Expected an item at the current indentation level.')
        end

        layout_state.consume_prepared_indent(source)
        succ(nil)
      end

      def to_s_inner(prec)
        'layout.same'
      end
    end

    class Indent < Event
      def try(source, context, consume_all)
        layout_state = state(source, context)
        return layout_state unless layout_state.is_a?(State)
        return disabled_failure(source, context) if layout_state.disabled?

        indent = layout_state.prepare(source, context, advance_if_at_line_end: true)
        if !layout_state.line_boundary || indent.nil? || indent <= layout_state.current_level
          return context.err(self, source, 'Expected a more deeply indented block.')
        end

        layout_state.push(indent)
        layout_state.consume_prepared_indent(source)
        succ(nil)
      end

      def to_s_inner(prec)
        'layout.indent'
      end
    end

    class Dedent < Event
      def try(source, context, consume_all)
        layout_state = state(source, context)
        return layout_state unless layout_state.is_a?(State)
        return disabled_failure(source, context) if layout_state.disabled?

        if layout_state.levels.empty?
          return context.err(self, source, 'Cannot dedent past the outer layout level.')
        end

        indent = layout_state.prepare(source, context, advance_if_at_line_end: true)
        if source.chars_left.zero?
          layout_state.pop
        elsif indent &&
                indent < layout_state.current_level &&
                layout_state.valid_outer_indent?(indent)
          layout_state.pop
        else
          return context.err(self, source, 'Expected a return to an enclosing indentation level.')
        end

        succ(nil)
      end

      def to_s_inner(prec)
        'layout.dedent'
      end
    end

    class End < Event
      def try(source, context, consume_all)
        layout_state = state(source, context)
        return layout_state unless layout_state.is_a?(State)
        return disabled_failure(source, context) if layout_state.disabled?

        layout_state.prepare(source, context, advance_if_at_line_end: true)
        return succ(nil) if source.chars_left.zero? && layout_state.levels.empty?

        context.err(self, source, 'Expected all layout blocks to be closed at end of input.')
      end

      def to_s_inner(prec)
        'layout.end'
      end
    end
  end

  class Suspended < Parslet::Atoms::Base
    attr_reader :parslet

    def initialize(parslet)
      @parslet = parslet
    end

    def cached?
      false
    end

    def try(source, context, consume_all)
      layout_state = context.layout_state if context.respond_to?(:layout_state)
      return @parslet.apply(source, context, consume_all) unless layout_state.is_a?(State)

      was_enabled = layout_state.enabled
      snapshot = layout_state.snapshot
      layout_state.disable!
      @parslet.apply(source, context, consume_all)
    ensure
      if layout_state
        layout_state.restore(snapshot)
        layout_state.disable! unless was_enabled
      end
    end

    def to_s_inner(prec)
      "layout.without { #{@parslet.to_s(prec)} }"
    end
  end

  class Block < Parslet::Atoms::Base
    attr_reader :layout, :content

    def initialize(layout, content)
      @layout = layout
      @content = content
    end

    def cached?
      false
    end

    def try(source, context, consume_all)
      parslet = @layout.indent >> @content >> @layout.dedent
      parslet.apply(source, context, consume_all)
    end

    def to_s_inner(prec)
      "layout.block(#{@content.to_s(prec)})"
    end
  end

  attr_reader :options

  # @param comment [#apply] atom matching the beginning of a full-line comment
  # @param tabs [:auto, :spaces, :tabs] indentation policy for this parser run
  # @param tab_width [Integer] visual width of one tab
  def initialize(comment: nil, tabs: :auto, tab_width: 8)
    @options = { comment: comment, tabs: tabs, tab_width: tab_width }
    @same = Atoms::SameLevel.new(self)
    @indent = Atoms::Indent.new(self)
    @dedent = Atoms::Dedent.new(self)
    @end = Atoms::End.new(self)
  end

  # Runs a grammar with an isolated layout state.
  def wrap(root_parslet)
    BoundParser.new(self, root_parslet)
  end
  alias bind wrap

  # Matches the current indentation level without entering or leaving a block.
  def same
    @same
  end

  # Matches the next deeper indentation level and enters that block.
  def indent
    @indent
  end

  # Leaves the current block at EOF or at a previously opened indentation.
  def dedent
    @dedent
  end

  # Succeeds only when all blocks are closed at end of input.
  def end_event
    @end
  end
  alias end_of_input end_event

  # Runs an expression while layout events are unavailable.
  def without(parslet)
    Suspended.new(parslet)
  end

  # Enters +content+, then requires a matching dedent or EOF block close.
  def block(content)
    Block.new(self, content)
  end
end
