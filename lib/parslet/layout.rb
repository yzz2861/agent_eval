# Indentation sensitive layout for parslet grammars.
#
# Instead of having every grammar count spaces by itself, this module
# analyses the input once at the beginning of a parse and then offers three
# composable layout events as parslet atoms:
#
# * +enter+  - the next significant line is indented deeper
# * +same+   - the next significant line is at the current level
# * +exit+   - the block ends here: the next line is shallower, or the
#              input ends (consecutive dedents are handled by nesting one
#              exit per block)
#
# The events consume (or, for +exit+, observe) the "gap" between two
# significant lines: newlines, blank lines, whole line comments and the
# indentation of the next line. Since the events are ordinary parslet atoms
# over the original input, all slices and positions in the parse tree still
# refer to the original text.
#
# Example:
#
#   class Config < Parslet::Parser
#     L = Parslet::Layout.new(comment: '#')
#
#     root(:document)
#     rule(:document) { L.start >> node >> (L.same >> node).repeat >> L.finish }
#     rule(:node)     { pair >> nested.maybe }
#     rule(:nested)   { L.scope(L.enter >> node >> (L.same >> node).repeat >> L.exit) }
#     # ...
#   end
#
# Backtracking safety: layout state (the stack of indentation levels) is
# kept per parse and per layout instance. Any atom sequence that can push a
# level and then fail must be wrapped in L.scope(...) (or use the
# L.scope { ... } block form), which restores the stack when its inner
# parse fails. L.block(head, item) is a ready-made transactional
# combination.
#
# Notes:
# * Blank lines and whole line comments (configured via :comment) never
#   count for indentation.
# * Inside brackets (() [] {}) layout recognition is suspended; a logical
#   line only ends at a newline with bracket depth zero. Quotes (' and ")
#   are honoured while scanning for brackets.
# * The tab policy is fixed once per parse (:auto, :spaces, :tabs or
#   :forbid). Mixing tabs and spaces in a way that makes indentation
#   ambiguous raises Parslet::Layout::TabError.
# * A dedent that lands between two established levels raises
#   Parslet::Layout::DedentError.
# * Blocks that are still open at end of input are closed implicitly:
#   +exit+ succeeds at end of input.
#
module Parslet
  module Layout
    # Base class for all errors raised by layout analysis.
    class Error < StandardError; end

    # Raised when tabs and spaces are mixed in a way that makes indentation
    # ambiguous, or when indentation violates the configured tab policy.
    class TabError < Error; end

    # Raised when a line is dedented to a level that was never established
    # by an enclosing line.
    class DedentError < Error; end

    # Creates a layout factory. This indirection allows
    # Parslet::Layout.new(...) even though Layout is a module.
    #
    def self.new(**options)
      Factory.new(**options)
    end

    # One significant (non blank, non comment, bracket depth zero) line.
    #
    class Line
      attr_reader :offset   # byte offset of the first content character
      attr_reader :indent   # raw indentation string (spaces and/or tabs)
      attr_accessor :width  # indentation width in policy units
      attr_accessor :depth  # nesting depth, 0 = top level
      attr_accessor :event  # :enter, :same or :exit relative to previous line

      def initialize(offset, indent)
        @offset = offset
        @indent = indent
      end
    end

    # Analyses the source text once per parse: finds significant lines,
    # determines the tab policy and validates indentation consistency.
    #
    class Analyzer
      DEFAULT_BRACKETS = { '(' => ')', '[' => ']', '{' => '}' }.freeze
      DEFAULT_QUOTES = ["'", '"'].freeze

      def initialize(source, comment: nil, tabs: :auto,
                     brackets: DEFAULT_BRACKETS, quotes: DEFAULT_QUOTES)
        @source = source
        @comment = comment
        @tabs = tabs
        @openers = brackets.keys
        @closers = brackets.values
        @quotes = quotes
      end

      # Returns [Array<Line>, Integer]: the significant lines and the base
      # (top level) indentation width.
      #
      def analyze
        lines = significant_lines
        mode = resolve_tab_mode(lines)
        assign_widths(lines, mode)
        base_width = lines.empty? ? 0 : lines.first.width
        assign_structure(lines)
        [lines, base_width]
      end

      private

      # Scans the source line by line, tracking bracket depth and string
      # state, and returns the significant lines.
      #
      def significant_lines
        lines = []
        depth = 0
        in_string = nil
        escaped = false
        bytepos = 0

        @source.each_line do |text|
          line_start = bytepos
          bytepos += text.bytesize

          depth_at_start = depth
          in_string_at_start = !in_string.nil?

          indent = text[/\A[ \t]*/] || ''
          rest = text[indent.length..] || ''

          blank = rest.strip.empty?
          comment = !blank && depth_at_start.zero? && !in_string_at_start &&
            comment_line?(rest)

          # Comment lines are inert: their content must not influence
          # bracket tracking.
          unless comment
            depth, in_string, escaped =
              scan_line(text, depth, in_string, escaped)
          end

          next unless depth_at_start.zero?
          next if blank || comment

          lines << Line.new(line_start + indent.bytesize, indent)
        end

        lines
      end

      def scan_line(text, depth, in_string, escaped)
        text.each_char do |char|
          if in_string
            if escaped
              escaped = false
            elsif char == '\\'
              escaped = true
            elsif char == in_string
              in_string = nil
            end
          elsif @quotes.include?(char)
            in_string = char
          elsif @openers.include?(char)
            depth += 1
          elsif @closers.include?(char)
            depth -= 1 if depth > 0
          end
        end
        [depth, in_string, escaped]
      end

      def comment_line?(rest)
        case @comment
        when nil then false
        when String then rest.start_with?(@comment)
        when Regexp then !!@comment.match?(rest)
        else
          raise ArgumentError, 'comment: must be a String or Regexp'
        end
      end

      # Determines the tab policy once for this parse and validates every
      # indentation string against it.
      #
      def resolve_tab_mode(lines)
        mode = @tabs
        if mode == :auto
          first = lines.map(&:indent).find { |indent| !indent.empty? }
          mode = first && first.include?("\t") ? :tabs : :spaces
        end

        unless %i(spaces tabs forbid).include?(mode)
          raise ArgumentError, 'tabs: must be :auto, :spaces, :tabs or :forbid'
        end

        lines.each do |line|
          indent = line.indent
          next if indent.empty?

          if indent.include?("\t") && indent.include?(' ')
            fail_at(line, TabError,
              'tabs and spaces mixed within one indentation')
          end
          if %i(spaces forbid).include?(mode) && indent.include?("\t")
            fail_at(line, TabError,
              "tab in indentation, but policy is #{mode.inspect} " \
              '(mixed tabs and spaces are ambiguous)')
          end
          if mode == :tabs && indent.include?(' ')
            fail_at(line, TabError,
              'space in indentation, but policy is :tabs ' \
              '(mixed tabs and spaces are ambiguous)')
          end
        end

        mode == :forbid ? :spaces : mode
      end

      def assign_widths(lines, mode)
        lines.each do |line|
          line.width =
            mode == :tabs ? line.indent.count("\t") : line.indent.length
        end
      end

      # Computes depth and the layout event of every line, validating that
      # dedents land exactly on a previously established level.
      #
      def assign_structure(lines)
        stack = []
        lines.each_with_index do |line, index|
          if index.zero?
            stack.push(line.width)
            line.event = :same
          elsif line.width > stack.last
            stack.push(line.width)
            line.event = :enter
          elsif line.width == stack.last
            line.event = :same
          else
            stack.pop while stack.length > 1 && line.width < stack.last
            if line.width != stack.last
              fail_at(line, DedentError,
                "inconsistent dedent to width #{line.width}, " \
                'no enclosing level has this indentation')
            end
            line.event = :exit
          end
          line.depth = stack.length - 1
        end
      end

      def fail_at(line, klass, message)
        line_no = @source[0...line.offset].count("\n") + 1
        raise klass, "#{message} (line #{line_no})"
      end
    end

    # Per-parse layout state: the analysed lines plus the stack of
    # indentation levels the parse is currently inside. One machine exists
    # per (parse, layout factory) pair, so separate parses never interfere.
    #
    class Machine
      attr_reader :lines, :base_width, :stack

      def initialize(source, options)
        @source = source
        @comment = options[:comment]
        analyzer = Analyzer.new(source, **options)
        @lines, @base_width = analyzer.analyze
        @stack = []
      end

      # Length of the analysed source in bytes.
      #
      def source_length
        @source.bytesize
      end

      # True when everything from the given byte position to the end of
      # the input is skippable: whitespace and whole line comments only.
      #
      def skippable_tail?(bytepos)
        @source.byteslice(bytepos..).each_line.all? do |text|
          stripped = text.strip
          stripped.empty? || comment_line?(stripped)
        end
      end

      # The significant line the given byte position belongs to (the last
      # line whose content starts at or before the position).
      #
      def line_at(bytepos)
        idx = @lines.bsearch_index { |line| line.offset > bytepos }
        idx = idx ? idx - 1 : @lines.length - 1
        idx >= 0 ? @lines[idx] : nil
      end

      # The first significant line starting after the given byte position,
      # or nil at end of input.
      #
      def next_line(bytepos)
        idx = @lines.bsearch_index { |line| line.offset > bytepos }
        idx ? @lines[idx] : nil
      end

      # Consumes input up to the given byte offset (the "gap": rest of the
      # current line, newlines, blank lines, comment lines and the
      # indentation of the next line) and returns it as a slice.
      #
      def consume_to(source, target)
        char_count = @source.byteslice(source.bytepos...target).length
        source.consume(char_count)
      end

      def push(width)
        @stack.push(width)
      end

      def pop
        @stack.pop
      end

      def current_level
        @stack.empty? ? @base_width : @stack.last
      end

      # Restores the stack to a previous depth; used to make layout state
      # participate in parslet's backtracking.
      #
      def restore(depth)
        @stack.slice!(depth..) if @stack.length > depth
      end

      private

      def comment_line?(stripped)
        case @comment
        when nil then false
        when String then stripped.start_with?(@comment)
        when Regexp then !!@comment.match?(stripped)
        else false
        end
      end
    end

    # Common base class for the layout atoms. Layout atoms are never cached
    # by the packrat cache, since their behaviour depends on the machine
    # state in addition to the input position.
    #
    class Atom < Parslet::Atoms::Base
      def initialize(factory)
        super()
        @factory = factory
      end

      def cached?
        false
      end

      private

      def machine(source, context)
        @factory.machine_for(source, context)
      end

      # Must be called whenever the layout stack was mutated: results that
      # were packrat-cached under the old stack may be invalid now.
      #
      def state_changed(context)
        context.reset_cache!
      end
    end

    # "enter": consumes the gap to the next significant line, requiring it
    # to be indented deeper than the current line. Pushes the new level
    # onto the layout stack.
    #
    class Enter < Atom
      def try(source, context, _consume_all)
        machine = machine(source, context)
        line = machine.next_line(source.bytepos)
        return context.err(self, source, 'expected a more deeply indented line') \
          unless line

        current = machine.line_at(source.bytepos)
        reference = current ? current.width : -1
        return context.err(self, source, 'expected a more deeply indented line') \
          unless line.width > reference

        slice = machine.consume_to(source, line.offset)
        machine.push(line.width)
        state_changed(context)
        succ(slice)
      end

      def to_s_inner(_prec)
        'LAYOUT_ENTER'
      end
    end

    # "same": consumes the gap to the next significant line, requiring it
    # to be at the current indentation level.
    #
    class Same < Atom
      def try(source, context, _consume_all)
        machine = machine(source, context)
        line = machine.next_line(source.bytepos)
        return context.err(self, source, 'expected a line at the same indentation') \
          unless line
        return context.err(self, source, 'expected a line at the same indentation') \
          unless line.width == machine.current_level

        succ(machine.consume_to(source, line.offset))
      end

      def to_s_inner(_prec)
        'LAYOUT_SAME'
      end
    end

    # "exit": zero width event that succeeds when the current block ends
    # here, i.e. when the next significant line is less indented than the
    # current level, or when the input is exhausted (blocks left open at
    # end of input are closed implicitly). Pops one level. Consecutive
    # dedents are handled by one exit per nested block.
    #
    class Exit < Atom
      def try(source, context, _consume_all)
        machine = machine(source, context)
        return context.err(self, source, 'no indentation level to leave') \
          if machine.stack.empty?

        line = machine.next_line(source.bytepos)
        if line && line.width >= machine.current_level
          return context.err(self, source, 'expected the end of an indented block')
        end

        machine.pop
        state_changed(context)
        succ(nil)
      end

      def to_s_inner(_prec)
        'LAYOUT_EXIT'
      end
    end

    # Consumes everything up to the first significant line: leading blank
    # lines, whole line comments and the first line's indentation. Use at
    # the beginning of a layout grammar. Succeeds (consuming the rest of
    # the input) even when there are no significant lines at all.
    #
    class Start < Atom
      def try(source, context, _consume_all)
        machine = machine(source, context)
        line = machine.lines.first
        target = line ? line.offset : machine.source_length
        succ(machine.consume_to(source, target))
      end

      def to_s_inner(_prec)
        'LAYOUT_START'
      end
    end

    # Consumes the skippable tail of the input (the rest of the current
    # line, trailing blank lines and whole line comments) up to end of
    # input. Fails when anything else remains. Use at the end of a layout
    # grammar, so that trailing whitespace does not make the parse fail.
    #
    class Finish < Atom
      def try(source, context, _consume_all)
        machine = machine(source, context)
        unless machine.skippable_tail?(source.bytepos)
          return context.err(self, source, 'expected end of input')
        end

        succ(machine.consume_to(source, machine.source_length))
      end

      def to_s_inner(_prec)
        'LAYOUT_FINISH'
      end
    end

    # Makes a composition of layout events transactional: if the inner
    # parslet fails, the layout stack is restored to the depth it had on
    # entry, so ordinary parslet backtracking (choice, maybe, repetition)
    # also restores layout state. The input position itself is rewound by
    # parslet as usual.
    #
    class Scope < Atom
      def initialize(factory, parslet)
        super(factory)
        @parslet = parslet
      end

      def try(source, context, consume_all)
        machine = machine(source, context)
        depth = machine.stack.length

        success, = result = @parslet.apply(source, context, consume_all)
        unless success
          machine.restore(depth)
          state_changed(context)
        end
        result
      end

      def to_s_inner(prec)
        "layout_scope(#{@parslet.to_s(prec)})"
      end
    end

    # Factory for the layout atoms, holding the analysis options. Create
    # one per grammar (usually as a constant) and use it inside rules:
    #
    #   L = Parslet::Layout.new(comment: '#')
    #   rule(:nested) { L.scope(L.enter >> items >> L.exit) }
    #
    class Factory
      def initialize(comment: nil, tabs: :auto,
                     brackets: Analyzer::DEFAULT_BRACKETS,
                     quotes: Analyzer::DEFAULT_QUOTES)
        @options = {
          comment: comment, tabs: tabs, brackets: brackets, quotes: quotes
        }
      end

      # "enter" event atom.
      def enter
        Enter.new(self)
      end

      # "same" event atom.
      def same
        Same.new(self)
      end

      # "exit" event atom.
      def exit
        Exit.new(self)
      end

      # Skips to the first significant line; use at the start of a grammar.
      def start
        Start.new(self)
      end

      # Consumes the skippable tail; use at the end of a grammar.
      def finish
        Finish.new(self)
      end

      # Wraps a parslet so that layout state is restored when it fails.
      def scope(parslet=nil, &block)
        Scope.new(self, parslet || block.call)
      end

      # Ready-made transactional block: a head line, then an indented
      # sequence of items at one deeper level.
      #
      #   L.block(head, item)
      #   # => head >> scope(enter >> item >> (same >> item).repeat >> exit)
      #
      def block(head, item)
        head >> scope(enter >> item >> (same >> item).repeat >> exit)
      end

      # Returns the per-parse machine for this factory, analysing the
      # source on first use. The tab policy is therefore fixed exactly once
      # per parse.
      #
      def machine_for(source, context)
        store = context.instance_variable_get(:@parslet_layout_machines)
        unless store
          store = {}
          context.instance_variable_set(:@parslet_layout_machines, store)
        end
        store[object_id] ||= Machine.new(source.string, @options)
      end
    end
  end
end
