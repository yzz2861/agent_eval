# frozen_string_literal: true

require "liquid/source_map/region_scanner"
require "liquid/source_map/markup_scanner"

module Liquid
  # A structural, byte-offset aware view of a parsed template used to perform
  # local source edits such as renaming a variable inside one lexical scope.
  #
  # A source map is built independently of the rendering AST on demand, so the
  # normal parse/render hot path is untouched. It resolves every variable
  # reference to a binding (taking loop-variable shadowing into account) and
  # records exact byte spans. That lets SourceEditor touch only the bytes that
  # belong to a chosen binding while leaving everything else, including raw
  # blocks, comments, strings and whitespace, byte-identical.
  class SourceMap
    # A single lexical binding and every occurrence that resolves to it.
    class Binding
      attr_reader :name, :scope_frame, :occurrences, :loop_binding

      def initialize(name, scope_frame, loop_binding: false)
        @name = name
        @scope_frame = scope_frame
        @loop_binding = loop_binding
        @occurrences = []
      end
    end

    # One textual mention of a variable name. `kind` is :binding for the
    # declaration site (loop variable, assign target, ...) and :reference
    # elsewhere.
    Occurrence = Struct.new(:name, :start_byte, :end_byte, :binding, :kind, keyword_init: true)

    # Internal lexical frame. Only loop bodies introduce a fresh frame; other
    # blocks (if/case/...) share their enclosing frame because Liquid's
    # assignment scope is the surrounding context, not the control block.
    Frame = Struct.new(:parent, :bindings, :loop, :start_byte, :end_byte, keyword_init: true)

    LOOP_TAGS    = { 'for' => 'endfor', 'tablerow' => 'endtablerow' }.freeze
    COUNTER_TAGS = %w[increment decrement].freeze
    PREDEFINED   = %w[forloop tablerowloop].freeze

    attr_reader :source, :regions, :occurrences

    def self.parse(source, environment: Environment.default)
      new(source, environment: environment)
    end

    def initialize(source, environment: Environment.default)
      @source = source.to_s.to_str
      @environment = environment
      @regions = RegionScanner.scan(@source)
      @occurrences = []
      @globals = {}
      analyze
    end

    # Reassembles the source from the recorded regions. Used as a byte
    # exactness invariant.
    def reconstruct
      @regions.map { |region| region.slice(@source) }.join
    end

    def byte_exact?
      reconstruct == @source
    end

    # Returns the Occurrence located at (or enclosing) the given byte offset,
    # or nil when the offset is outside a variable name.
    def occurrence_at(byte_offset)
      @occurrences.bsearch do |occurrence|
        if byte_offset < occurrence.start_byte then 1
        elsif byte_offset >= occurrence.end_byte then -1
        else 0 end
      end
    end

    # Finds the binding for `name` visible at a byte offset, honoring loop
    # shadowing. With scope: :document only the root frame is considered.
    def binding_for(name, at_byte = nil, scope: :innermost)
      frame = scope == :document ? root_frame : frame_at(at_byte || 0)
      lookup_binding(name, frame)
    end

    # Every binding with this name across all scopes (root and loop frames).
    def bindings_named(name)
      result = all_bindings.select { |binding| binding.name == name }
      result.uniq
    end

    def root_frame
      @root_frame
    end

    # Innermost lexical frame enclosing a byte offset.
    def frame_at(byte_offset)
      innermost = @root_frame
      @frames.each do |frame|
        next unless frame.end_byte
        innermost = frame if frame.start_byte <= byte_offset && byte_offset < frame.end_byte
      end
      innermost
    end

    private

    def analyze
      @root_frame = Frame.new(parent: nil, bindings: {}, loop: false, start_byte: 0, end_byte: nil)
      @root_frame.end_byte = @source.bytesize
      @frames = [@root_frame]
      # Entries of [frame, closing_tag_name] for currently open loops.
      @loop_stack = []
      # Byte ranges already occupied by declaration occurrences, so the same
      # name is not also recorded as a reference.
      @declaration_spans = {}

      logical_regions.each do |region|
        case region.kind
        when RegionScanner::TAG
          process_tag(region)
        when RegionScanner::VARIABLE
          scan_variable(region)
        end
      end

      @occurrences.sort_by!(&:start_byte)
    end

    # Expands a `{% liquid %}` block into one virtual tag region per inner
    # line so its tags participate in binding and scope analysis. The virtual
    # regions carry absolute byte offsets into the real source.
    def logical_regions
      expanded = []
      @regions.each do |region|
        if region.kind == RegionScanner::TAG && region.tag_name == 'liquid'
          expand_liquid_region(region, expanded)
        else
          expanded << region
        end
      end
      expanded
    end

    LIQUID_LINE = /\A\s*(?<name>#{TagName})(?<rest>\s+.*?)?\z/om

    def expand_liquid_region(region, expanded)
      markup_start = region.markup_start_byte || region.start_byte
      markup_end   = region.markup_end_byte || region.end_byte
      markup = @source.byteslice(markup_start, markup_end - markup_start)

      pos = markup_start
      markup.each_line do |line|
        line_start = pos
        line_end = pos + line.bytesize
        pos = line_end

        if (match = LIQUID_LINE.match(line.chomp("\n")))
          name = match[:name]
          rest_range = match[:rest]
          virtual = RegionScanner::Region.new(
            kind: RegionScanner::TAG,
            start_byte: line_start,
            end_byte: line_end,
            tag_name: name,
          )
          if rest_range
            # match offsets are relative to the (possibly newline-stripped) line;
            # account for the leading whitespace that begins the match.
            virtual.markup_start_byte = line_start + match.begin(:rest) + 1
            virtual.markup_end_byte   = line_start + match.end(:rest)
          else
            virtual.markup_start_byte = line_end
            virtual.markup_end_byte   = line_end
          end
          expanded << virtual
        end
      end
    end

    def process_tag(region)
      name = region.tag_name

      # A loop-closing tag ends the inner-most frame.
      if (entry = @loop_stack.last) && entry[1] == name
        frame, = @loop_stack.pop
        frame.end_byte = region.end_byte
        return
      end

      if LOOP_TAGS.key?(name)
        open_loop(region, LOOP_TAGS[name])
        return
      end

      process_declaration(region)
      scan_references(region, current_frame)
    end

    def open_loop(region, close_name)
      frame = Frame.new(parent: current_frame, bindings: {}, loop: true,
                        start_byte: region.start_byte, end_byte: nil)
      @frames << frame
      @loop_stack << [frame, close_name]

      # The first identifier in `for item in ...` is the loop variable and is
      # in scope from the opening tag onward.
      if (target = first_id(region))
        binding = Binding.new(target.value, frame, loop_binding: true)
        frame.bindings[target.value] = binding
        add_occurrence(binding, target.start_byte, target.end_byte, :binding)
      end

      # The collection expression is evaluated in the surrounding frame, so the
      # loop variable never shadows its own collection on the opening tag.
      scan_references(region, frame.parent || frame)
    end

    def process_declaration(region)
      name = region.tag_name
      tokens = markup_tokens(region)

      case name
      when 'assign'
        id_index = tokens.index { |token| token.type == :id }
        return unless id_index && tokens[id_index + 1]&.type == :equals
        declare(tokens[id_index], @root_frame)
      when 'capture'
        target = tokens.find { |token| token.type == :id }
        declare(target, @root_frame) if target
      when *COUNTER_TAGS
        target = tokens.find { |token| token.type == :id }
        declare(target, current_frame) if target
      end
    end

    def declare(token, frame)
      binding = frame.bindings[token.value] ||= Binding.new(token.value, frame)
      add_occurrence(binding, token.start_byte, token.end_byte, :binding)
    end

    def scan_variable(region)
      return if region.markup_start_byte.nil?
      candidates = MarkupScanner.scan(markup_of(region), region.markup_start_byte)
      candidates.each do |token|
        next if PREDEFINED.include?(token.value)
        reference(token, current_frame)
      end
    end

    # Records reference occurrences inside a tag's markup.
    def scan_references(region, frame)
      return if region.tag_name == '#' || region.markup_start_byte.nil?

      candidates = MarkupScanner.scan(markup_of(region), region.markup_start_byte)
      aliased_tag = %w[render include].include?(region.tag_name)
      tokens = markup_tokens(region)

      candidates.each do |token|
        next if @declaration_spans.key?(token.start_byte)
        next if PREDEFINED.include?(token.value)

        if aliased_tag
        # `render 'x' with collection as alias`: the alias is introduced into
        # the snippet, not this template.
          previous = tokens[tokens.index { |t| t.start_byte == token.start_byte } - 1]
          next if previous&.type == :id && previous.value == 'as'
        end

        reference(token, frame)
      end
    end

    def reference(token, frame)
      binding = resolve(token.value, frame)
      add_occurrence(binding, token.start_byte, token.end_byte, :reference)
    end

    # Resolves a name against the live frame chain. Unresolved names are
    # grouped under a synthetic root binding so outer references are renamed
    # together while correctly stopping at a shadowing loop binding.
    def resolve(name, frame)
      cursor = frame
      while cursor
        if (binding = cursor.bindings[name])
          return binding
        end
        cursor = cursor.parent
      end
      @globals[name] ||= Binding.new(name, @root_frame)
    end

    def lookup_binding(name, frame)
      cursor = frame
      while cursor
        if (binding = cursor.bindings[name])
          return binding
        end
        cursor = cursor.parent
      end
      @globals[name]
    end

    def all_bindings
      seen = {}.compare_by_identity
      list = []
      @frames.each do |frame|
        frame.bindings.each_value do |binding|
          next if seen[binding]
          seen[binding] = true
          list << binding
        end
      end
      @globals.each_value do |binding|
        next if seen[binding]
        seen[binding] = true
        list << binding
      end
      list
    end

    def current_frame
      @loop_stack.last&.first || @root_frame
    end

    def add_occurrence(binding, start_byte, end_byte, kind)
      occurrence = Occurrence.new(
        name: binding.name, start_byte: start_byte, end_byte: end_byte,
        binding: binding, kind: kind,
      )
      binding.occurrences << occurrence
      @occurrences << occurrence
      @declaration_spans[start_byte] = true if kind == :binding
    end

    def markup_tokens(region)
      MarkupScanner.tokenize(markup_of(region), region.markup_start_byte)
    end

    def first_id(region)
      markup_tokens(region).find { |token| token.type == :id }
    end

    def markup_of(region)
      region.markup(@source) || ''
    end
  end
end
