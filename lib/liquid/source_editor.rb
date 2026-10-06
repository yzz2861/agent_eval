# frozen_string_literal: true

module Liquid
  # Liquid::SourceEditor is a source-span-preserving parse mode for Liquid
  # templates, paired with a local edit interface.
  #
  # Liquid::Template.parse compiles a template into an executable node tree
  # and discards the source. SourceEditor instead analyzes the template
  # source and records the exact byte span of every variable definition and
  # every variable reference, along with the binding relation between them
  # (which definition each reference resolves to, taking loop variable
  # shadowing and dynamic `[expression]` access into account).
  #
  # On top of that analysis it offers local, surgical edits — most notably
  # renaming a variable "by binding": a definition plus exactly the
  # references that resolve to it within the scope where it is visible.
  # Bytes not covered by an edit are copied verbatim, so CRLF line endings,
  # whitespace control hyphens (`{%- ... -%}`) and irregular indentation
  # are preserved. Text inside strings, `comment`/`raw`/`doc` blocks and
  # inline (`{% # ... %}`) comments is never treated as a variable
  # reference.
  #
  #   editor = Liquid::SourceEditor.parse("{% for item in items %}{{ item }}{% endfor %}")
  #   editor.rename_variable("item", "product")
  #   editor.apply # => "{% for product in items %}{{ product }}{% endfor %}"
  #   editor.render("items" => [1, 2]) # re-parses the edited source and renders it
  #
  class SourceEditor
    # Raised when a newly added edit overlaps an edit that was added before.
    class OverlappingEditError < Liquid::Error; end

    # Raised when a variable would be renamed to an invalid identifier.
    class InvalidVariableNameError < Liquid::Error; end

    # A lexical scope inside a template. Scopes nest: the root scope covers
    # the whole template and every `for`/`tablerow` loop introduces a child
    # scope spanning its body. (`if`/`case`/`capture` etc. do not open new
    # scopes, matching Liquid's runtime semantics.)
    #
    # Offsets are byte offsets into the original template source.
    class Scope
      attr_reader :parent, :kind, :start_offset, :bindings
      attr_accessor :end_offset

      def initialize(parent:, kind:, start_offset:)
        @parent       = parent
        @kind         = kind
        @start_offset = start_offset
        @end_offset   = nil
        @bindings     = []
      end

      def root?
        @parent.nil?
      end
    end

    # A variable definition site: `assign`, `capture`, a `for`/`tablerow`
    # loop variable, or the implicit counter shared by `increment` and
    # `decrement` (which live in their own namespace).
    #
    # `start_offset`/`end_offset` are the byte span of the defined name in
    # the source. They are nil for implicit counter bindings, which have no
    # definition site of their own.
    class Binding
      attr_reader :name, :kind, :namespace, :scope, :start_offset, :end_offset

      def initialize(name:, kind:, namespace:, scope:, start_offset:, end_offset:)
        @name         = name
        @kind         = kind
        @namespace    = namespace
        @scope        = scope
        @start_offset = start_offset
        @end_offset   = end_offset
      end

      def loop_variable?
        @kind == :for || @kind == :tablerow
      end
    end

    # A single use of a variable in the template source, with the byte span
    # of its name and the binding it resolves to (nil when it resolves to
    # the template's environment rather than to a definition).
    class Reference
      attr_reader :name, :namespace, :scope, :start_offset, :end_offset
      attr_accessor :binding

      def initialize(name:, namespace:, scope:, start_offset:, end_offset:)
        @name         = name
        @namespace    = namespace
        @scope        = scope
        @start_offset = start_offset
        @end_offset   = end_offset
        @binding      = nil
      end
    end

    Edit = Struct.new(:start_offset, :end_offset, :replacement)

    IDENTIFIER_PATTERN = /\A[a-zA-Z_][\w-]*\z/
    LITERAL_WORDS      = ["true", "false", "nil", "null", "empty", "blank"].freeze

    class << self
      # Parses +source+ in source-span-preserving mode and returns an editor
      # for it. +template_options+ are passed through to Liquid::Template.parse
      # (e.g. error_mode:, environment:) which is used to validate the source
      # up front and to re-validate it after edits are applied.
      def parse(source, **template_options)
        new(source, **template_options)
      end
    end

    attr_reader :source, :edits

    def initialize(source, **template_options)
      @source           = source.to_s.to_str
      @template_options = template_options
      @edits            = []
      validate_source!(@source)
      analyze!
    end

    def root_scope
      @analyzer.root_scope
    end

    def bindings
      @analyzer.bindings
    end

    def references
      @analyzer.references
    end

    def bindings_named(name, namespace: :variable)
      bindings.select { |binding| binding.namespace == namespace && binding.name == name }
    end

    # Renames a variable by binding relationship.
    #
    # With no +scope+, every binding called +old_name+ (in +namespace+) is
    # renamed together with the references that resolve to it; references
    # that resolve to the template environment are renamed as well. Loop
    # variables that shadow an outer variable of the same name keep their
    # own binding, so a global rename stays consistent.
    #
    # +scope+ may be a Binding (rename just that definition and the
    # references bound to it) or a Scope (rename the bindings of that name
    # defined in the scope, plus their bound references).
    #
    # Returns the number of edits added.
    def rename_variable(old_name, new_name, scope: nil, namespace: :variable)
      validate_variable_name!(new_name)

      targets = rename_targets(old_name, scope, namespace)
      targets.each { |start_offset, end_offset| add_edit(start_offset, end_offset, new_name) }
      targets.size
    end

    # Renames a single binding (a definition plus the references bound to
    # it). Equivalent to rename_variable(binding.name, new_name, scope: binding).
    def rename_binding(binding, new_name)
      rename_variable(binding.name, new_name, scope: binding, namespace: binding.namespace)
    end

    # Low-level local edit: replaces the byte range
    # [start_offset, end_offset) of the original source with +replacement+.
    # Raises OverlappingEditError if the range overlaps a previously added
    # edit.
    def add_edit(start_offset, end_offset, replacement)
      start_offset = Integer(start_offset)
      end_offset   = Integer(end_offset)

      if start_offset < 0 || end_offset < start_offset || end_offset > @source.bytesize
        raise ArgumentError, "edit range [#{start_offset}, #{end_offset}) is out of bounds for source of #{@source.bytesize} bytes"
      end

      @edits.each do |edit|
        next unless edits_overlap?(start_offset, end_offset, edit.start_offset, edit.end_offset)

        raise OverlappingEditError,
          "edit [#{start_offset}, #{end_offset}) overlaps existing edit [#{edit.start_offset}, #{edit.end_offset})"
      end

      @edits << Edit.new(start_offset, end_offset, replacement.to_s)
      self
    end

    # Applies all edits and returns the new source. Bytes outside the edited
    # ranges are copied verbatim. The result is re-parsed with
    # Liquid::Template.parse, so a Liquid::SyntaxError is raised if an edit
    # produced an invalid template.
    def apply
      output   = @source.byteslice(0, 0)
      position = 0

      @edits.sort_by(&:start_offset).each do |edit|
        output << @source.byteslice(position, edit.start_offset - position) if edit.start_offset > position
        output << edit.replacement
        position = edit.end_offset
      end
      output << @source.byteslice(position, @source.bytesize - position)

      validate_source!(output)
      output
    end

    # Like #apply, but replaces the editor's source with the result and
    # re-runs the span analysis, so editing can continue on the new source.
    def apply!
      @source = apply
      @edits  = []
      analyze!
      self
    end

    # Applies the edits, re-parses the resulting template and renders it,
    # validating the edited template against real data. Arguments are
    # forwarded to Liquid::Template#render (assigns, render options, ...).
    def render(*args)
      Liquid::Template.parse(apply, **@template_options).render(*args)
    end

    private

    def validate_source!(source)
      Liquid::Template.parse(source, **@template_options)
    end

    def analyze!
      @analyzer = SpanAnalyzer.new(@source).analyze
    end

    def validate_variable_name!(name)
      unless name.is_a?(String) && name.match?(IDENTIFIER_PATTERN)
        raise InvalidVariableNameError, "invalid variable name: #{name.inspect}"
      end

      return unless LITERAL_WORDS.include?(name)

      raise InvalidVariableNameError, "cannot rename to reserved literal: #{name.inspect}"
    end

    def rename_targets(old_name, scope, namespace)
      case scope
      when nil
        global_rename_targets(old_name, namespace)
      when Binding
        binding_rename_targets(scope)
      when Scope
        scope.bindings.each_with_object([]) do |binding, targets|
          next unless binding.namespace == namespace && binding.name == old_name

          targets.concat(binding_rename_targets(binding))
        end
      else
        raise ArgumentError, "scope must be a Liquid::SourceEditor::Binding or Liquid::SourceEditor::Scope"
      end
    end

    def global_rename_targets(old_name, namespace)
      renamed = bindings_named(old_name, namespace: namespace)
      targets = renamed.map { |binding| [binding.start_offset, binding.end_offset] if binding.start_offset }
      references.each_with_object(targets) do |reference, acc|
        next unless reference.namespace == namespace && reference.name == old_name

        if reference.binding.nil?
          acc << [reference.start_offset, reference.end_offset] if namespace == :variable
        elsif renamed.include?(reference.binding)
          acc << [reference.start_offset, reference.end_offset]
        end
      end
      targets.compact
    end

    def binding_rename_targets(binding)
      targets = []
      targets << [binding.start_offset, binding.end_offset] if binding.start_offset
      references.each do |reference|
        targets << [reference.start_offset, reference.end_offset] if reference.binding.equal?(binding)
      end
      targets
    end

    def edits_overlap?(start_a, end_a, start_b, end_b)
      if start_a == end_a && start_b == end_b
        start_a == start_b
      elsif start_a == end_a
        start_b <= start_a && start_a < end_b
      elsif start_b == end_b
        start_a <= start_b && start_b < end_a
      else
        start_a < end_b && start_b < end_a
      end
    end

    # Performs the source-span-preserving analysis of a template source:
    # tokenizes the source, finds every variable definition and reference
    # (with byte spans) and resolves references to bindings through the
    # lexical scope tree.
    #
    # @api private
    class SpanAnalyzer
      TAG_TOKEN       = /\A\{%-?\s*(#|\w+)\s*/om
      LIQUID_TAG_LINE = /\A\s*(#|\w+)\s*(.*?)\z/om
      IDENTIFIER      = /[a-zA-Z_][\w-]*\??/
      STATIC_SEGMENT  = /[\w-]+\??/

      attr_reader :root_scope, :bindings, :references

      def initialize(source)
        @source = source
        @root_scope = Scope.new(parent: nil, kind: :root, start_offset: 0)
        @root_scope.end_offset = source.bytesize
        @scope_stack      = [@root_scope]
        @bindings         = []
        @references       = []
        @counter_bindings = {}
      end

      def analyze
        tokens = template_tokens

        index = 0
        while index < tokens.length
          token, token_offset = tokens[index]
          if token.start_with?("{{")
            scan_variable_token(token, token_offset)
          elsif token.start_with?("{%")
            index = scan_tag_token(tokens, index)
          end
          index += 1
        end
        self
      end

      private

      def template_tokens
        tokens    = []
        offset    = 0
        tokenizer = Liquid::Tokenizer.new(source: @source, string_scanner: StringScanner.new(""))
        while (token = tokenizer.shift)
          tokens << [token, offset]
          offset += token.bytesize
        end
        tokens
      end

      def scan_variable_token(token, token_offset)
        start = 2
        start = 3 if token.getbyte(2) == 45 # '-'
        parse_end = token.bytesize - 3
        parse_end -= 1 if token.getbyte(parse_end) == 45 # '-'
        length = parse_end - start + 1
        return if length <= 0

        scan_output(token.byteslice(start, length), token_offset + start)
      end

      def scan_tag_token(tokens, index)
        token, token_offset = tokens[index]
        match = TAG_TOKEN.match(token)
        return index unless match

        tag_name     = match[1]
        markup_start = match.end(0)
        markup_end   = token.bytesize - 2
        markup_end  -= 1 if token.getbyte(markup_end - 1) == 45 # '-'
        markup = token.byteslice(markup_start, markup_end - markup_start) || ""

        case tag_name
        when "raw"
          return skip_to_end_tag(tokens, index, "endraw")
        when "doc"
          return skip_to_end_tag(tokens, index, "enddoc")
        when "comment"
          return skip_comment_body(tokens, index)
        when "liquid"
          scan_liquid_tag(markup, token_offset + markup_start)
          return index
        end

        handle_tag(tag_name, markup, token_offset + markup_start, token_offset, token_offset + token.bytesize)
        index
      end

      def handle_tag(tag_name, markup, markup_offset, token_start, token_end)
        case tag_name
        when "assign"
          scan_assign(markup, markup_offset)
        when "capture"
          scan_capture(markup, markup_offset)
        when "for"
          scan_loop(markup, markup_offset, :for, token_start)
        when "tablerow"
          scan_loop(markup, markup_offset, :tablerow, token_start)
        when "if", "unless", "elsif", "when"
          scan_condition(markup, markup_offset)
        when "case"
          scan_expression_in(markup, markup_offset)
        when "echo"
          scan_output(markup, markup_offset)
        when "cycle"
          scan_cycle(markup, markup_offset)
        when "increment", "decrement"
          scan_counter(markup, markup_offset)
        when "render", "include"
          scan_render(markup, markup_offset)
        when "endfor", "endtablerow"
          close_scope(token_end)
        end
        # Everything else (break/continue/else/#/ifchanged, custom tags and
        # the end tags of non-scoping blocks) carries no variable references.
      end

      def skip_to_end_tag(tokens, index, end_tag_name)
        cursor = index + 1
        while cursor < tokens.length
          token, = tokens[cursor]
          if token.start_with?("{%") && (match = TAG_TOKEN.match(token)) && match[1] == end_tag_name
            return cursor
          end

          cursor += 1
        end
        tokens.length
      end

      def skip_comment_body(tokens, index)
        depth  = 1
        cursor = index + 1
        while cursor < tokens.length
          token, = tokens[cursor]
          if token.start_with?("{%") && (match = TAG_TOKEN.match(token))
            case match[1]
            when "raw"
              cursor = skip_to_end_tag(tokens, cursor, "endraw")
            when "comment"
              depth += 1
            when "endcomment"
              depth -= 1
              return cursor if depth.zero?
            end
          end

          cursor += 1
        end
        tokens.length
      end

      def scan_liquid_tag(markup, markup_offset)
        lines  = []
        offset = 0
        markup.split("\n", -1).each do |line|
          lines << [line, markup_offset + offset]
          offset += line.bytesize + 1
        end

        index = 0
        while index < lines.length
          line, line_offset = lines[index]
          if (match = LIQUID_TAG_LINE.match(line))
            tag_name           = match[1]
            line_markup        = match[2]
            line_markup_offset = line_offset + match.begin(2)

            case tag_name
            when "raw"
              index = skip_lines_to_end_tag(lines, index, "endraw")
            when "doc"
              index = skip_lines_to_end_tag(lines, index, "enddoc")
            when "comment"
              index = skip_comment_lines(lines, index)
            when "liquid"
              scan_liquid_tag(line_markup, line_markup_offset)
            else
              handle_tag(tag_name, line_markup, line_markup_offset, line_offset, line_offset + line.bytesize)
            end
          end
          index += 1
        end
      end

      def skip_lines_to_end_tag(lines, index, end_tag_name)
        cursor = index + 1
        while cursor < lines.length
          match = LIQUID_TAG_LINE.match(lines[cursor].first)
          return cursor if match && match[1] == end_tag_name

          cursor += 1
        end
        lines.length
      end

      def skip_comment_lines(lines, index)
        depth  = 1
        cursor = index + 1
        while cursor < lines.length
          if (match = LIQUID_TAG_LINE.match(lines[cursor].first))
            case match[1]
            when "raw"
              cursor = skip_lines_to_end_tag(lines, cursor, "endraw")
            when "comment"
              depth += 1
            when "endcomment"
              depth -= 1
              return cursor if depth.zero?
            end
          end

          cursor += 1
        end
        lines.length
      end

      def scan_assign(markup, base_offset)
        scanner = new_scanner(markup)
        scanner.skip(/\s*/)
        name_start = scanner.pos
        name       = scanner.scan(IDENTIFIER)
        return unless name

        name_end = scanner.pos
        scanner.skip(/\s*/)
        return unless scanner.scan(/=/)

        scan_expression(scanner, base_offset)
        scan_filters(scanner, base_offset)
        register_binding(name, :assign, base_offset + name_start, base_offset + name_end)
      end

      def scan_capture(markup, base_offset)
        scanner = new_scanner(markup)
        scanner.skip(/\s*/)
        name_start = scanner.pos
        return unless (name = scanner.scan(IDENTIFIER))

        register_binding(name, :capture, base_offset + name_start, base_offset + scanner.pos)
      end

      def scan_loop(markup, base_offset, kind, scope_start)
        scanner = new_scanner(markup)
        scanner.skip(/\s*/)
        name_start = scanner.pos
        name       = scanner.scan(IDENTIFIER)
        return unless name

        name_end = scanner.pos
        scanner.skip(/\s*/)
        return unless scanner.scan(/in\b/)

        scan_expression(scanner, base_offset) # collection expression

        loop do
          scanner.skip(/\s*/)
          break if scanner.eos?

          if scanner.peek_byte == 44 # ','
            scanner.scan_byte
            next
          end

          attribute = scanner.scan(/[a-zA-Z_][\w-]*/)
          break unless attribute
          next if attribute == "reversed"

          scanner.skip(/\s*/)
          next unless scanner.scan(/:/)

          if attribute == "offset"
            scanner.skip(/\s*/)
            next if scanner.scan(/continue\b/) # `offset: continue` is a keyword
          end

          scan_expression(scanner, base_offset)
        end

        open_loop_scope(name, kind, base_offset + name_start, base_offset + name_end, scope_start)
      end

      def scan_condition(markup, base_offset)
        scanner = new_scanner(markup)
        loop do
          scanner.skip(/\s*/)
          break if scanner.eos?

          byte = scanner.peek_byte
          if byte == 44 # ','
            scanner.scan_byte
          elsif byte == 61 || byte == 33 || byte == 60 || byte == 62 # '=' '!' '<' '>'
            scanner.scan_byte
            following = scanner.peek_byte
            scanner.scan_byte if following == 61 || following == 62 # '=' '>'
          elsif scanner.scan(/and\b|or\b|contains\b/)
            # boolean/comparison operator
          else
            scan_expression(scanner, base_offset)
          end
        end
      end

      def scan_cycle(markup, base_offset)
        scanner = new_scanner(markup)
        scan_expression(scanner, base_offset)
        scanner.skip(/\s*/)
        if scanner.peek_byte == 58 # ':'
          scanner.scan_byte
          scan_expression(scanner, base_offset)
        end

        loop do
          scanner.skip(/\s*/)
          break unless scanner.peek_byte == 44 # ','

          scanner.scan_byte
          scan_expression(scanner, base_offset)
        end
      end

      def scan_counter(markup, base_offset)
        scanner = new_scanner(markup)
        scanner.skip(/\s*/)
        name_start = scanner.pos
        return unless (name = scanner.scan(IDENTIFIER))

        record_reference(name, base_offset + name_start, base_offset + scanner.pos, :counter)
      end

      def scan_render(markup, base_offset)
        scanner = new_scanner(markup)
        scanner.skip(/\s*/)
        byte = scanner.peek_byte
        if byte == 34 || byte == 39 # '"' '\''
          skip_string(scanner)
        else
          scan_expression(scanner, base_offset) # variable template name
        end

        loop do
          scanner.skip(/\s*/)
          break if scanner.eos?

          if scanner.peek_byte == 44 # ','
            scanner.scan_byte
            next
          end

          word = scanner.scan(/[a-zA-Z_][\w-]*/)
          break unless word

          case word
          when "with", "for"
            scan_expression(scanner, base_offset)
          when "as"
            scanner.skip(/\s*/)
            scanner.scan(/[a-zA-Z_][\w-]*/) # snippet-local alias
          else
            scanner.skip(/\s*/)
            next unless scanner.peek_byte == 58 # ':'

            scanner.scan_byte
            scan_expression(scanner, base_offset)
          end
        end
      end

      def scan_output(markup, base_offset)
        scanner = new_scanner(markup)
        scan_expression(scanner, base_offset)
        scan_filters(scanner, base_offset)
      end

      def scan_expression_in(markup, base_offset)
        scan_expression(new_scanner(markup), base_offset)
      end

      def scan_filters(scanner, base_offset)
        loop do
          scanner.skip(/\s*/)
          break unless scanner.peek_byte == 124 # '|'

          scanner.scan_byte
          scanner.skip(/\s*/)
          scanner.scan(IDENTIFIER) # filter name
          scanner.skip(/\s*/)
          next unless scanner.peek_byte == 58 # ':'

          scanner.scan_byte
          scan_filter_args(scanner, base_offset)
        end
      end

      def scan_filter_args(scanner, base_offset)
        loop do
          scanner.skip(/\s*/)
          break if scanner.eos? || scanner.peek_byte == 124 # '|'

          saved = scanner.pos
          if scanner.scan(IDENTIFIER)
            scanner.skip(/\s*/)
            if scanner.peek_byte == 58 # ':'
              scanner.scan_byte # keyword argument name
            else
              scanner.pos = saved # positional expression
            end
          end

          scan_expression(scanner, base_offset)
          scanner.skip(/\s*/)
          break unless scanner.peek_byte == 44 # ','

          scanner.scan_byte
        end
      end

      def scan_expression(scanner, base_offset)
        scanner.skip(/\s*/)
        return if scanner.eos?

        byte = scanner.peek_byte
        case byte
        when 34, 39 # '"' '\''
          skip_string(scanner)
        when 40 # '('
          scanner.scan_byte
          scan_expression(scanner, base_offset)
          scanner.skip(/\s*/)
          if scanner.scan(/\.\./)
            scan_expression(scanner, base_offset)
            scanner.skip(/\s*/)
          end
          scanner.scan_byte if scanner.peek_byte == 41 # ')'
        when 91 # '['
          scanner.scan_byte
          scan_expression(scanner, base_offset)
          scanner.skip(/\s*/)
          scanner.scan_byte if scanner.peek_byte == 93 # ']'
          scan_lookups(scanner, base_offset)
        else
          if byte == 45 || (byte >= 48 && byte <= 57) # '-' or digit
            scanner.scan(/-?\d+(\.\d+)?/)
          elsif (name = scanner.scan(IDENTIFIER))
            name_start = scanner.pos - name.bytesize
            unless literal_word?(name, scanner)
              record_reference(name, base_offset + name_start, base_offset + scanner.pos)
            end
            scan_lookups(scanner, base_offset)
          else
            scanner.scan_byte # stay robust on unexpected input
          end
        end
      end

      def scan_lookups(scanner, base_offset)
        loop do
          saved = scanner.pos
          scanner.skip(/\s*/)
          byte = scanner.peek_byte

          if byte == 46 # '.'
            if scanner.peek(2) == ".."
              scanner.pos = saved
              break
            end

            scanner.scan_byte
            scanner.skip(/\s*/)
            scanner.scan(STATIC_SEGMENT) # static key, not a reference
          elsif byte == 91 # '['
            scanner.scan_byte
            scanner.skip(/\s*/)
            inner = scanner.peek_byte
            if inner == 34 || inner == 39 # '"' '\''
              skip_string(scanner)
            elsif inner == 45 || (inner && inner >= 48 && inner <= 57) # '-' or digit
              scanner.scan(/-?\d+(\.\d+)?/)
            else
              scan_expression(scanner, base_offset) # dynamic access
            end
            scanner.skip(/\s*/)
            scanner.scan_byte if scanner.peek_byte == 93 # ']'
          else
            scanner.pos = saved
            break
          end
        end
      end

      def skip_string(scanner)
        quote = scanner.scan_byte
        scanner.skip(quote == 34 ? /[^"]*/ : /[^']*/)
        scanner.scan_byte # closing quote
      end

      def literal_word?(name, scanner)
        LITERAL_WORDS.include?(name) && !lookup_ahead?(scanner)
      end

      def lookup_ahead?(scanner)
        saved = scanner.pos
        scanner.skip(/\s*/)
        byte  = scanner.peek_byte
        ahead = if byte == 46 # '.'
          scanner.peek(2) != ".."
        else
          byte == 91 # '['
        end
        scanner.pos = saved
        ahead
      end

      def new_scanner(markup)
        StringScanner.new(markup)
      end

      def register_binding(name, kind, start_offset, end_offset)
        binding = Binding.new(
          name: name,
          kind: kind,
          namespace: :variable,
          scope: @scope_stack.last,
          start_offset: start_offset,
          end_offset: end_offset,
        )
        @scope_stack.last.bindings << binding
        @bindings << binding
        binding
      end

      def open_loop_scope(name, kind, name_start, name_end, scope_start)
        scope   = Scope.new(parent: @scope_stack.last, kind: kind, start_offset: scope_start)
        binding = Binding.new(
          name: name,
          kind: kind,
          namespace: :variable,
          scope: scope,
          start_offset: name_start,
          end_offset: name_end,
        )
        scope.bindings << binding
        @bindings << binding
        @scope_stack << scope
      end

      def close_scope(token_end)
        return if @scope_stack.length <= 1

        @scope_stack.pop.end_offset = token_end
      end

      def record_reference(name, start_offset, end_offset, namespace = :variable)
        reference = Reference.new(
          name: name,
          namespace: namespace,
          scope: @scope_stack.last,
          start_offset: start_offset,
          end_offset: end_offset,
        )
        reference.binding = resolve_binding(name, namespace)
        @references << reference
      end

      def resolve_binding(name, namespace)
        return counter_binding(name) if namespace == :counter

        scope = @scope_stack.last
        while scope
          found = scope.bindings.reverse_each.find { |binding| binding.name == name }
          return found if found

          scope = scope.parent
        end
        nil
      end

      def counter_binding(name)
        binding = @counter_bindings[name]
        return binding if binding

        binding = Binding.new(
          name: name,
          kind: :counter,
          namespace: :counter,
          scope: @root_scope,
          start_offset: nil,
          end_offset: nil,
        )
        @counter_bindings[name] = binding
        @bindings << binding
        binding
      end
    end

    private_constant :SpanAnalyzer
  end
end
