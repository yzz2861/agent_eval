# frozen_string_literal: true

require 'set'

module Liquid
  class StaticVariableAnalyzer
    DynamicSegment = Struct.new(:expression, :dependencies, :iteration, keyword_init: true) do
      def dynamic?
        true
      end

      def iteration?
        !!iteration
      end

      def inspect
        source = iteration? ? '*' : expression.inspect
        "#<Liquid::StaticVariableAnalyzer::DynamicSegment expression=#{source}>"
      end
    end

    LocalBinding = Struct.new(:path, :conditional, keyword_init: true) do
      def self.opaque(conditional: false)
        new(path: nil, conditional: conditional)
      end

      def opaque?
        path.nil?
      end

      def with_conditional(value)
        self.class.new(path: path, conditional: value)
      end
    end

    Reference = Struct.new(:path, :line_number, :conditional, keyword_init: true) do
      alias_method :line, :line_number

      def dynamic?
        path.any? { |segment| segment.respond_to?(:dynamic?) && segment.dynamic? }
      end

      def conditional?
        conditional
      end

      def inspect
        source = "path=#{path.inspect} line_number=#{line_number} conditional=#{conditional}"
        "#<Liquid::StaticVariableAnalyzer::Reference #{source}>"
      end
    end

    Result = Struct.new(
      :definite,
      :conditional,
      :dynamic,
      :unresolved_renders,
      :unresolved_includes,
      keyword_init: true,
    ) do
      alias_method :branch, :conditional

      def to_h
        {
          definite: definite,
          conditional: conditional,
          dynamic: dynamic,
          unresolved_renders: unresolved_renders,
          unresolved_includes: unresolved_includes,
        }
      end
    end

    Frame = Struct.new(:bindings, keyword_init: true) do
      def self.empty
        new(bindings: {})
      end

      def local?(name)
        bindings.key?(name)
      end

      def merge(other)
        names = bindings.keys | other.bindings.keys
        merged = names.each_with_object({}) do |name, result|
          own = bindings[name]
          foreign = other.bindings[name]
          result[name] = merge_bindings(own, foreign)
        end
        self.class.new(
          bindings: merged,
        )
      end

      private

      def merge_bindings(own, foreign)
        return mark_conditional(foreign) if own.nil?
        return mark_conditional(own) if foreign.nil?

        return own if own == foreign && own.none?(&:conditional)
        return Set[LocalBinding.opaque] if own.all?(&:opaque?) && foreign.all?(&:opaque?)
        mark_conditional(own | foreign)
      end

      def mark_conditional(bindings)
        Set.new(bindings.map { |binding| binding.with_conditional(true) })
      end
    end

    def self.analyze(template, render_resolver: nil, render_dependency_resolver: render_resolver)
      template = Template.parse(template, line_numbers: true) if template.is_a?(String)
      root = template.is_a?(Template) ? template.root : template
      new(root, render_resolver: render_dependency_resolver).analyze
    end

    def initialize(root, render_resolver: nil)
      @root = root
      @render_resolver = render_resolver
      @frames = [Frame.empty]
      @definite = []
      @conditional = []
      @dynamic = []
      @unresolved_renders = []
      @unresolved_includes = []
    end

    def analyze
      visit(@root)
      Result.new(
        definite: @definite,
        conditional: @conditional,
        dynamic: @dynamic,
        unresolved_renders: @unresolved_renders,
        unresolved_includes: @unresolved_includes,
      )
    end

    private

    def with_frame(locals)
      frame = Frame.empty
      locals.each do |name, path|
        frame.bindings[name] = path || Set[LocalBinding.opaque]
      end
      @frames.push(frame)
      yield
    ensure
      @frames.pop
    end

    def with_branch
      yield
      current_frame_dup
    end

    def current_frame_dup
      frame = @frames.pop
      Frame.new(
        bindings: frame.bindings.transform_values(&:dup),
      )
    ensure
      @frames.push(frame)
    end

    def restore_frame(frame)
      @frames.pop
      @frames.push(frame)
    end

    def merge_branch_frames(base, frames)
      merged = frames.reduce(base) do |result, frame|
        result.merge(frame)
      end
      restore_frame(merged)
    end

    def bind_local(name, definitely, path: nil)
      bindings = path.nil? ? Set[LocalBinding.opaque] : Set[LocalBinding.new(path: path, conditional: false)]
      @frames.last.bindings[name.to_s] =
        if definitely
          bindings
        else
          Set.new(bindings.map { |binding| binding.with_conditional(true) })
        end
    end

    def bind_local_paths(name, definitely, paths)
      if paths.nil? || paths.empty?
        bind_local(name, definitely)
        return
      end

      bindings = Set.new(paths.map { |path| LocalBinding.new(path: path, conditional: false) })
      @frames.last.bindings[name.to_s] =
        if definitely
          bindings
        else
          Set.new(bindings.map { |binding| binding.with_conditional(true) })
        end
    end

    def local_bindings(name)
      frame = @frames.reverse.find { |scope| scope.bindings.key?(name) }
      frame ? frame.bindings.fetch(name) : nil
    end

    def iteration_bindings(expression, line, possible)
      case expression
      when VariableLookup
        resolved = resolve_lookup_paths(
          expression,
          line,
          possible,
          visit_dependencies: true,
          include_binding_roots: true,
        )
        Set.new(resolved.map do |path, conditional|
          add_reference(path, line, conditional)
          LocalBinding.new(
            path: path + [DynamicSegment.new(expression: '*', dependencies: [], iteration: true)],
            conditional: conditional,
          )
        end)
      when RangeLookup
        visit(expression, possible: possible, line: line)
        Set[LocalBinding.opaque]
      else
        Set[LocalBinding.opaque]
      end
    end

    def visit(node, possible: false, line: nil)
      return if node.nil? || node.is_a?(String)

      case node
      when Variable
        visit_variable(node, possible, line || node.line_number)
      when VariableLookup
        visit_variable_lookup(node, line || node.line_number, possible)
      when RangeLookup
        visit(node.start_obj, possible: possible, line: line)
        visit(node.end_obj, possible: possible, line: line)
      when BlockBody
        visit_each(node.nodelist, possible, line)
      when Document
        visit_each(node.nodelist, possible, line)
      when Assign
        visit_assign(node, possible, line)
      when Capture
        visit_capture(node, possible, line)
      when For
        visit_for(node, possible, line)
      when TableRow
        visit_table_row(node, possible, line)
      when If
        visit_if(node, possible, line)
      when Case
        visit_case(node, possible, line)
      when Render
        visit_render(node, possible, line)
      when Echo
        visit_variable(node.variable, possible, line || node.line_number)
      when Cycle
        node.variables.each { |expression| visit(expression, possible: possible, line: line || node.line_number) }
      when Increment, Decrement
        bind_local(node.variable_name, !possible)
      when Ifchanged
        visit_each(node.nodelist, possible, line)
      when Comment, Raw, Break, Continue
        nil
      when Include
        visit_include(node, possible, line)
      else
        visit_generic(node, possible, line)
      end
    end

    def visit_each(nodes, possible, line = nil)
      Array(nodes).each { |node| visit(node, possible: possible, line: line) }
    end

    def visit_variable(variable, possible, line = variable.line_number)
      visit_expression(variable.name, possible, line)
      variable.filters.each do |_filter_name, arguments, keyword_arguments = nil|
        Array(arguments).each { |expression| visit_expression(expression, possible, line) }
        Array(keyword_arguments).each do |_key, expression|
          visit_expression(expression, possible, line)
        end
      end
    end

    def visit_expression(expression, possible, line)
      case expression
      when VariableLookup
        visit_variable_lookup(expression, line, possible)
      when RangeLookup
        visit(expression, possible: possible, line: line)
      end
    end

    def visit_assign(node, possible, _line)
      visit_variable(node.from, possible, node.line_number)
      paths = assign_paths(node.from)
      bind_local_paths(node.to, !possible, paths)
    end

    def visit_capture(node, possible, _line)
      visit_each(node.nodelist, possible, node.line_number)
      bind_local(node.to, !possible)
    end

    def visit_for(node, possible, _line)
      visit(node.limit, possible: possible, line: node.line_number)
      visit(node.from, possible: possible, line: node.line_number)

      frame = current_frame_dup
      branch_frames = []

      branch_frames << with_branch do
        with_frame(
          node.variable_name => iteration_bindings(node.collection_name, node.line_number, possible),
          'forloop' => nil,
        ) do
          visit_each(node.nodelist.first.nodelist, true, node.line_number)
          current_frame_dup
        end
      end

      branch_frames << with_branch do
        visit_each(node.nodelist.last.nodelist, true, node.line_number) if node.nodelist.length > 1
        current_frame_dup
      end

      merge_branch_frames(frame, branch_frames)
      bind_local(node.variable_name, true)
    end

    def visit_table_row(node, possible, _line)
      node.attributes.each_value do |expression|
        visit(expression, possible: possible, line: node.line_number)
      end

      frame = current_frame_dup
      branch_frames = [with_branch do
        with_frame(
          node.variable_name => iteration_bindings(node.collection_name, node.line_number, possible),
          'tablerowloop' => nil,
        ) do
          visit_each(node.nodelist, true, node.line_number)
          current_frame_dup
        end
      end]
      merge_branch_frames(frame, branch_frames)
      bind_local(node.variable_name, true)
    end

    def visit_if(node, possible, _line)
      base = current_frame_dup
      branch_frames = node.blocks.map do |condition|
        frame = current_frame_dup
        result = with_branch do
          visit_condition(condition, possible, node.line_number)
          visit_each(condition.attachment.nodelist, true, node.line_number)
          current_frame_dup
        end
        restore_frame(frame)
        result
      end
      branch_frames << current_frame_dup unless node.blocks.last.else?
      merge_branch_frames(base, branch_frames)
    end

    def visit_case(node, possible, _line)
      visit(node.left, possible: possible, line: node.line_number)

      base = current_frame_dup
      branch_frames = node.blocks.map do |condition|
        frame = current_frame_dup
        result = with_branch do
          unless condition.else?
            visit(condition.right, possible: true, line: node.line_number)
          end
          visit_each(condition.attachment.nodelist, true, node.line_number)
          current_frame_dup
        end
        restore_frame(frame)
        result
      end
      branch_frames << current_frame_dup unless node.blocks.last.else?
      merge_branch_frames(base, branch_frames)
    end

    def visit_condition(condition, possible, line)
      current = condition
      compound = false
      while current
        expression_possible = possible || compound
        visit(current.left, possible: expression_possible, line: line)
        visit(current.right, possible: expression_possible, line: line)
        compound = !current.child_condition.nil?
        current = current.child_condition
      end
    end

    def visit_render(node, possible, _line)
      visit(node.template_name_expr, possible: possible, line: node.line_number)
      visit(node.variable_name_expr, possible: possible, line: node.line_number)
      attribute_possible = possible || node.for_loop?
      node.attributes.each_value do |expression|
        visit(expression, possible: attribute_possible, line: node.line_number)
      end

      if @render_resolver
        resolve_render(node, possible || node.for_loop?)
      else
        @unresolved_renders << node
      end
    end

    def resolve_render(node, possible)
      result = call_resolver(node)
      return unless result

      %i[definite conditional].each do |kind|
        result[kind].to_a.each do |path|
          add_reference(path, node.line_number, possible || kind == :conditional)
        end
      end
      result[:dynamic].to_a.each do |path|
        add_reference(path, node.line_number, true)
      end
    end

    def call_resolver(node)
      result =
        if @render_resolver.respond_to?(:call)
          if @render_resolver.arity == 1
            @render_resolver.call(node)
          else
            @render_resolver.call(node, node.template_name_expr)
          end
        else
          @render_resolver[node.template_name_expr]
        end

      return unless result

      normalized =
        if result.is_a?(Hash) || result.is_a?(Result)
          result.to_h.transform_keys(&:to_sym)
        else
          { definite: Array(result), conditional: [], dynamic: [] }
        end

      defaults = { definite: [], conditional: [], dynamic: [] }
      defaults.merge(normalized).transform_values do |references|
        Array(references).map do |reference|
          reference.respond_to?(:path) ? reference.path : reference
        end
      end
    end

    def visit_include(node, possible, _line)
      visit(node.template_name_expr, possible: possible, line: node.line_number)
      visit(node.variable_name_expr, possible: possible, line: node.line_number)
      node.attributes.each_value { |expression| visit(expression, possible: possible, line: node.line_number) }
      @unresolved_includes << node
    end

    def visit_generic(node, possible, line)
      if node.respond_to?(:nodelist)
        visit_each(Array(node.nodelist), possible, line || node.line_number)
      else
        ParseTreeVisitor.for(node).visit.each do |item|
          visit_generic_tree(item, possible, line || node.line_number)
        end
      end
    end

    def visit_generic_tree(item, possible, line)
      node, children = item
      visit(node, possible: possible, line: line) if node.respond_to?(:evaluate)
      Array(children).each { |child| visit_generic_tree(child, possible, line) }
    end

    def visit_variable_lookup(lookup, line, possible)
      resolve_lookup_paths(
        lookup,
        line,
        possible,
        visit_dependencies: true,
      ).each do |path, conditional|
        add_reference(path, line, conditional)
      end
    end

    def assign_paths(variable)
      return nil unless variable.filters.empty?

      case variable.name
      when VariableLookup
        resolve_lookup_paths(
          variable.name,
          variable.line_number,
          false,
          visit_dependencies: false,
        ).map(&:first)
      when RangeLookup
        nil
      else
        nil
      end
    end

    def resolve_lookup_paths(
      lookup,
      line,
      possible,
      visit_dependencies:,
      include_binding_roots: false
    )
      prefixes = []
      static_prefixes = []
      suffix = lookup.lookups.map do |segment|
        if segment.respond_to?(:evaluate) && !segment.is_a?(String)
          visit(segment, possible: possible, line: line) if visit_dependencies
          prefixes = false
          build_dynamic_segment(segment)
        elsif prefixes
          prefixes << segment
          static_prefixes << segment
          segment
        else
          segment
        end
      end

      if lookup.name.respond_to?(:evaluate)
        visit(lookup.name, possible: possible, line: line) if visit_dependencies
        return [[[build_dynamic_segment(lookup.name)] + suffix, possible]]
      end

      bindings = local_bindings(lookup.name)
      if bindings.nil?
        add_static_prefix(lookup.name, static_prefixes, line, possible)
        return external_lookup_paths(lookup.name, suffix, possible)
      end

      bindings.each_with_object([]) do |binding, result|
        if binding.opaque?
          result << [[lookup.name] + suffix, possible || binding.conditional] if binding.conditional
          next
        elsif suffix.empty? && !include_binding_roots
          next
        end

        result << [binding.path + suffix, possible || binding.conditional]
      end
    end

    def add_static_prefix(root, prefixes, line, possible)
      return unless root.is_a?(String) && prefixes.is_a?(Array) && !prefixes.empty?

      add_reference([root] + prefixes, line, possible)
    end

    def external_lookup_paths(root, suffix, possible)
      return [] if root == Expression::SELF && suffix.empty?
      return [] unless root.is_a?(String) || root == Expression::SELF

      if root == Expression::SELF
        first = suffix.first
        return [[suffix, possible]] if first.is_a?(String)

        return [[suffix, possible]]
      end

      [[[root] + suffix, possible]]
    end

    def build_dynamic_segment(expression)
      dependencies = []
      collect_variable_lookups(expression, dependencies)
      DynamicSegment.new(
        expression: expression_source(expression),
        dependencies: dependencies,
      )
    end

    def collect_variable_lookups(expression, result)
      case expression
      when VariableLookup
        result << expression
      when RangeLookup
        collect_variable_lookups(expression.start_obj, result)
        collect_variable_lookups(expression.end_obj, result)
      end
    end

    def expression_source(expression)
      case expression
      when VariableLookup
        ([expression.name] + expression.lookups).map(&:to_s).join('.')
      else
        expression.to_s
      end
    end

    def add_reference(path, line, conditional)
      bucket =
        if path.any? { |segment| segment.respond_to?(:dynamic?) && segment.dynamic? }
          @dynamic
        elsif conditional
          @conditional
        else
          @definite
        end

      return if bucket.any? { |existing| existing.path == path && existing.line_number == line }

      reference = Reference.new(path: path, line_number: line, conditional: conditional)
      bucket << reference
    end
  end
end
