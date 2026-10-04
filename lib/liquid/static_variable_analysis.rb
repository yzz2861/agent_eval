# frozen_string_literal: true

require 'set'

module Liquid
  # Statically collects external variable reads from a parsed template.
  #
  # The analyzer never renders a template, invokes a filter or Drop, or reads
  # a partial from disk. Dependencies for render tags must be supplied by the
  # caller through a resolver.
  class StaticVariableAnalysis
    Reference = Struct.new(:path, :line_number, keyword_init: true)
    DynamicReference = Struct.new(:prefix, :line_number, :conditional, keyword_init: true)

    class Analysis
      attr_reader :certain, :conditional, :dynamic

      def initialize
        @certain = []
        @conditional = []
        @dynamic = []
      end

      def add(path, line_number, conditional)
        reference = Reference.new(path: path, line_number: line_number)
        collection = conditional ? @conditional : @certain
        collection << reference unless collection.include?(reference)
      end

      def add_dynamic(prefix, line_number, conditional)
        reference = DynamicReference.new(
          prefix: prefix,
          line_number: line_number,
          conditional: conditional,
        )
        @dynamic << reference unless @dynamic.include?(reference)
      end

      def to_h
        {
          certain: @certain.dup,
          conditional: @conditional.dup,
          dynamic: @dynamic.dup,
        }
      end
    end

    State = Struct.new(:definite_locals, :possible_locals, keyword_init: true) do
      def self.empty
        new(definite_locals: Set.new, possible_locals: Set.new)
      end

      def dup
        self.class.new(
          definite_locals: definite_locals.dup,
          possible_locals: possible_locals.dup,
        )
      end

      def definite_local?(name)
        definite_locals.include?(name)
      end

      def add_definite_local(name)
        definite_locals.add(name)
        possible_locals.delete(name)
      end

      def add_possible_local(name)
        possible_locals.add(name) unless definite_locals.include?(name)
      end
    end

    def self.analyze(template_or_document, render_resolver = nil)
      document = case template_or_document
      when Template
        template_or_document.root
      when Document
        template_or_document
      else
        raise ArgumentError, "expected a Liquid::Template or Liquid::Document"
      end

      new(render_resolver).analyze_document(document)
    end

    def initialize(render_resolver)
      @render_resolver = render_resolver
      @analysis = Analysis.new
    end

    def analyze_document(document)
      analyze_body(document.nodelist, State.empty, false)
      @analysis.to_h
    end

    private

    def analyze_body(nodes, state, conditional)
      nodes.each do |node|
        analyze_node(node, state, conditional)
      end
      state
    end

    def analyze_node(node, state, conditional)
      case node
      when String
        state
      when Variable
        analyze_variable(node, state, conditional)
      when Assign
        analyze_variable(node.from, state, conditional)
        state.add_definite_local(node.to)
      when Capture
        analyze_body(node.nodelist, state, conditional)
        state.add_definite_local(node.to)
      when For
        analyze_for(node, state, conditional)
      when TableRow
        analyze_table_row(node, state, conditional)
      when If
        analyze_if(node, state, conditional)
      when Case
        analyze_case(node, state, conditional)
      when Render
        analyze_render(node, state, conditional)
      when Include
        analyze_include(node, state, conditional)
      when Echo
        analyze_variable(node.variable, state, conditional)
      when Comment, Doc
        state
      when Cycle
        analyze_expression(node.name, state, conditional, node.line_number) if node.name.respond_to?(:lookups)
        node.variables.each { |expression| analyze_expression(expression, state, conditional, node.line_number) }
      when Increment, Decrement
        analyze_expression(VariableLookup.new(node.variable_name), state, conditional, node.line_number)
        state.add_definite_local(node.variable_name)
      when Ifchanged
        analyze_body(node.nodelist, state, conditional)
      when Block
        analyze_body(node.nodelist, state, true)
      else
        analyze_unknown_node(node, state, conditional)
      end
      state
    end

    def analyze_variable(variable, state, conditional)
      line_number = variable.line_number
      analyze_expression(variable.name, state, conditional, line_number)

      variable.filters.each do |_filter_name, arguments, keyword_arguments = nil|
        arguments.each { |expression| analyze_expression(expression, state, conditional, line_number) }
        keyword_arguments&.each_value { |expression| analyze_expression(expression, state, conditional, line_number) }
      end
    end

    def analyze_expression(expression, state, conditional, line_number)
      case expression
      when VariableLookup
        analyze_variable_lookup(expression, state, conditional, line_number)
      when RangeLookup
        analyze_expression(expression.start_obj, state, conditional, line_number)
        analyze_expression(expression.end_obj, state, conditional, line_number)
      end
    end

    def analyze_variable_lookup(lookup, state, conditional, line_number)
      path, root_is_dynamic, root_is_self, root_is_possible_local = variable_lookup_root(
        lookup.name, state, conditional, line_number
      )
      return if path.nil?
      conditional = true if root_is_possible_local

      lookup.lookups.each_with_index do |segment, index|
        if lookup.lookup_command?(index)
          @analysis.add(path, line_number, conditional) unless path.empty? || state.definite_local?(path.first)
          return
        end

        if static_lookup_segment?(segment)
          path << segment
        else
          analyze_expression(segment, state, conditional, line_number)
          if path.empty?
            if root_is_self
              @analysis.add_dynamic([Expression::SELF], line_number, conditional)
            end
          elsif !state.definite_local?(path.first)
            @analysis.add_dynamic(path, line_number, conditional)
            @analysis.add(path, line_number, conditional) if root_is_dynamic
          end
          return
        end
      end

      if root_is_dynamic
        @analysis.add_dynamic([], line_number, conditional)
      elsif !path.empty? && !state.definite_local?(path.first)
        @analysis.add(path, line_number, conditional)
      end
    end

    def variable_lookup_root(root, state, conditional, line_number)
      case root
      when String
        return [nil, false, false, false] if state.definite_local?(root)
        return [[], false, true, state.possible_locals.include?(root)] if root == Expression::SELF

        [[root], false, false, state.possible_locals.include?(root)]
      when Integer, nil, true, false
        [nil, false, false, false]
      else
        analyze_expression(root, state, conditional, line_number)
        [[], true, false, false]
      end
    end

    def static_lookup_segment?(segment)
      segment.is_a?(String) || segment.is_a?(Integer)
    end

    def analyze_unknown_node(node, state, conditional)
      line_number = node.line_number if node.respond_to?(:line_number)
      callbacks = {
        VariableLookup => ->(expression, context) { [expression, context] },
        RangeLookup => ->(expression, context) { [expression, context] },
      }
      callbacks.default = proc {}
      visitor = ParseTreeVisitor.new(node, callbacks)
      visitor.visit.each do |item|
        collect_unknown_expressions(item, state, conditional, line_number)
      end
    end

    def collect_unknown_expressions(item, state, conditional, line_number)
      return unless item.is_a?(Array)

      expression_node, children = item
      if expression_node.is_a?(VariableLookup) || expression_node.is_a?(RangeLookup)
        analyze_expression(expression_node, state, conditional, line_number)
      end
      children.each { |child| collect_unknown_expressions(child, state, conditional, line_number) }
    end

    def analyze_for(node, state, conditional)
      line_number = node.line_number
      analyze_expression(node.collection_name, state, conditional, line_number)
      analyze_expression(node.limit, state, conditional, line_number)
      analyze_expression(node.from, state, conditional, line_number) unless node.from == :continue

      body_state = state.dup
      body_state.add_definite_local(node.variable_name)
      body_state.add_definite_local('forloop')
      analyze_body(node.for_block.nodelist, body_state, true)

      if node.else_block
        else_state = state.dup
        analyze_body(node.else_block.nodelist, else_state, true)
        merge_possible_branch_states(state, [else_state])
      end
    end

    def analyze_table_row(node, state, conditional)
      line_number = node.line_number
      analyze_expression(node.collection_name, state, conditional, line_number)
      node.attributes.each_value do |expression|
        analyze_expression(expression, state, conditional, line_number)
      end

      body_state = state.dup
      body_state.add_definite_local(node.variable_name)
      body_state.add_definite_local('tablerowloop')
      analyze_body(node.nodelist, body_state, true)
    end

    def analyze_if(node, state, conditional)
      branch_states = []

      node.blocks.each_with_index do |block, index|
        condition_state = state.dup
        analyze_condition(block, condition_state, conditional, node.line_number)

        next unless block.attachment

        body_state = condition_state.dup
        analyze_body(block.attachment.nodelist, body_state, true)
        branch_states << body_state
      end

      if node.blocks.any?(&:else?) && !conditional
        merge_branch_states(state, branch_states)
      else
        merge_possible_branch_states(state, branch_states)
      end
    end

    def analyze_condition(condition, state, condition_conditional, line_number)
      return unless condition.respond_to?(:left)

      current_conditional = condition_conditional || !condition.child_condition.nil?
      reference_line = condition.line_number || line_number
      analyze_expression(condition.left, state, current_conditional, reference_line)
      analyze_expression(condition.right, state, current_conditional, reference_line)

      child = condition.child_condition
      analyze_condition(child, state, true, line_number) if child
    end

    def merge_branch_states(state, branch_states)
      return if branch_states.empty?

      branch_definite = branch_states.map { |branch_state| branch_state.definite_locals.to_a }

      definite = branch_definite.first.select do |name|
        branch_definite.all? { |locals| locals.include?(name) }
      end

      definite.each { |name| state.add_definite_local(name) }
      branch_states.each do |branch_state|
        branch_state.possible_locals.each { |name| state.add_possible_local(name) }
      end
    end

    def merge_possible_branch_states(state, branch_states)
      branch_states.each do |branch_state|
        branch_state.definite_locals.each { |name| state.add_possible_local(name) }
        branch_state.possible_locals.each { |name| state.add_possible_local(name) }
      end
    end

    def analyze_case(node, state, conditional)
      line_number = node.line_number
      analyze_expression(node.left, state, conditional, line_number)

      branch_states = []
      node.blocks.each do |block|
        block_state = state.dup
        if block.respond_to?(:right)
          analyze_expression(block.right, block_state, true, block.line_number || line_number)
        end
        analyze_body(block.attachment.nodelist, block_state, true)
        branch_states << block_state
      end

      if node.blocks.any?(&:else?) && !conditional
        merge_branch_states(state, branch_states)
      else
        merge_possible_branch_states(state, branch_states)
      end
    end

    def analyze_render(node, state, conditional)
      line_number = node.line_number
      analyze_expression(node.variable_name_expr, state, conditional, line_number)
      node.attributes.each_value do |expression|
        analyze_expression(expression, state, conditional, line_number)
      end

      dependencies = resolve_render_dependencies(node.template_name_expr)
      add_render_dependencies(dependencies, render_locals(node), conditional, line_number)
    end

    def analyze_include(node, state, conditional)
      line_number = node.line_number
      analyze_expression(node.template_name_expr, state, conditional, line_number)
      analyze_expression(node.variable_name_expr, state, conditional, line_number)
      node.attributes.each_value do |expression|
        analyze_expression(expression, state, conditional, line_number)
      end
    end

    def render_locals(node)
      locals = node.attributes.keys.to_set
      if node.variable_name_expr
        locals << (node.alias_name || implicit_render_local_name(node.template_name_expr))
        locals << 'forloop' if node.for_loop?
      end
      locals
    end

    def implicit_render_local_name(template_name)
      template_name if template_name.is_a?(String) && template_name.split('/').last
    end

    def resolve_render_dependencies(template_name)
      return unless template_name.is_a?(String) && @render_resolver

      if @render_resolver.respond_to?(:call)
        @render_resolver.call(template_name)
      elsif @render_resolver.is_a?(Hash)
        @render_resolver[template_name]
      end
    end

    def add_render_dependencies(dependencies, locals, conditional, line_number)
      dependencies = { certain: dependencies } if dependencies.is_a?(Array)
      return unless dependencies.is_a?(Hash)

      { certain: false, conditional: true }.each do |kind, dependency_conditional_base|
        Array(dependency_value(dependencies, kind)).each do |path|
          path = normalize_dependency_path(path)
          next if path.empty? || locals.include?(path.first.to_s)

          @analysis.add(path, line_number, conditional || dependency_conditional_base)
        end
      end

      Array(dependency_value(dependencies, :dynamic)).each do |dependency|
        prefix = normalize_dependency_path(dependency.is_a?(Hash) ? dependency[:prefix] : dependency)
        next if prefix.empty? || locals.include?(prefix.first.to_s)

        @analysis.add_dynamic(prefix, line_number, conditional)
      end
    end

    def dependency_value(dependencies, key)
      dependencies[key] || dependencies[key.to_s]
    end

    def normalize_dependency_path(path)
      case path
      when Array
        path
      when String
        path.split('.')
      when Hash
        normalize_dependency_path(path[:path])
      when Reference, DynamicReference
        normalize_dependency_path(path.path)
      else
        []
      end
    end
  end
end
