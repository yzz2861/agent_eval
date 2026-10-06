# Static analysis for parslet grammars.

# A grammar check that never touches business input. It expands the atom
# graph of a parser without reading any input string and reports constructs
# that cannot make progress on the input:
#
# * a repetition (repeat without an upper bound) whose body can match the
#   empty string -- every successful iteration consumes nothing, so the
#   repetition loops forever;
# * rules that refer back to themselves (directly or through other rules)
#   while none of the rules on the cycle is guaranteed to consume a
#   character first, i.e. non-progressing left recursion.
#
# Nullability ("can this atom match without consuming a character?") is
# propagated as a three valued answer: yes, no or unknown. A +dynamic+ atom
# (and a +scope+ block, which is evaluated while parsing) is never executed
# to guess its result; it contributes an +unknown+ answer and the check
# reports which part of the grammar could not be confirmed statically.
#
# Example:
#
#   class Mini < Parslet::Parser
#     rule(:space) { match('\\s').repeat }
#     rule(:spaces?) { space.maybe }
#     rule(:item) { spaces? >> str('a') }
#     rule(:list) { item.repeat }
#     root(:list)
#   end
#
#   result = Mini.grammar_check
#   result.ok?            # => true
#
module Parslet
  # Raised by a strict grammar check (GrammarCheck::Result#verify!) when
  # the grammar contains a construct that cannot make progress on input.
  #
  class GrammarError < StandardError; end

  # Convenience entry point: checks any parslet atom (or Parslet::Parser
  # instance/class) without reading business input.
  #
  #   result = Parslet.grammar_check(str('').repeat)
  #
  def self.grammar_check(subject, rule_names=[])
    GrammarCheck.analyze(subject, rule_names)
  end

  class GrammarCheck
    # One piece of evidence produced by the check.
    #
    # +level+ is either +:error+ (a construct that definitely cannot make
    # progress) or +:warning+ (a construct that contains an atom, such as a
    # +dynamic+, whose behaviour cannot be decided without reading input).
    # +chain+ is the list of rule names and atom descriptions that leads from
    # a user declared rule to the offending construct.
    #
    Finding = Struct.new(:level, :message, :chain) do
      def to_s
        location = chain && chain.any? ? "  at: #{chain.join(' -> ')}" : nil
        ["#{level.to_s.upcase}: #{message}", location].compact.join("\n")
      end
    end

    # Outcome of a grammar check. See #errors, #warnings and #report.
    class Result
      attr_reader :findings

      def initialize(findings)
        @findings = findings
      end

      def errors
        findings.select { |f| f.level == :error }
      end

      def warnings
        findings.select { |f| f.level == :warning }
      end

      # True when there is no definite non-progressing construct. Warnings
      # about unanalyzable atoms still allow the grammar to be used.
      #
      def ok?
        errors.empty?
      end

      # Raises {Parslet::GrammarError} with the full report unless #ok?.
      #
      def verify!
        raise Parslet::GrammarError, report unless ok?
        self
      end

      def report
        lines = findings.map(&:to_s)
        summary = "#{errors.size} error(s), #{warnings.size} warning(s)"
        (lines + [summary]).join("\n")
      end
      alias_method :to_s, :report
    end

    # Runs the check against +subject+, which can be a Parslet::Parser
    # instance/class or any parslet atom. +rule_names+ lists the names of the
    # user declared rules (see Parslet::ClassMethods); it is used to start
    # the analysis from every rule, not only the root.
    #
    def self.analyze(subject, rule_names=[])
      new(subject, rule_names).analyze
    end

    def initialize(subject, rule_names)
      if subject.is_a?(Class)
        @parser = subject.new
      else
        @parser = subject
      end
      @rule_names = rule_names
      @findings = []
      @reported = {}
    end

    def analyze
      collect!
      compute_nullability!
      scan_repetitions!
      detect_cycles!

      Result.new(@findings)
    end

    #--
    # Phase 1: Walk the atom graph and collect every Entity (a declared
    # rule) reachable from the root or from a declared rule. Rule bodies
    # are forced by calling their definition blocks; this is the same lazy
    # expansion that happens during parsing, but no input is read. Blocks
    # belonging to dynamic or scope atoms are deliberately not called.
    #+++
    def collect!
      @entities = {}   # object_id => Entity
      @display  = {}   # object_id => String used when printing chains

      @rule_names.each do |name|
        entity = @parser.send(name)
        register_entity(entity)
      end

      @root_atom =
        if @parser.respond_to?(:root)
          @parser.root
        else
          @parser
        end

      walk(@root_atom)
    end

    def register_entity(entity)
      return if @entities.has_key?(entity.object_id)

      @entities[entity.object_id] = entity
      @display[entity.object_id] = entity.name.to_s
      walk(entity.parslet)
    end

    def walk(atom)
      case atom
      when Atoms::Entity
        register_entity(atom)
      when Parslet::Parser
        walk(atom.root)
      else
        structural_children(atom).each { |child| walk(child) }
      end
    end

    # Children that are statically part of the grammar. Blocks of dynamic
    # and scope atoms are intentionally excluded so we never execute them.
    #
    def structural_children(atom)
      case atom
      when Atoms::Named, Atoms::Ignored, Atoms::Capture
        [atom.parslet]
      when Atoms::Sequence
        atom.parslets
      when Atoms::Alternative
        atom.alternatives
      when Atoms::Repetition
        [atom.parslet]
      when Atoms::Lookahead
        [atom.bound_parslet]
      when Atoms::Infix
        [atom.element] +
          atom.operations.map { |op_atom, _prec, _assoc| op_atom }
      else
        []
      end
    end

    #--
    # Phase 2: Nullability fixpoint over the rules. Each atom gets a pair
    # of booleans, [may_be_nullable, provably_nullable], where may >= prov:
    #
    #   [false, false] ... cannot match without consuming
    #   [true,  true]  ... definitely matches without consuming
    #   [true,  false] ... unknown (contains a dynamic/scope atom or an
    #                      entity that is itself unknown)
    #+++
    def compute_nullability!
      @may  = Hash.new(false)
      @prov = Hash.new(false)

      loop do
        changed = false
        @entities.each_value do |entity|
          may, prov = nullable(entity.parslet)
          unless @may[entity.object_id] == may &&
              @prov[entity.object_id] == prov
            @may[entity.object_id]  = may
            @prov[entity.object_id] = prov
            changed = true
          end
        end
        break unless changed
      end
    end

    # Returns [may_be_nullable, provably_nullable] for an atom.
    #
    def nullable(atom)
      case atom
      when Atoms::Entity
        [@may.fetch(atom.object_id, true),
         @prov.fetch(atom.object_id, false)]
      when Atoms::Str
        [atom.str.empty?, atom.str.empty?]
      when Atoms::Re
        # Re atoms always consume the single character they matched.
        [false, false]
      when Atoms::Named, Atoms::Ignored, Atoms::Capture
        nullable(atom.parslet)
      when Atoms::Sequence
        combine(atom.parslets) { |values| values.all? }
      when Atoms::Alternative
        combine(atom.alternatives) { |values| values.any? }
      when Atoms::Repetition
        if atom.min == 0
          [true, true]
        else
          nullable(atom.parslet)
        end
      when Atoms::Lookahead
        # Both &p and !p succeed without consuming anything.
        [true, true]
      when Atoms::Dynamic, Atoms::Scope
        # Never execute the block to guess the result.
        [true, false]
      when Atoms::Infix
        nullable(atom.element)
      when Parslet::Parser
        nullable(atom.root)
      else
        # Unknown atom type: be conservative.
        [true, false]
      end
    end

    def combine(atoms)
      values = atoms.map { |child| nullable(child) }
      may  = yield values.map { |m, _p| m }
      prov = yield values.map { |_m, p| p }
      [may, prov]
    end

    def may_nullable?(atom)
      nullable(atom).first
    end

    def provably_nullable?(atom)
      nullable(atom).last
    end

    #--
    # Phase 3: Every unbounded repetition whose body can succeed without
    # consuming a character is a guaranteed infinite loop. If the body's
    # nullability can only be assumed because it contains a dynamic atom,
    # emit a warning instead of an error.
    #+++
    def scan_repetitions!
      @rep_visited = {}
      @entities.each_value do |entity|
        next if @rep_visited[entity.object_id]
        @rep_visited[entity.object_id] = true
        find_repetitions(entity.parslet, [entity.name.to_s])
      end
      unless @parser.respond_to?(:root)
        find_repetitions(@root_atom, [])
      end
    end

    def find_repetitions(atom, chain)
      case atom
      when Atoms::Repetition
        body_chain = chain + [describe_repetition(atom)]
        check_repetition_body(atom, body_chain)
        find_repetitions(atom.parslet, body_chain)
      when Atoms::Entity
        return unless @entities.has_key?(atom.object_id)
        return if @rep_visited[atom.object_id]
        @rep_visited[atom.object_id] = true
        find_repetitions(atom.parslet,
          chain + [@display[atom.object_id]])
      when Parslet::Parser
        find_repetitions(atom.root, chain)
      else
        structural_children(atom).each do |child|
          find_repetitions(child, chain)
        end
      end
    end

    def check_repetition_body(repetition, chain)
      # A finite repetition (.maybe, .repeat(0, 3)) terminates by its upper
      # bound, even when the body matches the empty string once.
      return unless repetition.max.nil?

      body = repetition.parslet
      if provably_nullable?(body)
        report(:error,
          "Unbounded repetition of a body that can match the empty " \
          "string; successful iterations never consume input, so this " \
          "loops forever",
          chain + nullable_chain(body))
      elsif may_nullable?(body)
        unknown = first_unknown(body, [])
        report(:warning,
          "Unbounded repetition whose body may match the empty string; " \
          "nullability cannot be confirmed statically because a dynamic " \
          "atom is involved",
          chain + unknown)
      end
    end

    def describe_repetition(repetition)
      if repetition.min == 0 && repetition.max == 1
        "maybe"
      elsif repetition.max.nil?
        "repeat(#{repetition.min}, nil)"
      else
        "repeat(#{repetition.min}, #{repetition.max})"
      end
    end

    # Walks down an atom that is provably nullable and returns the chain
    # leading to the construct responsible for matching nothing.
    #
    def nullable_chain(atom)
      case atom
      when Atoms::Entity
        name = @display[atom.object_id] || atom.name.to_s
        [name] + nullable_chain(atom.parslet)
      when Atoms::Named, Atoms::Ignored, Atoms::Capture
        nullable_chain(atom.parslet)
      when Atoms::Sequence
        child = atom.parslets.find { |p| provably_nullable?(p) }
        return [atom.to_s] if child.nil?
        nullable_chain(child)
      when Atoms::Alternative
        child = atom.alternatives.find { |p| provably_nullable?(p) }
        return [atom.to_s] if child.nil?
        nullable_chain(child)
      when Atoms::Repetition
        if atom.min == 0
          [describe_repetition(atom)]
        else
          nullable_chain(atom.parslet)
        end
      when Atoms::Lookahead
        [atom.to_s]
      when Atoms::Str
        ["str('')"]
      when Parslet::Parser
        [atom.class.name || 'parser'] + nullable_chain(atom.root)
      else
        [atom.to_s]
      end
    end

    # Returns the chain to the first dynamic/scope atom that makes the
    # nullability answer uncertain.
    #
    def first_unknown(atom, chain)
      case atom
      when Atoms::Dynamic, Atoms::Scope
        chain + [atom.to_s]
      when Atoms::Entity
        if @prov[atom.object_id]
          chain
        else
          first_unknown(atom.parslet,
            chain + [@display[atom.object_id] || atom.name.to_s])
        end
      when Atoms::Named, Atoms::Ignored, Atoms::Capture, Atoms::Repetition
        target = atom.is_a?(Atoms::Repetition) ? atom.parslet : atom.parslet
        first_unknown(target, chain)
      when Atoms::Sequence
        unknown_child = atom.parslets.find { |p| may_nullable?(p) &&
                                             !provably_nullable?(p) } ||
                        atom.parslets.find { |p| may_nullable?(p) }
        return chain + [atom.to_s] if unknown_child.nil?
        first_unknown(unknown_child, chain)
      when Atoms::Alternative
        unknown_child = atom.alternatives.find { |p| may_nullable?(p) &&
                                                 !provably_nullable?(p) } ||
                        atom.alternatives.find { |p| may_nullable?(p) }
        return chain + [atom.to_s] if unknown_child.nil?
        first_unknown(unknown_child, chain)
      when Atoms::Lookahead
        chain
      when Parslet::Parser
        first_unknown(atom.root, chain)
      else
        chain + [atom.to_s]
      end
    end

    #--
    # Phase 4: Build the graph of "first references" between rules: an edge
    # R -> S means that rule R can invoke rule S without consuming a
    # character first. A cycle in this graph is non-progressing recursion.
    #
    # A dynamic/scope atom reached in that position produces a warning: its
    # block is never executed, so we cannot tell which rule (if any) it
    # returns and whether that rule consumes input.
    #+++
    def detect_cycles!
      @edges   = Hash.new { |h, k| h[k] = {} }  # id => target_id => chain
      @unknown = Hash.new { |h, k| h[k] = [] }  # id => chains to dynamic

      @entities.values.dup.each do |entity|
        refs = first_references(entity.parslet, [])
        refs[:edges].each do |target_id, edge_chain|
          unless @edges[entity.object_id].key?(target_id)
            @edges[entity.object_id][target_id] = edge_chain
          end
        end
        refs[:unknown].each do |unknown_chain|
          @unknown[entity.object_id] << unknown_chain
        end
      end

      report_certain_cycles!
      report_unknown_prefixes!
    end

    # Traverses atoms that can be reached before a character is consumed.
    # Returns {:edges => [[entity_id, chain_of_names]],
    #          :unknown => [chain_to_dynamic_atom]}.
    #
    def first_references(atom, chain)
      result = { edges: [], unknown: [] }

      case atom
      when Atoms::Entity
        target_id = atom.object_id
        name = @display[target_id] || atom.name.to_s
        result[:edges] << [target_id, chain + [name]]
      when Atoms::Str
        # A non empty string consumes before anything else.
      when Atoms::Re
      when Atoms::Named, Atoms::Ignored, Atoms::Capture
        merge_refs(result, first_references(atom.parslet, chain))
      when Atoms::Sequence
        atom.parslets.each_with_index do |child, index|
          preceding = atom.parslets[0...index]
          # Later members are in first position only if everything before
          # them may match without consuming.
          next unless preceding.all? { |p| may_nullable?(p) }
          merge_refs(result, first_references(child, chain))
        end
      when Atoms::Alternative
        atom.alternatives.each do |child|
          merge_refs(result, first_references(child, chain))
        end
      when Atoms::Repetition
        merge_refs(result, first_references(atom.parslet, chain))
      when Atoms::Lookahead
        merge_refs(result, first_references(atom.bound_parslet, chain))
      when Atoms::Dynamic, Atoms::Scope
        result[:unknown] << (chain + [atom.to_s])
      when Atoms::Infix
        merge_refs(result, first_references(atom.element, chain))
      when Parslet::Parser
        merge_refs(result, first_references(atom.root, chain))
      end

      result
    end

    def merge_refs(result, child_result)
      result[:edges].concat(child_result[:edges])
      result[:unknown].concat(child_result[:unknown])
    end

    def report_certain_cycles!
      strongly_connected_components.each do |component|
        ordered = component.sort_by { |id| @display[id] || @entities[id].name.to_s }
        cycle = cycle_within(component, ordered.first)
        next unless cycle

        names = cycle.map { |id| @display[id] || @entities[id].name.to_s }
        report(:error,
          "Non-consuming rule loop: none of the rules on this cycle is " \
          "guaranteed to consume a character before recursing, so the " \
          "parse cannot make progress",
          names + [names.first])
      end
    end

    # Returns a list of entity ids forming a cycle inside +component+ or nil.
    #
    def cycle_within(component, start)
      member = {}
      component.each { |id| member[id] = true }
      stack  = []
      on_stack = {}

      visit = lambda do |node|
        stack << node
        on_stack[node] = true

        @edges[node].keys.each do |target|
          next unless member[target]
          if on_stack[target]
            if target == start
              # A closed walk back to the start. For a self loop, the
              # stack only contains start itself.
              throw :found, stack.dup
            end
          else
            visit.call(target)
          end
        end

        on_stack.delete(node)
        stack.pop
        nil
      end

      catch(:found) { visit.call(start) }
    end

    # Tarjan SCC, restricted to components containing a cycle (self loops
    # included).
    #
    def strongly_connected_components
      index = 0
      indices = {}
      lowlink = {}
      stack = []
      on_stack = {}
      components = []

      visit = lambda do |node|
        indices[node] = index
        lowlink[node] = index
        index += 1
        stack << node
        on_stack[node] = true

        @edges.fetch(node, {}).keys.each do |target|
          if !indices.key?(target)
            visit.call(target)
            lowlink[node] = [lowlink[node], lowlink[target]].min
          elsif on_stack[target]
            lowlink[node] = [lowlink[node], indices[target]].min
          end
        end

        if lowlink[node] == indices[node]
          component = []
          loop do
            member = stack.pop
            on_stack[member] = false
            component << member
            break if member == node
          end

          cyclic = component.size > 1 ||
                   @edges.fetch(component.first, {}).key?(component.first)
          components << component if cyclic
        end
      end

      @edges.each_key { |node| visit.call(node) unless indices.key?(node) }
      components
    end

    def report_unknown_prefixes!
      @unknown.each do |entity_id, chains|
        name = @display[entity_id] || @entities[entity_id].name.to_s
        chains.uniq.each do |chain|
          report(:warning,
            "Cannot statically confirm that this non-consuming prefix " \
            "makes progress; the dynamic atom is not executed during the " \
            "check, so a rule returned there that matches the empty " \
            "string would form a non-consuming loop",
            [name] + chain)
        end
      end
    end

    def report(level, message, chain)
      key = [level, message, chain]
      return if @reported.key?(key)
      @reported[key] = true
      @findings << Finding.new(level, message, chain)
    end
  end
end
