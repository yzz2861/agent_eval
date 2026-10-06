# Static analysis for parslet grammars.
#
# This file provides a grammar check that never touches business input.
# Rule definition blocks are expanded the same way they are built for a
# real parse and are inspected for combinations that can run without ever
# advancing over the input:
#
# * an infinitely repeated atom that can match the empty string (a nullable
#   repetition body, including nullability that propagates indirectly
#   through other rules),
# * cycles between rules that consume no characters (left recursion, such
#   as <tt>rule(:a) { a }</tt>).
#
# Dynamic atoms (Parslet.dynamic / Atoms::Dynamic) are never executed:
# their result is inherently input dependent, so constructs going through
# them are reported as not statically confirmable instead of guessed at.
#
# Usage:
#
#   require 'parslet/static_analysis'
#
#   class MyParser < Parslet::Parser
#     rule(:a) { str('a').repeat }
#     root(:a)
#   end
#
#   report = MyParser.new.check_grammar       # StaticAnalysis::Report
#   report.ok?                                # => true
#   MyParser.new.check_grammar!               # raises GrammarError
#
# Bracket-style right recursion such as
# <tt>rule(:pairs) { (str('(') >> pairs.maybe >> str(')')).repeat }</tt>
# consumes a character before recursing and is not flagged.
#
require 'set'
require 'parslet'

module Parslet
  class << self
    # Performs the static grammar check on +subject+ without parsing any
    # business input.
    #
    # @param subject [Parslet::Parser, Parslet::Atoms::Base]
    # @return [Parslet::StaticAnalysis::Report]
    def check_grammar(subject)
      StaticAnalysis.analyze(subject)
    end
  end

  module StaticAnalysis
    # Raised when a grammar provably contains a construct that can run
    # without consuming input.
    #
    class GrammarError < StandardError
      attr_reader :report
      def initialize(report)
        @report = report
        super(report.errors.map(&:message).join("\n"))
      end
    end

    # A single observation about a grammar. Every finding carries a #chain
    # of user declared rule names (plus the final construct) leading to the
    # flagged part of the grammar.
    #
    class Finding
      attr_reader :severity, :kind, :chain, :detail

      # @param severity [:error, :warning] +:error+ marks a provably stuck
      #   construct; +:warning+ marks a construct that cannot be confirmed
      #   because it goes through a dynamic atom.
      #
      def initialize(severity, kind, chain, detail)
        @severity = severity
        @kind     = kind
        @chain    = chain
        @detail   = detail
      end

      def chain_string
        chain.map(&:to_s).join(' -> ')
      end

      def message
        tag = severity == :error ? 'ERROR' : 'WARNING'
        "[#{tag}] #{detail} (rule chain: #{chain_string})"
      end
      alias to_s message
    end

    # Outcome of a grammar check.
    #
    class Report
      attr_reader :findings
      def initialize(findings=[])
        @findings = findings
      end

      def errors
        findings.select { |f| f.severity == :error }
      end

      def warnings
        findings.select { |f| f.severity == :warning }
      end

      def ok?
        errors.empty?
      end

      def assert!
        raise GrammarError.new(self) unless ok?
        self
      end
    end

    class << self
      # Builds a Report for the grammar reachable from +subject+. Only rule
      # definition blocks are evaluated (as during parser construction);
      # no parse input is ever read.
      #
      def analyze(subject)
        Analyzer.new(subject).report
      end
    end

    # @api private
    #
    # Collects every rule reachable from the start, records references
    # between them and solves nullability as two fixed points:
    #
    # [provable] least fixed point, dynamic atoms treated as non-nullable.
    #   Membership proves that a rule can match the empty string.
    # [optimistic] greatest fixed point, dynamic atoms treated as nullable.
    #   Membership means a rule might match the empty string; conclusions
    #   resting on a dynamic atom become warnings, not errors.
    #
    class Analyzer
      DYNAMIC_DETAIL =
        'a dynamic { ... } atom is reached here; it is only evaluated ' \
        'against parse input and was neither executed nor guessed at'

      def initialize(subject)
        @subject = subject
        # qualified rule name -> definition atom
        @definitions = {}
        # [from, to, :confirmed|:possible]
        @edges = []
        # [from, to] -> path steps within the from-rule body
        @edge_paths = {}
        # [repetition, rule, path steps]
        @repetitions = []
      end

      def report
        collect
        @provable, @optimistic = solve
        build_report
      end

      # ---- Phase 3: findings --------------------------------------------

      def build_report
        findings = []

        findings.concat(repetition_findings)
        findings.concat(cycle_findings)

        Report.new(findings.sort_by do |finding|
          [finding.severity.to_s, finding.chain_string]
        end)
      end

      def repetition_findings
        @repetitions.map do |repetition, rule, _path|
          body = repetition.parslet

          if body_nullable?(body, @provable, false)
            chain = [rule] + nullable_witness(body, Set.new)
            Finding.new(:error, :nullable_repetition, chain,
              'unbounded repetition has a body that can match the empty ' \
              'string, so it never has to advance over the input')
          elsif body_nullable?(body, @optimistic, true)
            chain = [rule] + possible_witness(body, Set.new)
            Finding.new(:warning, :unconfirmed_repetition, chain,
              'unbounded repetition has a body that might match the empty ' \
              "string, but #{DYNAMIC_DETAIL}")
          end
        end.compact
      end

      # Whether a repetition body can match the empty string. Unlike the
      # nullability of a repetition expression itself, the zero-times option
      # does not apply here: the body will in fact be invoked on every
      # iteration.
      #
      def body_nullable?(body, rules, dynamic)
        status = body_nullability(body, rules, dynamic)
        status == :nullable
      end

      def body_nullability(atom, rules, dynamic)
        case atom
        when Atoms::Repetition
          body_nullability(atom.parslet, rules, dynamic)
        when Atoms::Sequence
          combine_all(atom.parslets, rules, dynamic) do |child|
            body_nullability(child, rules, dynamic)
          end
        when Atoms::Alternative
          combine_any(atom.alternatives, rules, dynamic) do |child|
            body_nullability(child, rules, dynamic)
          end
        when Atoms::Named, Atoms::Ignored, Atoms::Capture
          body_nullability(atom.parslet, rules, dynamic)
        when Atoms::Lookahead
          # A lookahead always rewinds, so a repetition body consisting of
          # (or wrapping) a lookahead can succeed without advancing.
          :nullable
        when Atoms::Scope
          scope_body = safely { atom.block.call }
          scope_body ? body_nullability(scope_body, rules, dynamic) :
            :unknown
        else
          nullability(atom, rules, dynamic: dynamic)
        end
      end

      # Chain proving that +atom+ is nullable without using a dynamic atom.
      #
      def nullable_witness(atom, visiting)
        witness(atom, visiting, @provable, false,
          'epsilon (empty string)')
      end

      # Chain showing how +atom+ might be nullable. It ends at the dynamic
      # atom when that is what prevents a firm conclusion.
      #
      def possible_witness(atom, visiting)
        witness(atom, visiting, @optimistic, true,
          'epsilon (empty string)')
      end

      def witness(atom, visiting, rules, dynamic, _epsilon_desc)
        case atom
        when Atoms::Str
          atom.str.empty? ? ['empty string'] : []
        when Atoms::Lookahead
          [atom.positive ? 'present? (consumes nothing)' :
            'absent? (consumes nothing)']
        when Atoms::Dynamic
          ['dynamic { ... } (not executed)']
        when Atoms::Entity
          entity_witness(atom, visiting, rules, dynamic)
        when Atoms::Sequence
          atom.parslets.flat_map do |child|
            witness(child, visiting, rules, dynamic,
              'empty string')
          end
        when Atoms::Alternative
          chosen = atom.alternatives.find do |child|
            nullability(child, rules, dynamic: dynamic) == :nullable
          end
          chosen ? witness(chosen, visiting, rules, dynamic,
            'empty string') : []
        when Atoms::Repetition
          if atom.min.zero?
            # Inside a repetition body this is reached per iteration; the
            # zero-times option does not help, so continue into the body.
            witness(atom.parslet, visiting, rules, dynamic,
              'empty string')
          else
            witness(atom.parslet, visiting, rules, dynamic,
              'empty string')
          end
        when Atoms::Named, Atoms::Ignored, Atoms::Capture
          witness(atom.parslet, visiting, rules, dynamic,
            'empty string')
        when Atoms::Scope
          body = safely { atom.block.call }
          body ? witness(body, visiting, rules, dynamic,
            'empty string') : ['scope { ... }']
        when Atoms::Infix
          witness(atom.element, visiting, rules, dynamic,
            'empty string')
        when Parser
          root_entity = safely { atom.root }
          root_entity ?
            ["#{atom.class.name || atom.class.inspect}##{root_entity.name}"] :
            [atom.class.name || atom.class.inspect]
        else
          []
        end
      end

      def entity_witness(entity, visiting, rules, dynamic)
        origin = @entity_origin[entity.object_id]
        name = origin ? qualified_name(origin[0], origin[1]) :
          entity.name.to_sym

        return [name] if visiting.include?(name)

        definition = @definitions[name]
        return [name] unless definition

        nested = visiting.dup
        nested << name
        [name] + witness(definition, nested, rules, dynamic,
          'empty string')
      end

      # An edge marked :possible can be followed with zero characters
      # consumed from the start of the source rule (it sits behind an
      # all-nullable prefix). A cycle made entirely of such edges is exactly
      # a non-consuming rule loop: following it comes back to the same rule
      # at the same input position.
      #
      def cycle_findings
        graph = Hash.new { |hash, key| hash[key] = [] }

        @edges.each do |from, to, label|
          next unless label == :possible
          graph[from] << to unless graph[from].include?(to)
        end

        strongly_connected_cycles(graph).map do |cycle|
          Finding.new(:error, :non_consuming_cycle,
            cycle_chain(cycle),
            'rules refer to each other without consuming a character; ' \
            'this loop can never make progress over the input')
        end
      end

      # One representative cycle per non trivial strongly connected
      # component, using an iterative Tarjan traversal.
      #
      def strongly_connected_cycles(graph)
        nodes = (graph.keys + graph.values.flatten).uniq
        index = {}
        low = {}
        stack = []
        on_stack = Set.new
        counter = [0]
        components = []

        visit = lambda do |start|
          work = [[start, 0]]
          index[start] = low[start] = counter[0]
          counter[0] += 1
          stack << start
          on_stack << start

          until work.empty?
            node, neighbour_index = work.last

            if neighbour_index < graph[node].size
              neighbour = graph[node][neighbour_index]
              work.last[1] += 1

              if index[neighbour].nil?
                index[neighbour] = low[neighbour] = counter[0]
                counter[0] += 1
                stack << neighbour
                on_stack << neighbour
                work << [neighbour, 0]
              elsif on_stack.include?(neighbour)
                low[node] = [low[node], index[neighbour]].min
              end
            else
              if low[node] == index[node]
                component = []
                loop do
                  member = stack.pop
                  on_stack.delete(member)
                  component << member
                  break if member == node
                end
                nontrivial = component.size > 1 ||
                  graph[node].include?(node)
                components << component if nontrivial
              end

              work.pop
              parent = work.last
              if parent
                low[parent[0]] = [low[parent[0]], low[node]].min
              end
            end
          end
        end

        nodes.each { |node| visit.call(node) unless index[node] }
        components.map { |component| order_cycle(component, graph) }
      end

      # Turns an SCC into a closed path [a, b, ..., a] for reporting.
      # Every member of a strongly connected component can reach every
      # other member, so a depth first search always finds a way back.
      #
      def order_cycle(component, graph)
        members = component
        start = members.first
        path = [start]
        visited = Set.new([start])

        search = lambda do |node|
          graph[node].each do |neighbour|
            next unless members.include?(neighbour)

            if neighbour == start && path.size > 1
              return :found
            end
            next if visited.include?(neighbour)

            visited << neighbour
            path << neighbour
            if search.call(neighbour) == :found
              return :found
            end
            path.pop
            visited.delete(neighbour)
          end
          nil
        end

        search.call(start)
        path << start
        path
      end

      def cycle_chain(cycle)
        # The chain is the closed list of user declared rules.
        cycle.dup
      end

      private

      # ---- Phase 1: expand definitions, record edges -------------------

      def collect
        # parser instance id -> { rule name => entity }
        @parser_rules = {}
        # entity object id -> [owner parser, rule name]
        @entity_origin = {}

        if @subject.respond_to?(:root)
          register_parser(@subject)
        else
          @definitions[:atom] = @subject
          scan(@subject, :atom, fresh_context, nil)
        end

        queue = []
        if @subject.respond_to?(:root)
          root_entity = safely { @subject.root }
          queue << [@subject, root_entity] if root_entity
        end

        seen = Set.new
        until queue.empty?
          owner, entity = queue.shift
          next unless entity.is_a?(Atoms::Entity)

          name = qualified_name(owner, entity.name)
          next if seen.include?(name)
          seen << name

          definition = safely { entity.parslet }
          next unless definition

          # Expanding a definition can materialize more rule entities in
          # the owner's memo; sync them so references resolve correctly.
          register_parser(owner)
          @definitions[name] = definition
          scan(definition, name, fresh_context, owner)

          each_reference(definition, owner) do |ref_owner, ref_node|
            if ref_node.is_a?(Parser)
              register_parser(ref_node)
              root_entity = safely { ref_node.root }
              queue << [ref_node, root_entity] if root_entity
            elsif ref_node.is_a?(Atoms::Entity)
              queue << [ref_owner, ref_node]
            end
          end
        end
      end

      # Materializes the rule entities of +parser+ and remembers where each
      # entity comes from. Calling the memoized rule methods only builds
      # grammar atoms; it never reads parse input.
      #
      def register_parser(parser)
        @parser_rules[parser.object_id] ||= {}

        # Rule entities come into existence lazily as a grammar expands, so
        # sync any rules that have appeared in the memo since last time.
        memo = safely { parser.instance_variable_get(:@rules) }
        return unless memo

        memo.each do |rule_name, entity|
          next if @entity_origin.key?(entity.object_id)

          @parser_rules[parser.object_id][rule_name] = entity
          @entity_origin[entity.object_id] = [parser, rule_name]
        end
      end

      def fresh_context
        { nullable: true, path: [] }
      end

      # Qualified name of a rule. Rules of the subject parser keep their
      # bare name; rules of nested parsers are prefixed with the class.
      #
      def qualified_name(owner, name)
        return name.to_sym unless owner.respond_to?(:root)
        return name.to_sym if owner.equal?(@subject)

        label = owner.class.name || owner.class.inspect
        :"#{label}##{name}"
      end

      def safely
        yield
      rescue StandardError
        nil
      end

      # Yields [owner, entity_or_parser] for every rule reference or nested
      # parser contained in +atom+.
      #
      def each_reference(atom, owner, &block)
        each_node(atom, owner) do |node, node_owner|
          case node
          when Atoms::Entity then yield(node_owner, node)
          when Parser        then yield(node, node)
          end
        end
      end

      def each_node(atom, owner, &block)
        block.call(atom, owner)
        return if atom.is_a?(Parser) || atom.is_a?(Atoms::Entity)

        children_of(atom).each do |child|
          each_node(child, owner, &block)
        end
      end

      def children_of(atom)
        case atom
        when Atoms::Sequence    then atom.parslets
        when Atoms::Alternative then atom.alternatives
        when Atoms::Repetition  then [atom.parslet]
        when Atoms::Named, Atoms::Ignored, Atoms::Capture then [atom.parslet]
        when Atoms::Lookahead   then [atom.bound_parslet]
        when Atoms::Scope
          body = safely { atom.block.call }
          body ? [body] : []
        when Atoms::Infix
          [atom.element] + atom.operations.map { |op, _, _| op }
        else
          []
        end
      end

      # Context aware walk of one rule body. +nullable+ says whether the
      # current node can be reached with zero characters consumed since the
      # start of the rule; +path+ describes where it sits.
      #
      def scan(atom, rule, context, owner)
        case atom
        when Atoms::Entity
          record_reference(atom, rule, context, owner)
        when Parser
          record_nested_parser(atom, rule, context)
        when Atoms::Repetition
          record_repetition(atom, rule, context)
          scan(atom.parslet, rule, step(context, true, 'repetition body'),
            owner)
        when Atoms::Sequence
          atom.parslets.each_with_index do |child, index|
            before = atom.parslets[0...index].all? do |sibling|
              structural_nullable?(sibling)
            end
            scan(child, rule, step(context, before, "sequence[#{index}]"),
              owner)
          end
        when Atoms::Alternative
          atom.alternatives.each_with_index do |child, index|
            scan(child, rule, step(context, true, "alternative[#{index}]"),
              owner)
          end
        when Atoms::Named, Atoms::Ignored, Atoms::Capture
          scan(atom.parslet, rule, step(context, true, wrapper_desc(atom)),
            owner)
        when Atoms::Lookahead
          desc = atom.positive ? 'present?' : 'absent?'
          scan(atom.bound_parslet, rule, step(context, true, desc), owner)
        when Atoms::Scope
          body = safely { atom.block.call }
          if body
            scan(body, rule,
              step(context, structural_nullable?(body), 'scope'), owner)
          end
        when Atoms::Infix
          scan(atom.element, rule, step(context, true, 'infix element'),
            owner)
          atom.operations.each_with_index do |(op, _, _), index|
            scan(op, rule, step(context, false,
              "infix operator[#{index}]"), owner)
          end
        end
      end

      def record_reference(entity, rule, context, owner)
        target = entity_name(entity, owner)
        add_edge(rule, target, context[:nullable],
          context[:path] + [entity.name.to_s.upcase])
      end

      def record_nested_parser(parser, rule, context)
        root_entity = safely { parser.root }
        return unless root_entity

        target = qualified_name(parser, root_entity.name)
        add_edge(rule, target, context[:nullable],
          context[:path] + [parser.class.name || parser.class.inspect])
      end

      def record_repetition(atom, rule, context)
        return unless atom.max.nil?

        record = [atom, rule, context[:path] + ['repeat']]
        @repetitions << record unless @repetitions.any? do |existing|
          existing[0].equal?(atom) && existing[1] == rule
        end
      end

      def add_edge(from, to, nullable, path)
        label = nullable ? :possible : :confirmed
        unless @edges.include?([from, to, label])
          @edges << [from, to, label]
          @edge_paths[[from, to]] = path
        end
      end

      def step(context, nullable, description)
        {
          nullable: context[:nullable] && nullable,
          path: context[:path] + [description]
        }
      end

      def wrapper_desc(atom)
        case atom
        when Atoms::Named   then "as(#{atom.name.inspect})"
        when Atoms::Capture then "capture(#{atom.name.inspect})"
        else                     'ignore'
        end
      end

      def entity_name(entity, owner)
        origin = @entity_origin[entity.object_id]
        if origin
          qualified_name(origin[0], origin[1])
        else
          # The memo can gain entities while a body is expanding. Refresh
          # the owner parser before falling back to a qualified name.
          register_parser(owner) if owner.respond_to?(:root)
          origin = @entity_origin[entity.object_id]
          return qualified_name(origin[0], origin[1]) if origin

          qualified_name(owner, entity.name)
        end
      end

      # Purely structural nullability used while deciding which parts of a
      # sequence come after an already nullable prefix. Rule references and
      # dynamic atoms are optimistically nullable here; rule level results
      # are computed by the fixed points.
      #
      def structural_nullable?(atom)
        case atom
        when Atoms::Entity, Atoms::Dynamic, Atoms::Lookahead, Parser
          true
        when Atoms::Str
          atom.str.empty?
        when Atoms::Re
          false
        when Atoms::Sequence
          atom.parslets.all? { |child| structural_nullable?(child) }
        when Atoms::Alternative
          atom.alternatives.any? { |child| structural_nullable?(child) }
        when Atoms::Repetition
          atom.min.zero? || structural_nullable?(atom.parslet)
        when Atoms::Named, Atoms::Ignored, Atoms::Capture
          structural_nullable?(atom.parslet)
        when Atoms::Scope
          body = safely { atom.block.call }
          body ? structural_nullable?(body) : true
        when Atoms::Infix
          structural_nullable?(atom.element)
        else
          false
        end
      end

      # ---- Phase 2: nullability fixed points ----------------------------

      # Returns [provable_set, optimistic_set].
      #
      def solve
        provable   = least_fixed_point(false)
        optimistic = greatest_fixed_point
        [provable, optimistic]
      end

      # Least fixed point: start with nothing nullable and grow. Dynamic
      # atoms count as non-nullable, so anything derived through them is not
      # provable.
      #
      def least_fixed_point(_)
        nullable = Set.new

        loop do
          changed = false
          @definitions.each do |name, atom|
            next if nullable.include?(name)
            status = nullability(atom, nullable, dynamic: false)
            if status == :nullable
              nullable << name
              changed = true
            end
          end
          return nullable unless changed
        end
      end

      # Greatest fixed point: assume every rule is nullable and remove
      # those that cannot be. Dynamic atoms count as nullable, so a rule
      # stays in the set if it might be nullable.
      #
      def greatest_fixed_point
        nullable = Set.new(@definitions.keys)

        loop do
          changed = false
          @definitions.each do |name, atom|
            next unless nullable.include?(name)
            status = nullability(atom, nullable, dynamic: true)
            if status == :non_nullable
              nullable.delete(name)
              changed = true
            end
          end
          return nullable unless changed
        end
      end

      # Three valued structural nullability against a current rule set.
      # Returns :nullable, :unknown or :non_nullable.
      #
      def nullability(atom, rules, dynamic:)
        case atom
        when Atoms::Str
          atom.str.empty? ? :nullable : :non_nullable
        when Atoms::Re
          :non_nullable
        when Atoms::Entity
          origin = @entity_origin[atom.object_id]
          if origin.nil?
            :non_nullable
          else
            name = qualified_name(origin[0], origin[1])
            rules.include?(name) ? :nullable : :non_nullable
          end
        when Parser
          root_entity = safely { atom.root }
          root_entity && rules.include?(qualified_name(atom,
            root_entity.name)) ? :nullable : :non_nullable
        when Atoms::Lookahead
          :nullable
        when Atoms::Dynamic
          dynamic ? :nullable : :non_nullable
        when Atoms::Sequence
          combine_all(atom.parslets, rules, dynamic) { |child|
            nullability(child, rules, dynamic: dynamic) }
        when Atoms::Alternative
          combine_any(atom.alternatives, rules, dynamic) { |child|
            nullability(child, rules, dynamic: dynamic) }
        when Atoms::Repetition
          # A repetition is nullable either because it may run zero times,
          # or because its body may match empty (which lets a positive
          # repetition match empty as well).
          body_status = nullability(atom.parslet, rules, dynamic: dynamic)
          if atom.min.zero? && body_status != :nullable
            # zero repetitions allowed: nullable unless body is unknown
            body_status == :unknown ? :unknown : :nullable
          else
            body_status
          end
        when Atoms::Named, Atoms::Ignored, Atoms::Capture
          nullability(atom.parslet, rules, dynamic: dynamic)
        when Atoms::Scope
          body = safely { atom.block.call }
          body ? nullability(body, rules, dynamic: dynamic) : :unknown
        when Atoms::Infix
          nullability(atom.element, rules, dynamic: dynamic)
        else
          :non_nullable
        end
      end

      def combine_all(children, _rules, _dynamic)
        worst = :nullable
        children.each do |child|
          status = yield(child)
          worst = join_status(worst, status)
          break if worst == :non_nullable
        end
        worst
      end

      def combine_any(children, _rules, _dynamic)
        best = :non_nullable
        children.each do |child|
          status = yield(child)
          return :nullable if status == :nullable
          best = :unknown if status == :unknown
        end
        best
      end

      # Ordering for conjunction: nullable < unknown < non_nullable.
      #
      def join_status(left, right)
        rank = { nullable: 0, unknown: 1, non_nullable: 2 }
        rank[left] >= rank[right] ? left : right
      end

    end
  end
end

# Entry points on parsers and standalone atoms.
#
class Parslet::Atoms::Base
  # Runs the static check on everything reachable from this atom without
  # reading business input.
  #
  # @return [Parslet::StaticAnalysis::Report]
  def check_grammar
    Parslet::StaticAnalysis.analyze(self)
  end

  # Like #check_grammar, but raises Parslet::StaticAnalysis::GrammarError
  # when a provably non-advancing construct is present.
  #
  def check_grammar!
    check_grammar.assert!
  end
end

class Parslet::Parser
  # Runs the static check on the grammar reachable from #root. Call this at
  # startup, before parsing any business input.
  #
  # @return [Parslet::StaticAnalysis::Report]
  def check_grammar
    Parslet::StaticAnalysis.analyze(self)
  end

  # Like #check_grammar, but raises Parslet::StaticAnalysis::GrammarError
  # when a provably non-advancing construct is present. Warnings about
  # dynamic atoms do not raise.
  #
  def check_grammar!
    check_grammar.assert!
  end
end
