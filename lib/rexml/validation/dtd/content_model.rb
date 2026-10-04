# frozen_string_literal: false

require "strscan"
require_relative "../validationexception"
require_relative "../../xmltokens"

module REXML
  module Validation
    class DTD
      # Parsed content model of a single +<!ELEMENT>+ declaration.
      #
      # The supported content specification forms are:
      # - +EMPTY+
      # - +ANY+
      # - mixed content: +(#PCDATA)+ and +(#PCDATA | name | ...)*+
      # - element content built from element names, sequences (+,+),
      #   choices (+|+), groups and the +?+, +*+ and +++ occurrence
      #   indicators
      #
      # Element content is matched with a small epsilon-NFA (Thompson
      # construction); the document is never converted to a string and
      # matched with regular expressions.
      class ContentModel
        include XMLTokens

        EMPTY = :empty
        ANY = :any
        MIXED = :mixed
        ELEMENTS = :elements

        # Raised when an element declaration contains a content
        # specification the parser does not understand.
        class ParseError < ValidationException
        end

        # A state of the content-model NFA.  A state with a non-nil
        # #label consumes a child element with that name through
        # #transition; all other connections are epsilon transitions.
        class State
          attr_accessor :label, :transition
          attr_reader :epsilons

          def initialize(label = nil)
            @label = label
            @transition = nil
            @epsilons = []
          end
        end

        def self.parse(content_specification)
          new(content_specification)
        end

        attr_reader :kind, :allowed_names

        def initialize(content_specification)
          @spec = content_specification.strip
          @allowed_names = []
          @start = @accept = nil
          parse_specification
        end

        # Whether non-whitespace character data is allowed directly.
        def allows_text?
          @kind == MIXED or @kind == ANY
        end

        def empty?
          @kind == EMPTY
        end

        def start_state
          @start
        end

        def accept_state
          @accept
        end

        # Returns the set of NFA states reachable after consuming the
        # child element +name+, or +nil+ when +name+ is not a legal
        # successor in any of the current +states+.
        def consume(states, name)
          targets = []
          states.each do |state|
            if state.label == name
              targets << state.transition
            end
          end
          return nil if targets.empty?
          epsilon_closure(targets)
        end

        # Element names the NFA can consume from any of +states+, in
        # the order in which they appear in the content model.
        def expected_labels(states)
          labels = []
          visit_epsilon(states) do |state|
            if state.label and not labels.include?(state.label)
              labels << state.label
            end
          end
          labels
        end

        def accepting?(states)
          epsilon_closure(states).include?(@accept)
        end

        def initial_states
          epsilon_closure([@start])
        end

        private

        def parse_specification
          scanner = StringScanner.new(@spec)
          scanner.skip(/\s*/)
          if scanner.scan(/EMPTY\z/)
            @kind = EMPTY
            state = State.new
            @start = @accept = state
          elsif scanner.scan(/ANY\z/)
            @kind = ANY
          elsif scanner.check(/\(\s*#PCDATA/)
            parse_mixed(scanner)
          elsif scanner.check(/\(/)
            tree = parse_content_particle(scanner)
            scanner.skip(/\s*/)
            parse_error unless scanner.eos?
            @kind = ELEMENTS
            @start, @accept = build_fragment(tree)
          else
            parse_error
          end
        end

        # mixed ::= '(' S? '#PCDATA' (S? '|' S? Name)* S? ')*'
        #
        # The bare '(#PCDATA)' form (no repetition) is accepted as a
        # text-only model for compatibility with lenient producers.
        def parse_mixed(scanner)
          scanner.scan(/\(/) or parse_error
          scanner.skip(/\s*/)
          scanner.scan(/#PCDATA/) or parse_error
          names = []
          scanner.skip(/\s*/)
          while scanner.scan(/\|/)
            scanner.skip(/\s*/)
            name = scanner.scan(/#{NAME_STR}/) or parse_error
            names << name
            scanner.skip(/\s*/)
          end
          scanner.scan(/\)/) or parse_error
          scanner.skip(/\s*/)
          scanner.scan(/\*/)
          scanner.skip(/\s*/)
          parse_error unless scanner.eos?
          @kind = MIXED
          @allowed_names = names
        end

        # cp ::= (Name | choice | seq) ('?' | '*' | '+')?
        # All particles in one group have to use the same connector.
        def parse_content_particle(scanner)
          scanner.skip(/\s*/)
          node =
            if scanner.scan(/\(/)
              children = []
              connector = nil
              scanner.skip(/\s*/)
              children << parse_content_particle(scanner)
              scanner.skip(/\s*/)
              while (mark = scanner.scan(/[,|]/))
                if connector.nil?
                  connector = mark
                elsif mark != connector
                  parse_error
                end
                scanner.skip(/\s*/)
                children << parse_content_particle(scanner)
                scanner.skip(/\s*/)
              end
              scanner.scan(/\)/) or parse_error
              if children.length == 1
                children.first
              else
                [connector == "|" ? :choice : :sequence, children]
              end
            else
              name = scanner.scan(/#{NAME_STR}/) or parse_error
              [:name, name]
            end
          scanner.skip(/\s*/)
          if scanner.scan(/[?*+]/)
            node = [:repeat, node, scanner.matched]
          end
          node
        end

        # Builds an NFA fragment for a parsed particle and returns
        # +[start_state, accept_state]+ (Thompson construction).
        def build_fragment(node)
          case node.first
          when :name
            start = State.new(node[1])
            accept = State.new
            start.transition = accept
            [start, accept]
          when :sequence
            fragments = node[1].collect { |child| build_fragment(child) }
            (fragments.length - 1).times do |index|
              fragments[index][1].epsilons << fragments[index + 1][0]
            end
            [fragments.first[0], fragments.last[1]]
          when :choice
            start = State.new
            accept = State.new
            node[1].each do |child|
              child_start, child_accept = build_fragment(child)
              start.epsilons << child_start
              child_accept.epsilons << accept
            end
            [start, accept]
          when :repeat
            child_start, child_accept = build_fragment(node[1])
            start = State.new
            accept = State.new
            start.epsilons << child_start
            case node[2]
            when "?"
              start.epsilons << accept
              child_accept.epsilons << accept
            when "*"
              start.epsilons << accept
              child_accept.epsilons << child_start
              child_accept.epsilons << accept
            when "+"
              child_accept.epsilons << child_start
              child_accept.epsilons << accept
            end
            [start, accept]
          end
        end

        def epsilon_closure(states)
          closure = []
          visit_epsilon(states) { |state| closure << state }
          closure
        end

        # Breadth-first traversal of epsilon transitions, following
        # the insertion order so error messages keep model declaration
        # order.  Labelled states are reported but not traversed.
        def visit_epsilon(states)
          seen = {}
          queue = states.dup
          until queue.empty?
            state = queue.shift
            next if seen[state]
            seen[state] = true
            yield state
            if state.label.nil?
              state.epsilons.each { |target| queue << target }
            end
          end
        end

        def parse_error
          raise ParseError,
                "malformed element content model: #{@spec.inspect}"
        end
      end
    end
  end
end
