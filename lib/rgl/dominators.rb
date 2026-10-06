# frozen_string_literal: true

require 'set'
require 'rgl/base'

module RGL

  # Computes dominators for the vertices reachable from a specified start
  # vertex in a directed graph.
  #
  # A vertex +d+ dominates a vertex +v+ when every directed path from the start
  # vertex to +v+ contains +d+. The immediate dominator of +v+ is its closest
  # strict dominator. Vertices that are not reachable from the start vertex are
  # not included in the result.
  class DominatorAnalysis

    # @return [Object] the entry vertex from which dominators are computed
    attr_reader :start_vertex

    # @return [Set] vertices reachable from the start vertex
    def reachable_vertices
      @reachable_vertices.dup
    end

    # Computes dominator information for _graph_ starting at _start_vertex_.
    #
    # @param [Graph] graph a directed graph
    # @param [Object] start_vertex a vertex in _graph_
    def initialize(graph, start_vertex)
      raise NotDirectedError, 'dominator analysis only works for directed graphs' unless graph.directed?
      raise NoVertexError, "No vertex #{start_vertex}." unless graph.has_vertex?(start_vertex)

      @graph = graph
      @start_vertex = start_vertex
      analyze
    end

    # @return [Boolean] whether _vertex_ is reachable from the start vertex
    def reachable?(vertex)
      @reachable_vertices.include?(vertex)
    end

    # Returns the immediate (closest strict) dominator of _vertex_. Returns nil
    # for the start vertex. Raises ArgumentError for an unreachable vertex.
    #
    # @param [Object] vertex a reachable vertex
    # @return [Object, nil]
    def immediate_dominator(vertex)
      ensure_reachable(vertex)
      @immediate_dominators.fetch(vertex)
    end

    alias idom immediate_dominator
    alias direct_dominator immediate_dominator

    # @return [Hash{Object => Object,nil}] a map from each reachable vertex to
    #   its immediate dominator. The start vertex maps to nil.
    def immediate_dominators
      @immediate_dominators.dup
    end

    alias direct_dominators immediate_dominators

    # Returns all dominators of _vertex_. By default the vertex itself is
    # included because dominance is reflexive.
    #
    # @param [Object] vertex a reachable vertex
    # @param [Boolean] include_self whether to include _vertex_
    # @return [Set]
    def dominators(vertex, include_self: true)
      ensure_reachable(vertex)

      result = Set.new
      current = vertex

      while current
        result << current
        current = @immediate_dominators[current]
      end

      result.delete(vertex) unless include_self
      result
    end

    # @return [Boolean] whether _dominator_ dominates _vertex_
    # @param [Boolean] include_self whether a vertex dominates itself
    def dominates?(dominator, vertex, include_self: true)
      ensure_reachable(dominator)
      ensure_reachable(vertex)
      return true if dominator == vertex && include_self
      return false if dominator == vertex

      dominators(vertex).include?(dominator)
    end

    # @return [Boolean] whether _dominator_ strictly dominates _vertex_
    def strictly_dominates?(dominator, vertex)
      dominates?(dominator, vertex, include_self: false)
    end

    # Returns the dominance frontier of _vertex_. A vertex +w+ is in the
    # frontier when _vertex_ dominates a predecessor of +w+ but does not
    # strictly dominate +w+.
    #
    # @param [Object] vertex a reachable vertex
    # @return [Set]
    def dominance_frontier(vertex)
      ensure_reachable(vertex)
      @dominance_frontiers.fetch(vertex).dup
    end

    # @return [Hash{Object => Set}] the dominance frontier of every reachable
    #   vertex
    def dominance_frontiers
      @dominance_frontiers.transform_values(&:dup)
    end

    private

    def analyze
      @reachable_vertices, @predecessors = collect_reachable_graph
      reverse_postorder = collect_reverse_postorder
      postorder = reverse_postorder.reverse
      postorder_number = {}
      postorder.each_with_index { |vertex, index| postorder_number[vertex] = index }

      compute_immediate_dominators(reverse_postorder, postorder_number)
      compute_dominance_frontiers
    end

    def collect_reachable_graph
      reachable = Set.new
      predecessors = Hash.new { |hash, key| hash[key] = Set.new }
      stack = [@start_vertex]

      until stack.empty?
        vertex = stack.pop
        next if reachable.include?(vertex)

        reachable << vertex
        predecessors[vertex]

        @graph.each_adjacent(vertex) do |successor|
          predecessors[successor] << vertex
          stack << successor unless reachable.include?(successor)
        end
      end

      [reachable, predecessors]
    end

    def collect_reverse_postorder
      postorder = []
      scheduled = Set[@start_vertex]
      stack = [[@start_vertex, false]]

      until stack.empty?
        vertex, finished = stack.pop

        if finished
          postorder << vertex
          next
        end

        stack << [vertex, true]

        @graph.each_adjacent(vertex) do |successor|
          next unless @reachable_vertices.include?(successor)
          next if scheduled.include?(successor)

          scheduled << successor
          stack << [successor, false]
        end
      end

      postorder.reverse
    end

    def compute_immediate_dominators(reverse_postorder, postorder_number)
      @immediate_dominators = { @start_vertex => @start_vertex }
      changed = true

      while changed
        changed = false

        reverse_postorder[1..].each do |vertex|
          processed_predecessor = @predecessors[vertex].find { |predecessor| @immediate_dominators.key?(predecessor) }
          new_idom = processed_predecessor

          @predecessors[vertex].each do |predecessor|
            next unless @immediate_dominators.key?(predecessor)

            new_idom = intersect(predecessor, new_idom, postorder_number)
          end

          if @immediate_dominators[vertex] != new_idom
            @immediate_dominators[vertex] = new_idom
            changed = true
          end
        end
      end

      @immediate_dominators[@start_vertex] = nil
    end

    def intersect(first, second, postorder_number)
      finger1 = first
      finger2 = second

      while finger1 != finger2
        while postorder_number[finger1] < postorder_number[finger2]
          finger1 = @immediate_dominators[finger1]
        end

        while postorder_number[finger2] < postorder_number[finger1]
          finger2 = @immediate_dominators[finger2]
        end
      end

      finger1
    end

    def compute_dominance_frontiers
      @dominance_frontiers = {}
      @reachable_vertices.each { |vertex| @dominance_frontiers[vertex] = Set.new }

      @reachable_vertices.each do |vertex|
        next unless vertex == @start_vertex || @predecessors[vertex].size >= 2

        @predecessors[vertex].each do |predecessor|
          runner = predecessor

          while runner && runner != @immediate_dominators[vertex]
            @dominance_frontiers[runner] << vertex
            runner = @immediate_dominators[runner]
          end
        end
      end
    end

    def ensure_reachable(vertex)
      raise NoVertexError, "No vertex #{vertex}." unless @graph.has_vertex?(vertex)
      raise ArgumentError, "#{vertex} is not reachable from #{@start_vertex}" unless reachable?(vertex)
    end

  end # class DominatorAnalysis

  module Graph

    # Builds a {DominatorAnalysis} starting at _start_vertex_.
    #
    # @return [DominatorAnalysis]
    def dominator_analysis(start_vertex)
      DominatorAnalysis.new(self, start_vertex)
    end

    # Returns the immediate dominator of every vertex reachable from
    # _start_vertex_. The start vertex maps to nil.
    #
    # @return [Hash{Object => Object,nil}]
    def immediate_dominators(start_vertex)
      dominator_analysis(start_vertex).immediate_dominators
    end

  end # module Graph

end # module RGL
