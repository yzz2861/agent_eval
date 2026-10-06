# frozen_string_literal: true

# dominators.rb
#
require 'rgl/base'
require 'rgl/adjacency'
require 'rgl/traversal'
require 'set'

module RGL

  # Result of a dominator analysis rooted at one specified entry vertex.
  #
  # A vertex +u+ dominates a reachable vertex +v+ when every directed path
  # from the analysis entry to +v+ contains +u+. The immediate dominator of
  # +v+ is its closest strict dominator. Unreachable vertices are not added
  # to the analysis and do not get a virtual parent below the entry.
  class DominatorAnalysis

    UNDEFINED = BasicObject.new

    private_constant :UNDEFINED

    # @return [Object] the entry vertex at which all analyzed paths start
    attr_reader :entry

    # @param graph [Graph] a directed graph
    # @param entry [Object] a vertex in +graph+
    def initialize(graph, entry)
      raise NotDirectedError,
            "dominator analysis only works for directed graphs" unless graph.directed?
      raise NoVertexError, "No vertex #{entry}." unless graph.has_vertex?(entry)

      @graph = graph
      @entry = entry
      @postorder = []
      @postorder_number = {}
      @reachable = {}
      @predecessors = Hash.new { |hash, vertex| hash[vertex] = Set.new }
      @idom = {}
      @dominance_frontier = {}

      analyze
    end

    # @return [Set<Object>] vertices reachable from the entry
    def reachable_vertices
      @idom.keys.to_set
    end

    # @param vertex [Object]
    # @return [Boolean] whether +vertex+ is reachable from the entry
    def reachable?(vertex)
      @reachable.key?(vertex)
    end

    # @return [Hash{Object => Object,nil}] immediate dominator for every
    #   reachable vertex. The entry maps to +nil+.
    def idoms
      @idom.dup
    end

    # @param vertex [Object]
    # @return [Object, nil] the immediate dominator of +vertex+, or +nil+
    #   for the entry vertex
    def idom(vertex)
      ensure_reachable(vertex)
      @idom[vertex]
    end

    # @param dominator [Object]
    # @param vertex [Object]
    # @return [Boolean] whether +dominator+ lies on every path from the entry
    #   to +vertex+
    def dominates?(dominator, vertex)
      return false unless reachable?(dominator) && reachable?(vertex)

      current = vertex
      loop do
        return true if current == dominator
        break if current == @entry

        current = @idom[current]
      end
      false
    end

    # @param vertex [Object]
    # @return [Array<Object>] strict dominators of +vertex+, ordered from its
    #   immediate dominator to the entry
    def dominators(vertex)
      ensure_reachable(vertex)

      result = []
      current = @idom[vertex]
      while !current.nil? || current.equal?(@entry)
        result << current
        break if current == @entry

        current = @idom[current]
      end
      result
    end

    # @return [Hash{Object => Set<Object>}] dominance frontier for every
    #   reachable vertex
    def dominance_frontiers
      @dominance_frontier.dup
    end

    # @param vertex [Object]
    # @return [Set<Object>] the dominance frontier of +vertex+
    def dominance_frontier(vertex)
      ensure_reachable(vertex)
      @dominance_frontier[vertex].dup
    end

    # @return [DirectedAdjacencyGraph] the dominator tree. It contains only
    #   vertices reachable from the entry and edges from immediate dominators
    #   to the vertices they dominate.
    def dominator_tree
      tree = DirectedAdjacencyGraph.new
      @reachable.each_key { |vertex| tree.add_vertex(vertex) }
      @idom.each do |vertex, dominator|
        tree.add_edge(dominator, vertex) unless vertex == @entry
      end
      tree
    end

    private

    def analyze
      collect_reachable_graph
      compute_idoms
      compute_dominance_frontiers
      @idom[@entry] = nil
    end

    def collect_reachable_graph
      waiting = [@entry]
      @reachable[@entry] = true

      until waiting.empty?
        vertex = waiting.pop
        @graph.each_adjacent(vertex) do |neighbor|
          @predecessors[neighbor].add(vertex)
          next if @reachable.key?(neighbor)

          @reachable[neighbor] = true
          waiting << neighbor
        end
      end

      @graph.depth_first_visit(@entry, DFSVisitor.new(@graph)) do |vertex|
        @postorder << vertex
      end

      @postorder.each_with_index do |vertex, index|
        @postorder_number[vertex] = index
      end
    end

    def compute_idoms
      @reachable.each_key do |vertex|
        @idom[vertex] = vertex == @entry ? @entry : UNDEFINED
      end

      changed = true
      reverse_postorder = @postorder.reverse

      while changed
        changed = false

        reverse_postorder.each do |vertex|
          next if vertex == @entry

          processed_predecessor = @predecessors[vertex].find do |predecessor|
            !@idom[predecessor].equal?(UNDEFINED)
          end
          new_idom = processed_predecessor

          @predecessors[vertex].each do |predecessor|
            next if predecessor.equal?(processed_predecessor)
            next if @idom[predecessor].equal?(UNDEFINED)

            new_idom = intersect(predecessor, new_idom)
          end

          next if @idom[vertex].equal?(new_idom)

          @idom[vertex] = new_idom
          changed = true
        end
      end

    end

    def intersect(left, right)
      finger_left = left
      finger_right = right

      while finger_left != finger_right
        while @postorder_number[finger_left] < @postorder_number[finger_right]
          finger_left = @idom[finger_left]
        end
        while @postorder_number[finger_right] < @postorder_number[finger_left]
          finger_right = @idom[finger_right]
        end
      end

      finger_left
    end

    def compute_dominance_frontiers
      @reachable.each_key do |vertex|
        @dominance_frontier[vertex] = Set.new
        @dominance_frontier[vertex] << vertex if @predecessors[vertex].include?(vertex)
      end

      @reachable.each_key do |vertex|
        next if @predecessors[vertex].empty?

        @predecessors[vertex].each do |predecessor|
          runner = predecessor
          while runner != @idom[vertex]
            @dominance_frontier[runner] << vertex
            runner = @idom[runner]
          end
        end

        if vertex == @entry && @predecessors[@entry].any?
          @dominance_frontier[@entry] << @entry
        end
      end
    end

    def ensure_reachable(vertex)
      raise NoVertexError, "No vertex #{vertex}." unless @graph.has_vertex?(vertex)
      raise ArgumentError, "Vertex #{vertex} is not reachable from #{@entry}." unless reachable?(vertex)
    end

  end # class DominatorAnalysis

  module Graph

    # Builds a dominator analysis rooted at +entry+. The graph is not modified.
    # Only vertices reachable from +entry+ are included; disconnected vertices
    # and vertices only reachable through another entry are ignored.
    #
    # @param entry [Object] entry vertex
    # @return [DominatorAnalysis]
    # @raise [NotDirectedError] if the graph is undirected
    # @raise [NoVertexError] if +entry+ is not a vertex of the graph
    # @example Check whether a step covers every path into another step
    #   analysis = graph.dominator_analysis(:entry)
    #   analysis.dominates?(:check, :process) # true on every path
    def dominator_analysis(entry)
      DominatorAnalysis.new(self, entry)
    end

  end # module Graph

end # module RGL
