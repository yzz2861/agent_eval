# frozen_string_literal: true

# isomorphism.rb

require 'rgl/base'

module RGL

  # Raised by {Graph#isomorphism_mapping} and {Graph#isomorphic?} when the
  # search limit given by the +:max_states+ option is exhausted before the
  # search space has been fully explored. In this case nothing can be said
  # about whether the graphs are isomorphic; the exception deliberately
  # distinguishes "unknown" from "definitely not isomorphic" (which is
  # reported by a +nil+ / +false+ result).
  class IsomorphismSearchLimitExceeded < RuntimeError; end

  module Graph

    # Returns true if the graph is isomorphic to +other+. See
    # {#isomorphism_mapping} for the semantics of the comparison and the
    # supported options.
    #
    # @param [Graph] other the graph to compare with
    # @return [bool] true if the graphs are isomorphic
    # @raise [IsomorphismSearchLimitExceeded] if the search limit is exhausted
    def isomorphic?(other, vertex_label: nil, edge_label: nil, max_states: nil)
      !isomorphism_mapping(other,
                           vertex_label: vertex_label,
                           edge_label:   edge_label,
                           max_states:   max_states).nil?
    end

    # Tests whether the graph is isomorphic to +other+, i.e. whether there is
    # a bijection between the vertex sets that preserves the adjacency
    # structure. Works for directed as well as undirected graphs; two graphs
    # with different +directed?+ properties are never isomorphic.
    #
    # The vertex objects (IDs) themselves never take part in the structural
    # comparison; only the graph topology and the caller supplied labels are
    # compared. This makes the method suitable for comparing graphs that were
    # exported from different environments with unrelated vertex IDs.
    #
    # Self loops are supported. Parallel edges are supported as well
    # (multigraph semantics): edges are matched by their multiplicity, so two
    # graphs are only isomorphic if corresponding vertex pairs are connected
    # by the same number of parallel edges. Note that edge labels are
    # compared per (ordered) vertex pair, not per individual parallel edge.
    #
    # On success a Hash mapping each vertex of this graph to the
    # corresponding vertex of +other+ is returned. If the graphs are
    # definitely not isomorphic, +nil+ is returned.
    #
    # Symmetric structures may admit a huge number of candidate mappings. The
    # +:max_states+ option limits the number of candidate assignments the
    # backtracking search examines. If the limit is exhausted the search
    # raises {IsomorphismSearchLimitExceeded} instead of reporting the graphs
    # as non-isomorphic.
    #
    # @param [Graph] other the graph to compare with
    # @param [Proc, Array] vertex_label +nil+, a callable +label.call(vertex)+
    #   used for both graphs, or a pair +[for_self, for_other]+ of callables.
    #   Vertices are only matched when their labels are equal.
    # @param [Proc, Array] edge_label +nil+, a callable
    #   +label.call(source, target)+ used for both graphs, or a pair
    #   +[for_self, for_other]+ of callables. Edges are only matched when
    #   their labels are equal. The callable is only invoked for vertex pairs
    #   that are actually connected by at least one edge.
    # @param [Integer, nil] max_states maximum number of candidate
    #   assignments examined during the search; +nil+ means no limit
    # @return [Hash, nil] vertex mapping from this graph to +other+, or +nil+
    #   if the graphs are not isomorphic
    # @raise [IsomorphismSearchLimitExceeded] if the search limit is exhausted
    #
    # @example
    #   g1 = RGL::DirectedAdjacencyGraph[1, 2, 2, 3]
    #   g2 = RGL::DirectedAdjacencyGraph['a', 'b', 'b', 'c']
    #   g1.isomorphism_mapping(g2) # => {1 => 'a', 2 => 'b', 3 => 'c'}
    def isomorphism_mapping(other, vertex_label: nil, edge_label: nil, max_states: nil)
      return nil unless other.is_a?(Graph) && directed? == other.directed?

      IsomorphismSearch.new(self, other, vertex_label, edge_label, max_states).run
    end

  end # module Graph

  # Backtracking search for a graph isomorphism. Used by
  # {Graph#isomorphism_mapping}; not part of the public API.
  #
  # Vertices of the source graph are assigned in order of decreasing degree
  # (most constrained first). A candidate target vertex must have the same
  # signature (label, in/out degree, self loop multiplicity) and must be
  # consistent with every already assigned vertex regarding edge
  # multiplicities and edge labels in both directions.
  class IsomorphismSearch

    def initialize(graph, other, vertex_label, edge_label, max_states)
      unless max_states.nil? || (max_states.is_a?(Integer) && max_states >= 0)
        raise ArgumentError, 'max_states must be a non-negative Integer or nil'
      end

      @graph1 = graph
      @graph2 = other
      @vertex_label1, @vertex_label2 = normalize_labeler(vertex_label)
      @edge_label1, @edge_label2 = normalize_labeler(edge_label)
      @max_states = max_states
      @states = 0
    end

    # @return [Hash, nil] the vertex mapping, or nil if no isomorphism exists
    # @raise [IsomorphismSearchLimitExceeded] if the search limit is exhausted
    def run
      prepare
      return nil unless feasible?

      @mapping = {}
      @used = {}
      search(0)
    end

    private

    def normalize_labeler(labeler)
      return [nil, nil] if labeler.nil?
      return labeler if labeler.is_a?(Array) && labeler.size == 2

      [labeler, labeler]
    end

    def prepare
      @adj1 = adjacency_multiplicities(@graph1)
      @adj2 = adjacency_multiplicities(@graph2)
      @vertices1 = @adj1.keys
      @vertices2 = @adj2.keys
      @signatures1 = signatures(@vertices1, @adj1, @vertex_label1)
      @signatures2 = signatures(@vertices2, @adj2, @vertex_label2)
      @candidates = @vertices2.group_by { |v| @signatures2[v] }
      # Most constrained vertices first; the index keeps the order
      # deterministic for equally constrained vertices.
      degrees = Hash.new { |hash, key| hash[key] = degree(key, @adj1) }
      @order = @vertices1.each_with_index
                         .sort_by { |v, i| [-degrees[v], i] }
                         .map(&:first)
    end

    # Adjacency as nested hashes of edge multiplicities:
    # result[u][v] is the number of edges from u to v. For undirected graphs
    # the adjacency lists are symmetric, so the result is symmetric as well.
    def adjacency_multiplicities(graph)
      adj = {}
      graph.each_vertex { |v| adj[v] = Hash.new(0) }
      graph.each_vertex do |u|
        graph.each_adjacent(u) { |v| adj[u][v] += 1 }
      end
      adj
    end

    def signatures(vertices, adj, vertex_label)
      result = {}
      vertices.each do |v|
        in_degree = 0
        adj.each_value { |row| in_degree += row[v] }
        result[v] = [
          vertex_label && vertex_label.call(v),
          degree(v, adj),
          in_degree,
          adj[v][v] # self loop multiplicity
        ]
      end
      result
    end

    def degree(vertex, adj)
      adj[vertex].values.inject(0, :+)
    end

    # Cheap necessary conditions, checked before the backtracking search.
    def feasible?
      return false unless @vertices1.size == @vertices2.size
      return false unless edge_count(@adj1) == edge_count(@adj2)

      signature_tally(@signatures1.values) == signature_tally(@signatures2.values)
    end

    def edge_count(adj)
      adj.values.inject(0) { |sum, row| sum + row.values.inject(0, :+) }
    end

    def signature_tally(signatures)
      signatures.each_with_object(Hash.new(0)) { |sig, tally| tally[sig] += 1 }
    end

    def search(depth)
      return @mapping.dup if depth == @order.size

      source = @order[depth]
      (@candidates[@signatures1[source]] || []).each do |target|
        next if @used[target]

        @states += 1
        if @max_states && @states > @max_states
          raise IsomorphismSearchLimitExceeded,
                "isomorphism search limit of #{@max_states} states exceeded"
        end

        next unless consistent?(source, target)

        @mapping[source] = target
        @used[target] = true
        result = search(depth + 1)
        return result if result

        @mapping.delete(source)
        @used.delete(target)
      end
      nil
    end

    # Checks whether assigning source -> target is consistent with all
    # previously assigned vertices (edge multiplicities and edge labels in
    # both directions) and with the self loop of source.
    def consistent?(source, target)
      if @edge_label1 && @adj1[source][source] > 0 &&
         @edge_label1.call(source, source) != @edge_label2.call(target, target)
        return false
      end

      @mapping.each do |u1, u2|
        forward1 = @adj1[source][u1]
        forward2 = @adj2[target][u2]
        return false unless forward1 == forward2

        if forward1 > 0 && @edge_label1 &&
           @edge_label1.call(source, u1) != @edge_label2.call(target, u2)
          return false
        end

        backward1 = @adj1[u1][source]
        backward2 = @adj2[u2][target]
        return false unless backward1 == backward2

        if backward1 > 0 && @edge_label1 &&
           @edge_label1.call(u1, source) != @edge_label2.call(u2, target)
          return false
        end
      end
      true
    end

  end # class IsomorphismSearch

end # module RGL
