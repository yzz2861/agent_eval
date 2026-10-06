# frozen_string_literal: true

require 'rgl/base'
require 'rgl/traversal'

module RGL

  # Raised when vertices or edges do not respect a declared bipartition, e.g.
  # when a vertex is declared in both sets of a {BipartiteGraph} or an edge
  # connects two vertices of the same set.
  class NotBipartiteError < ArgumentError; end

  module Graph

    # Separates graph's vertices into two disjoint sets so that every edge of the graph connects vertices from different
    # sets. If it's possible, the graph is bipartite.
    #
    # Returns an array of two disjoint vertices sets (represented as arrays) if the graph is bipartite. Otherwise,
    # returns nil.
    # @return [Array]
    def bipartite_sets
      raise NotUndirectedError.new('bipartite sets can only be found for an undirected graph') if directed?

      bfs = BipartiteBFSIterator.new(self)

      # if necessary, we start BFS from each vertex to make sure
      # that all connected components of the graph are processed
      each_vertex do |u|
        next if bfs.finished_vertex?(u)

        bfs.reset_start(u)
        bfs.move_forward_until { bfs.found_odd_cycle }

        return if bfs.found_odd_cycle
      end

      bfs.bipartite_sets_map.inject([[], []]) do |sets, (vertex, set)|
        sets[set] << vertex
        sets
      end
    end

    # Returns true if the graph is bipartite. Otherwise returns false.
    #
    def bipartite?
      !bipartite_sets.nil?
    end

  end # module Graph


  class BipartiteBFSIterator < BFSIterator

    attr_reader :bipartite_sets_map, :found_odd_cycle

    def reset
      super

      @bipartite_sets_map = {}
      @found_odd_cycle = false
    end

    def set_to_begin
      super

      @bipartite_sets_map[@start_vertex] = 0
    end

    def reset_start(new_start)
      @start_vertex = new_start
      set_to_begin
    end

    def handle_tree_edge(u, v)
      @bipartite_sets_map[v] = (@bipartite_sets_map[u] + 1) % 2 unless u.nil?  # put v into the other set
    end

    def handle_back_edge(u, v)
      verify_odd_cycle(u, v)
    end

    def handle_forward_edge(u, v)
      verify_odd_cycle(u, v)
    end

    private

    def verify_odd_cycle(u, v)
      u_set = @bipartite_sets_map[u]
      @found_odd_cycle = true if u_set && u_set == @bipartite_sets_map[v]
    end

  end # class BipartiteBFSIterator

  # A BipartiteGraph is an undirected graph whose vertices are explicitly
  # separated by the caller into two disjoint sets (+left+ and +right+). Every
  # edge must connect a vertex of +left+ with a vertex of +right+; attempts to
  # declare a vertex in both sets or to add an edge within one set (or touching
  # an undeclared vertex) raise {NotBipartiteError}.
  #
  # Besides the usual {Graph} interface the class provides
  # {#maximum_matching}, which computes a maximum cardinality matching, and
  # {#deficient_set}, which explains why one side cannot be fully matched by
  # returning a set of vertices whose neighborhood is smaller than the set
  # itself (a Hall's theorem violator).
  #
  # Vertices may be arbitrary Ruby objects; nothing is ever sorted, so vertices
  # do not need to be comparable. All iteration follows the declaration order
  # of the vertex sets and the insertion order of the edges, which makes
  # results reproducible for a given input.
  #
  # @example
  #   graph = RGL::BipartiteGraph.new([:ticket1, :ticket2], [:agent1, :agent2])
  #   graph.add_edge(:ticket1, :agent1)
  #   graph.add_edge(:ticket2, :agent1)
  #   graph.maximum_matching  # => [[:ticket1, :agent1]]
  #   graph.deficient_set(:left) # => [:ticket1, :ticket2] (2 tickets, 1 candidate)
  class BipartiteGraph

    include Graph

    # @return [Array] vertices of the left set, in declaration order
    attr_reader :left_vertices

    # @return [Array] vertices of the right set, in declaration order
    attr_reader :right_vertices

    # Creates a bipartite graph with the given disjoint vertex sets.
    #
    # @param [Enumerable] left_vertices vertices of the left set
    # @param [Enumerable] right_vertices vertices of the right set
    # @raise [NotBipartiteError] if a vertex is declared in both sets
    def initialize(left_vertices, right_vertices)
      @left_vertices = left_vertices.to_a.uniq
      @right_vertices = right_vertices.to_a.uniq
      @side = {}
      @left_vertices.each { |v| @side[v] = :left }
      @right_vertices.each do |v|
        raise NotBipartiteError, "vertex #{v.inspect} is declared in both sets" if @side.key?(v)

        @side[v] = :right
      end
      @adjacency = {}
      each_declared_vertex { |v| @adjacency[v] = [] }
      @matching = nil
    end

    # Adds the edge +(u, v)+ to the graph. One vertex must belong to the left
    # set and the other to the right set. Adding an existing edge has no
    # effect.
    #
    # @raise [NotBipartiteError] if a vertex is undeclared or both vertices
    #   belong to the same set
    def add_edge(u, v)
      side_u = @side[u]
      side_v = @side[v]
      raise NotBipartiteError, "edge (#{u.inspect}, #{v.inspect}) touches an undeclared vertex" unless side_u && side_v
      raise NotBipartiteError, "edge (#{u.inspect}, #{v.inspect}) connects vertices of the same set" if side_u == side_v

      unless @adjacency[u].include?(v)
        @adjacency[u] << v
        @adjacency[v] << u
        @matching = nil
      end
      self
    end

    # Computes a maximum cardinality matching of the graph.
    #
    # The result neither depends on the vertices being comparable nor on hash
    # enumeration order: left vertices are visited in declaration order and
    # their neighbors in edge insertion order, so equal inputs always produce
    # equal matchings.
    #
    # @return [Array<Array>] array of +(left, right)+ vertex pairs, ordered by
    #   the declaration order of the left vertices
    def maximum_matching
      compute_matching unless @matching
      @left_vertices.select { |u| @match_left.key?(u) }.map { |u| [u, @match_left[u]] }
    end

    # Returns a set of vertices of the given side (+:left+ or +:right+) that
    # cannot all be matched because their common neighborhood is too small:
    # the returned set +S+ satisfies +|N(S)| < |S|+ (Hall's theorem). The set
    # is empty exactly when the whole side can be matched. Isolated vertices
    # of the side always belong to the set, with an empty neighborhood.
    #
    # @param [:left, :right] side the side of the bipartition to inspect
    # @return [Array] vertices of the side, in declaration order
    def deficient_set(side)
      raise ArgumentError, "side must be :left or :right, got #{side.inspect}" unless %i[left right].include?(side)

      compute_matching unless @matching
      own, matched, matched_other =
        if side == :left
          [@left_vertices, @match_left, @match_right]
        else
          [@right_vertices, @match_right, @match_left]
        end

      unmatched = own.reject { |v| matched.key?(v) }
      return [] if unmatched.empty?

      # Vertices reachable from unmatched vertices of the side via alternating
      # paths (non-matching edges forward, matching edges backward).
      seen_own = {}
      seen_other = {}
      queue = unmatched
      unmatched.each { |v| seen_own[v] = true }
      until queue.empty?
        u = queue.shift
        @adjacency[u].each do |w|
          next if matched[u] == w || seen_other[w]

          seen_other[w] = true
          x = matched_other[w]
          next if x.nil? || seen_own[x]

          seen_own[x] = true
          queue << x
        end
      end
      own.select { |v| seen_own[v] }
    end

    # Iterator for the vertices of the graph: left set first, then right set,
    # each in declaration order.
    # @see Graph#each_vertex
    def each_vertex(&block)
      return enum_for(__method__) unless block_given?

      each_declared_vertex(&block)
    end

    # Iterator for the adjacent vertices of vertex +v+, in edge insertion
    # order.
    # @see Graph#each_adjacent
    def each_adjacent(v, &block)
      raise NoVertexError, "vertex #{v.inspect} is not declared in the graph" unless @adjacency.key?(v)

      return enum_for(__method__, v) unless block_given?

      @adjacency[v].each(&block)
    end

    # Returns true if +v+ is a declared vertex of the graph.
    def has_vertex?(v)
      @side.key?(v)
    end

    private

    def each_declared_vertex(&block)
      @left_vertices.each(&block)
      @right_vertices.each(&block)
    end

    # Kuhn's augmenting path algorithm. Deterministic for a fixed declaration
    # and edge insertion order.
    def compute_matching
      @match_left = {}
      @match_right = {}
      @left_vertices.each { |u| find_augmenting_path(u, {}) }
      @matching = true
    end

    def find_augmenting_path(u, visited)
      @adjacency[u].each do |w|
        next if visited[w]

        visited[w] = true
        if !@match_right.key?(w) || find_augmenting_path(@match_right[w], visited)
          @match_left[u] = w
          @match_right[w] = u
          return true
        end
      end
      false
    end

  end # class BipartiteGraph

end # module RGL
