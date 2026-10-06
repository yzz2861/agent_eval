# frozen_string_literal: true

require 'rgl/base'
require 'rgl/traversal'

module RGL

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

    # Computes a maximum matching of the graph interpreted as a bipartite graph whose two sides
    # (partitions) are given explicitly by the caller.
    #
    # The graph must be undirected, the two sides must be disjoint and together contain exactly
    # the vertices of the graph, and every edge must connect vertices of different sides. Otherwise
    # an ArgumentError (or NotUndirectedError for a directed graph) is raised. Vertices are never
    # compared or sorted, so they don't have to be Comparable: the enumeration order of the given
    # sides and the adjacency iterators determines the (reproducible) result.
    #
    # The first side is the side of interest: if not all of its vertices can be matched, the
    # returned RGL::BipartiteMatching also exposes a Hall-deficient set of vertices of that side
    # whose neighbor set is strictly smaller than the set itself, which certifies that matching
    # all of them is impossible (Hall's theorem).
    #
    # @param first_side [Array] vertices of the side which must be fully matched
    # @param second_side [Array] vertices of the other side
    # @return [BipartiteMatching]
    # @raise [NotUndirectedError] if the graph is directed
    # @raise [ArgumentError] if the sides are invalid for the graph
    # @example
    #   matching = graph.maximum_bipartite_matching([1, 2], [3, 4])
    #   matching.size            # => number of matched pairs
    #   matching.perfect?        # => true if every vertex is matched
    #   matching.first_side_complete?
    #   matching.deficient_set   # => Hall-deficient vertices, or nil
    #   matching.neighbors_of_deficient_set
    def maximum_bipartite_matching(first_side, second_side)
      BipartiteMatchingAlgorithm.new(self, first_side, second_side).maximum_matching
    end

  end # module Graph

  # Result of {Graph#maximum_bipartite_matching}. The matched pairs can be iterated as two-element
  # arrays +[first_side_vertex, second_side_vertex]+ (the object is Enumerable).
  class BipartiteMatching
    include Enumerable

    # @return [Array] vertices of the side requested to be fully matched.
    attr_reader :first_side

    # @return [Array] vertices of the other side.
    attr_reader :second_side

    # @return [Hash] map from a matched second-side vertex to its matched first-side vertex.
    attr_reader :matching

    # @return [Array, nil] Hall-deficient vertices of the first side if it cannot be fully
    #   matched, nil otherwise.
    attr_reader :deficient_set

    # @return [Array, nil] neighbors of {#deficient_set} (all in the second side), nil if the
    #   first side can be fully matched.
    attr_reader :neighbors_of_deficient_set

    def initialize(first_side, second_side, matching, deficient_set, neighbors_of_deficient_set)
      @first_side = first_side
      @second_side = second_side
      @matching = matching
      @deficient_set = deficient_set
      @neighbors_of_deficient_set = neighbors_of_deficient_set

      @partner_of = {}
      @matching.each do |second_vertex, first_vertex|
        @partner_of[first_vertex] = second_vertex
        @partner_of[second_vertex] = first_vertex
      end
    end

    # Iterates over the matched pairs as +[first_side_vertex, second_side_vertex]+.
    def each(&block)
      return enum_for(:each) unless block_given?

      @first_side.each do |u|
        yield [u, @partner_of[u]] if @partner_of.key?(u)
      end
    end

    # @return [Array] the matched pairs as two-element arrays.
    def pairs
      to_a
    end

    # @return [Integer] number of matched pairs.
    def size
      @matching.size
    end

    alias cardinality size

    # @return [Boolean] true if every vertex of the first side is matched.
    def first_side_complete?
      @deficient_set.nil?
    end

    alias first_side_matched? first_side_complete?

    # @return [Boolean] true if every vertex of both sides is matched.
    def perfect?
      @matching.size == @first_side.size && @matching.size == @second_side.size
    end

    # @return [Object, nil] the vertex matched with +vertex+, or nil if it is unmatched.
    def partner_of(vertex)
      @partner_of[vertex]
    end

    # @return [Boolean] true if +vertex+ is incident to a matched edge.
    def matched?(vertex)
      @partner_of.key?(vertex)
    end

    # @return [Array] vertices of the first side which remain unmatched.
    def unmatched_first_side_vertices
      @first_side.reject { |u| @partner_of.key?(u) }
    end

    # @return [Array] vertices of the second side which remain unmatched.
    def unmatched_second_side_vertices
      @second_side.reject { |v| @partner_of.key?(v) }
    end

    # @return [String]
    def to_s
      "#<#{self.class.name} #{pairs.inspect}>"
    end

    alias inspect to_s

  end # class BipartiteMatching

  # Implements the {https://en.wikipedia.org/wiki/Kuhn%27s_algorithm Kuhn algorithm} (augmenting
  # path search) for maximum bipartite matching, and derives a Hall-deficient vertex set via the
  # alternating reachability argument when the requested side cannot be fully matched.
  # @see Graph#maximum_bipartite_matching
  class BipartiteMatchingAlgorithm

    # Initializes the algorithm for _graph_ with the two explicitly given partitions.
    def initialize(graph, first_side, second_side)
      raise NotUndirectedError.new('maximum bipartite matching can only be computed for an undirected graph') if graph.directed?

      @graph = graph
      @first_side = to_unique_vertices(first_side)
      @second_side = to_unique_vertices(second_side)
      validate_sides!
    end

    # Computes the maximum matching and the Hall-deficient vertex set (if any).
    # @return [BipartiteMatching]
    def maximum_matching
      # Maps a matched second-side vertex to its first-side partner.
      @matching = {}
      @matched_first = {}

      @first_side.each do |u|
        @visited = {}
        try_augment(u)
      end

      deficient_set, neighbors = find_deficient_sets unless @matching.size == @first_side.size

      BipartiteMatching.new(
        @first_side,
        @second_side,
        @matching,
        deficient_set,
        neighbors
      )
    end

    private

    # DFS augmenting-path search from a first-side vertex +u+.
    def try_augment(u)
      @graph.each_adjacent(u) do |v|
        next unless @second_set.key?(v)
        next if @visited[v]

        @visited[v] = true
        current_partner = @matching[v]
        if current_partner.nil? || try_augment(current_partner)
          @matching[v] = u
          @matched_first[u] = true
          return true
        end
      end
      false
    end

    # Alternating reachability starting from every unmatched first-side vertex:
    # follow unmatched edges towards the second side and matched edges back to the first side.
    # The reached first-side vertices form a Hall-deficient set S with N(S) equal to the reached
    # second-side vertices and |N(S)| < |S|.
    def find_deficient_sets
      reached_first = {}
      reached_second = {}

      queue = @first_side.reject { |u| @matched_first.key?(u) }
      queue.each { |u| reached_first[u] = true }

      until queue.empty?
        u = queue.shift
        @graph.each_adjacent(u) do |v|
          next unless @second_set.key?(v)
          next if reached_second.key?(v)

          reached_second[v] = true
          partner = @matching[v]
          if partner && !reached_first.key?(partner)
            reached_first[partner] = true
            queue << partner
          end
        end
      end

      [
        @first_side.select { |u| reached_first.key?(u) },
        @second_side.select { |v| reached_second.key?(v) }
      ]
    end

    def to_unique_vertices(side)
      vertices = []
      seen = {}
      side.each do |v|
        unless seen.key?(v)
          seen[v] = true
          vertices << v
        end
      end
      vertices
    end

    def validate_sides!
      @first_set = @first_side.each_with_object({}) { |u, h| h[u] = true }
      @second_set = @second_side.each_with_object({}) { |v, h| h[v] = true }

      overlap = @first_side.any? { |u| @second_set.key?(u) }
      raise ArgumentError.new('the two sides of a bipartite graph must be disjoint') if overlap

      graph_vertices = {}
      @graph.each_vertex { |v| graph_vertices[v] = true }

      @first_side.each do |v|
        unless graph_vertices.key?(v)
          raise ArgumentError.new("vertex #{vertex_description(v)} declared on the first side is not a vertex of the graph")
        end
      end

      @second_side.each do |v|
        unless graph_vertices.key?(v)
          raise ArgumentError.new("vertex #{vertex_description(v)} declared on the second side is not a vertex of the graph")
        end
      end

      undeclared = @graph.vertices.any? { |v| !@first_set.key?(v) && !@second_set.key?(v) }
      raise ArgumentError.new('the two sides must together contain every vertex of the graph') if undeclared

      @graph.each_edge do |u, v|
        same_side = (@first_set.key?(u) && @first_set.key?(v)) ||
                    (@second_set.key?(u) && @second_set.key?(v))
        if same_side
          raise ArgumentError.new("edge (#{u}, #{v}) connects vertices of the same side; only edges between the two sides are allowed")
        end
      end
    end

    def vertex_description(v)
      v.inspect
    rescue StandardError
      v.to_s
    end

  end # class BipartiteMatchingAlgorithm


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

end # module RGL
