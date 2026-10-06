# frozen_string_literal: true

require 'rgl/dijkstra_visitor'
require 'rgl/edge_properties_map'
require 'rgl/implicit'
require 'rgl/path_builder'

require 'pairing_heap'
require 'set'

module RGL

  # This class implements {Graph#dijkstra_shortest_path} and {Graph#dijkstra_shortest_paths}
  class DijkstraAlgorithm

    # Priority used when equal-distance vertices must be returned in the order they are discovered.
    class OrderedDistance

      include Comparable

      attr_reader :distance, :order

      def initialize(distance, order)
        @distance = distance
        @order    = order
      end

      def <=>(other)
        result = distance <=> other.distance
        result.zero? ? order <=> other.order : result
      end

    end # class OrderedDistance

    # Distance combinator is a lambda that accepts the distance (usually from the source) to vertex _u_ and the weight
    # of the edge connecting vertex _u_ to another vertex _v_ and returns the distance to vertex _v_ if it's reached
    # through the vertex _u_. By default, the distance to vertex _u_ and the edge's weight are summed.
    DEFAULT_DISTANCE_COMBINATOR = lambda { |distance, edge_weight| distance + edge_weight }

    # Initializes Dijkstra's algorithm for a _graph_ with provided edges weights map.
    #
    def initialize(graph, edge_weights_map, visitor, distance_combinator = nil, ordered: false)
      @graph               = graph
      @edge_weights_map    = build_edge_weights_map(edge_weights_map)
      @visitor             = visitor
      @distance_combinator = distance_combinator || DEFAULT_DISTANCE_COMBINATOR
      @ordered             = ordered
    end

    # Finds the shortest path from the _source_ to the _target_ in the graph.
    #
    # Returns the shortest path, if it exists, as an Array of vertices. Otherwise, returns nil.
    #
    def shortest_path(source, target)
      init(source)
      relax_edges(target, true)
      PathBuilder.new(source, @visitor.parents_map).path(target)
    end

    # Finds the shortest path form the _source_ to every other vertex of the graph and builds shortest paths map.
    #
    # Returns the shortest paths map that contains the shortest path (if it exists) from the source to any vertex of the
    # graph.
    #
    def shortest_paths(source)
      find_shortest_paths(source)
      PathBuilder.new(source, @visitor.parents_map).paths(@graph.vertices)
    end

    # Finds the shortest path from the _source_ to every other vertex.
    #
    def find_shortest_paths(source)
      init(source)
      relax_edges
    end

    private

    def init(source)
      @visitor.set_source(source)

      @queue_order = 0
      @queue = PairingHeap::MinPriorityQueue.new
      @queue.push(source, queue_distance(0))
    end

    def relax_edges(target = nil, break_on_target = false)
      until @queue.empty?
        u = @queue.pop

        break if break_on_target && u == target

        @visitor.handle_examine_vertex(u)

        @graph.each_adjacent(u) do |v|
          relax_edge(u, v) unless @visitor.finished_vertex?(v)
        end

        @visitor.color_map[u] = :BLACK
        @visitor.handle_finish_vertex(u)
      end
    end

    def relax_edge(u, v)
      @visitor.handle_examine_edge(u, v)

      new_v_distance = @distance_combinator.call(@visitor.distance_map[u], @edge_weights_map.edge_property(u, v))

      if new_v_distance < @visitor.distance_map[v]
        @visitor.distance_map[v] = new_v_distance
        @visitor.parents_map[v]  = u

        new_v_distance = queue_distance(new_v_distance)

        if @visitor.color_map[v] == :WHITE
          @visitor.color_map[v] = :GRAY
          @queue.push(v, new_v_distance)
        elsif @visitor.color_map[v] == :GRAY
          @queue.decrease_key(v, new_v_distance)
        end

        @visitor.handle_edge_relaxed(u, v)
      else
        @visitor.handle_edge_not_relaxed(u, v)
      end
    end

    def build_edge_weights_map(edge_weights_map)
      edge_weights_map.is_a?(EdgePropertiesMap) ? edge_weights_map : NonNegativeEdgePropertiesMap.new(edge_weights_map, @graph.directed?)
    end

    def queue_distance(distance)
      return distance unless @ordered

      @queue_order += 1
      OrderedDistance.new(distance, @queue_order)
    end

  end # class DijkstraAlgorithm


  # Lazily enumerates simple source-to-target paths in nondecreasing order of total edge weight using
  # {https://en.wikipedia.org/wiki/Yen's_algorithm Yen's algorithm}.
  class DijkstraShortestPathEnumerator

    include Enumerable

    # Priority of a candidate path. Equal-cost paths retain the order in which they were generated.
    class CandidatePriority

      include Comparable

      attr_reader :cost, :order

      def initialize(cost, order)
        @cost  = cost
        @order = order
      end

      def <=>(other)
        result = cost <=> other.cost
        result.zero? ? order <=> other.order : result
      end

    end # class CandidatePriority

    def initialize(graph, edge_weights_map, source, target)
      @graph            = graph
      @source           = source
      @target           = target
      @edge_weights_map = build_edge_weights_map(edge_weights_map)
    end

    # Yields each simple path as an Array of vertices. Enumeration stops when the caller stops consuming the
    # enumerator, so paths after the requested one do not have to be computed.
    #
    def each
      return enum_for(:each) unless block_given?

      initial_path, initial_cost = shortest_path(@source, @graph)
      return unless initial_path

      accepted_paths = []
      known_paths    = { initial_path => true }
      candidates     = PairingHeap::MinPriorityQueue.new
      @sequence      = 0

      add_candidate(candidates, initial_path, initial_cost)

      until candidates.empty?
        path, = candidates.pop_with_priority
        yield path

        accepted_paths << path
        add_candidates(path, accepted_paths, candidates, known_paths)
      end
    end

    private

    def add_candidates(path, accepted_paths, candidates, known_paths)
      (0...path.size - 1).each do |index|
        root_path        = path[0..index]
        spur_node        = path[index]
        removed_vertices = Set.new(root_path[0...-1])
        removed_edges    = Set.new

        accepted_paths.each do |accepted_path|
          next unless accepted_path.size > index + 1 && accepted_path[0..index] == root_path

          removed_edges << edge_key(accepted_path[index], accepted_path[index + 1])
        end

        filtered_graph = filter_graph(removed_vertices, removed_edges)
        spur_path, spur_cost = shortest_path(spur_node, filtered_graph)
        next unless spur_path

        candidate_path = root_path[0...-1] + spur_path
        next if known_paths.key?(candidate_path)

        root_cost = path_cost(root_path)
        add_candidate(candidates, candidate_path, root_cost + spur_cost)
        known_paths[candidate_path] = true
      end
    end

    def add_candidate(candidates, path, cost)
      candidates.push(path, CandidatePriority.new(cost, @sequence))
      @sequence += 1
    end

    def filter_graph(removed_vertices, removed_edges)
      @graph
        .vertices_filtered_by { |vertex| !removed_vertices.include?(vertex) }
        .edges_filtered_by { |u, v| !removed_edges.include?(edge_key(u, v)) }
    end

    def shortest_path(source, graph)
      visitor   = DijkstraVisitor.new(graph)
      algorithm = DijkstraAlgorithm.new(graph, @edge_weights_map, visitor, ordered: true)
      path      = algorithm.shortest_path(source, @target)

      [path, path && visitor.distance_map[@target]]
    end

    def path_cost(path)
      path.each_cons(2).sum(0) do |u, v|
        @edge_weights_map.edge_property(u, v)
      end
    end

    def edge_key(u, v)
      @graph.directed? ? [u, v] : Edge::UnDirectedEdge.new(u, v)
    end

    def build_edge_weights_map(edge_weights_map)
      if edge_weights_map.is_a?(EdgePropertiesMap)
        edge_weights_map
      else
        NonNegativeEdgePropertiesMap.new(edge_weights_map, @graph.directed?)
      end
    end

  end # class DijkstraShortestPathEnumerator


  module Graph

    # Finds the shortest path from the _source_ to the _target_ in the graph.
    #
    # If the path exists, returns it as an Array of vertices. Otherwise, returns nil.
    #
    # Raises ArgumentError if edge weight is negative or undefined.
    #
    def dijkstra_shortest_path(edge_weights_map, source, target, visitor = DijkstraVisitor.new(self))
      DijkstraAlgorithm.new(self, edge_weights_map, visitor).shortest_path(source, target)
    end

    # Finds the shortest paths from the _source_ to each vertex of the graph.
    #
    # Returns a Hash that maps each vertex of the graph to an Array of vertices that represents the shortest path
    # from the _source_ to the vertex. If the path doesn't exist, the corresponding hash value is nil. For the _source_
    # vertex returned hash contains a trivial one-vertex path - [source].
    #
    # Raises ArgumentError if edge weight is negative or undefined.
    #
    def dijkstra_shortest_paths(edge_weights_map, source, visitor = DijkstraVisitor.new(self))
      DijkstraAlgorithm.new(self, edge_weights_map, visitor).shortest_paths(source)
    end

    # Enumerates simple paths from the _source_ to the _target_ in nondecreasing order of total edge weight.
    #
    # Returns an Enumerator when no block is given. For example, +first(3)+ returns the shortest path and the next two
    # alternatives without enumerating all remaining simple paths. Equal-cost paths are returned in a deterministic
    # order derived from graph edge iteration and candidate generation; vertices do not need to be comparable.
    #
    # Raises ArgumentError if edge weight is negative or undefined.
    #
    def each_dijkstra_shortest_path(edge_weights_map, source, target)
      enumerator = DijkstraShortestPathEnumerator.new(self, edge_weights_map, source, target)
      return enumerator unless block_given?

      enumerator.each { |path| yield path }
    end

  end # module Graph

end # module RGL
