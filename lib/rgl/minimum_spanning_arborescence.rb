# frozen_string_literal: true

require 'rgl/base'
require 'rgl/edge_properties_map'

module RGL

  # Implements the Chu–Liu/Edmonds algorithm for a minimum-cost directed
  # spanning arborescence.
  # @see Graph#minimum_spanning_arborescence
  class MinimumSpanningArborescenceAlgorithm

    # @private
    class Edge
      attr_accessor :source, :target, :weight, :edge, :original_edge

      def initialize(source, target, weight, edge, original_edge)
        @source        = source
        @target        = target
        @weight        = weight
        @edge          = edge
        @original_edge = original_edge
      end
    end

    # @private
    Supernode = Struct.new(:vertices)

    # Initializes the algorithm for a directed _graph_ with _edge_weights_map_.
    def initialize(graph, edge_weights_map, root)
      raise NotDirectedError.new('a spanning arborescence can only be found in a directed graph') unless graph.directed?
      raise ArgumentError.new("root #{root} is not a vertex of the graph") unless graph.has_vertex?(root)

      @graph             = graph
      @root              = root
      @edge_weights_map  = EdgePropertiesMap.new(edge_weights_map, true)
    end

    # Returns the edges of a minimum-cost spanning arborescence rooted at _root_.
    # The returned edges are the same edge objects returned by Graph#edges.
    def minimum_spanning_arborescence
      validate_reachable

      original_edges = @graph.edges
      edges = original_edges.map do |edge|
        weight = @edge_weights_map.edge_property(edge.source, edge.target)
        Edge.new(edge.source, edge.target, weight, nil, edge)
      end
      edges.each { |edge| edge.edge = edge }

      selected_edges = find_minimum_edges(@graph.vertices, edges, @root)
      selected_edges.map(&:original_edge)
    end

    private

    def validate_reachable
      reachable = { @root => true }
      waiting = [@root]

      until waiting.empty?
        vertex = waiting.shift
        @graph.each_adjacent(vertex) do |neighbor|
          unless reachable.key?(neighbor)
            reachable[neighbor] = true
            waiting << neighbor
          end
        end
      end

      unreachable = @graph.vertices.reject { |vertex| reachable.key?(vertex) }
      return if unreachable.empty?

      raise ArgumentError.new(
        "no spanning arborescence rooted at #{@root}: #{unreachable.join(', ')} cannot be reached"
      )
    end

    def find_minimum_edges(vertices, edges, root)
      minimum_incoming_edges = cheapest_incoming_edges(edges, root)

      missing = vertices.reject { |vertex| vertex == root || minimum_incoming_edges.key?(vertex) }
      unless missing.empty?
        raise ArgumentError.new("no spanning arborescence rooted at #{root}: #{missing.join(', ')} has no incoming edge")
      end

      cycles = find_cycles(minimum_incoming_edges)
      return minimum_incoming_edges.values if cycles.empty?

      contracted_vertices, vertex_to_supernode = contract_vertices(vertices, cycles, root)
      contracted_edges = contract_edges(edges, cycles, vertex_to_supernode, minimum_incoming_edges)
      contracted_tree = find_minimum_edges(contracted_vertices, contracted_edges, root)

      expand(contracted_tree, cycles, minimum_incoming_edges)
    end

    def cheapest_incoming_edges(edges, root)
      edges.each_with_object({}) do |edge, minimum_edges|
        next if edge.target == root

        current = minimum_edges[edge.target]
        minimum_edges[edge.target] = edge if current.nil? || edge.weight < current.weight
      end
    end

    def find_cycles(minimum_incoming_edges)
      cycles = []
      state = {}

      minimum_incoming_edges.each_key do |start_vertex|
        next if state[start_vertex]

        path = []
        positions = {}
        vertex = start_vertex

        while vertex && state[vertex].nil?
          state[vertex] = :visiting
          positions[vertex] = path.size
          path << vertex
          incoming_edge = minimum_incoming_edges[vertex]
          vertex = incoming_edge&.source
        end

        if vertex && state[vertex] == :visiting && positions.key?(vertex)
          cycles << path[positions[vertex]..]
        end

        path.each { |path_vertex| state[path_vertex] = :done }
      end

      cycles
    end

    def contract_vertices(vertices, cycles, root)
      contracted_vertices = [root]
      vertex_to_supernode = { root => root }

      cycles.each do |cycle|
        supernode = Supernode.new(cycle)
        cycle.each { |vertex| vertex_to_supernode[vertex] = supernode }
        contracted_vertices << supernode
      end

      vertices.each do |vertex|
        next if vertex == root || vertex_to_supernode.key?(vertex)

        vertex_to_supernode[vertex] = vertex
        contracted_vertices << vertex
      end

      [contracted_vertices, vertex_to_supernode]
    end

    def contract_edges(edges, cycles, vertex_to_supernode, minimum_incoming_edges)
      cycle_by_vertex = {}
      cycles.each do |cycle|
        cycle.each { |vertex| cycle_by_vertex[vertex] = cycle }
      end

      edges.filter_map do |edge|
        next if edge.target != @root && cycle_by_vertex[edge.target]&.include?(edge.source)

        source = vertex_to_supernode.fetch(edge.source)
        target = vertex_to_supernode.fetch(edge.target)
        next if source == target

        weight = edge.weight
        if target.is_a?(Supernode)
          weight -= minimum_incoming_edges[edge.target].weight
        end

        Edge.new(source, target, weight, edge, edge.original_edge)
      end
    end

    def expand(contracted_tree, cycles, minimum_incoming_edges)
      tree = []
      entered_vertices = {}

      contracted_tree.each do |edge|
        pre_contraction_edge = edge.edge
        tree << pre_contraction_edge

        cycles.each do |cycle|
          if cycle.include?(pre_contraction_edge.target) && !cycle.include?(pre_contraction_edge.source)
            entered_vertices[cycle] = pre_contraction_edge.target
          end
        end
      end

      cycles.each do |cycle|
        entered_vertex = entered_vertices[cycle]
        unless entered_vertex
          raise ArgumentError.new('contracted arborescence is missing an edge entering a cycle')
        end

        cycle.each do |vertex|
          next if vertex == entered_vertex

          tree << minimum_incoming_edges[vertex]
        end
      end

      tree
    end

  end # class MinimumSpanningArborescenceAlgorithm

  module Graph

    # Finds a minimum-cost spanning arborescence rooted at _root_.
    #
    # Returns an Array of directed edge objects from #edges. Edge weights may be
    # negative. Every vertex must be reachable from _root_; otherwise an
    # ArgumentError is raised.
    def minimum_spanning_arborescence(edge_weights_map, root)
      MinimumSpanningArborescenceAlgorithm.new(self, edge_weights_map, root).minimum_spanning_arborescence
    end

    alias minimum_arborescence minimum_spanning_arborescence

  end # module Graph

end # module RGL
