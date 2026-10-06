# frozen_string_literal: true

require 'rgl/base'
require 'rgl/edge_properties_map'

module RGL

  # Implements Edmonds' (Chu–Liu/Edmonds) minimum-cost arborescence algorithm.
  # @see Graph#minimum_cost_arborescence
  class MinimumArborescenceAlgorithm

    CandidateEdge = Struct.new(:source, :target, :weight, :original_edge, :parent_edge)

    # Initializes the algorithm for a directed _graph_ with provided edge weights map.
    #
    def initialize(graph, edge_weights_map, root)
      unless graph.directed?
        raise NotDirectedError.new(
          'minimum-cost arborescence can only be computed for a directed graph'
        )
      end

      @graph             = graph
      @edge_weights_map  = EdgePropertiesMap.new(edge_weights_map, true)
      @root              = root
    end

    # Returns the minimum-cost rooted arborescence as an array of original edge objects.
    #
    def minimum_cost_arborescence
      validate_root
      validate_reachability

      edges = @graph.edges.map do |edge|
        weight = @edge_weights_map.edge_property(edge.source, edge.target)
        next if edge.source == edge.target

        CandidateEdge.new(edge.source, edge.target, weight, edge, nil)
      end.compact

      solve(@graph.vertices, @root, edges).map(&:original_edge)
    end

    private

    def validate_root
      return if @graph.has_vertex?(@root)

      raise ArgumentError.new("root vertex #{@root} is not a vertex of the graph")
    end

    def validate_reachability
      reachable = { @root => true }
      pending   = [@root]

      until pending.empty?
        vertex = pending.shift

        @graph.each_adjacent(vertex) do |neighbor|
          next if reachable.key?(neighbor)

          reachable[neighbor] = true
          pending << neighbor
        end
      end

      unreachable = @graph.vertices.reject { |vertex| reachable.key?(vertex) }
      return if unreachable.empty?

      raise ArgumentError.new("vertices #{unreachable.map(&:inspect).join(', ')} are not reachable from root #{@root.inspect}")
    end

    def solve(vertices, root, edges)
      selected_incoming_edges = cheapest_incoming_edges(root, edges)
      cycles = selected_cycles(selected_incoming_edges)

      return selected_incoming_edges.values if cycles.empty?

      component_for       = {}
      cycle_vertices      = {}
      contracted_vertices = []

      cycles.each do |cycle|
        component = Object.new
        contracted_vertices << component
        cycle_vertices[component] = cycle
        cycle.each { |vertex| component_for[vertex] = component }
      end

      vertices.each do |vertex|
        next if component_for.key?(vertex)

        component_for[vertex] = vertex
        contracted_vertices << vertex
      end

      contracted_edges = edges.filter_map do |edge|
        source_component = component_for[edge.source]
        target_component = component_for[edge.target]
        next if source_component == target_component

        adjusted_weight = edge.weight
        adjusted_weight -= selected_incoming_edges[edge.target].weight if cycle_vertices.key?(target_component)

        CandidateEdge.new(
          source_component,
          target_component,
          adjusted_weight,
          edge.original_edge,
          edge
        )
      end

      contracted_tree = solve(
        contracted_vertices,
        component_for[root],
        contracted_edges
      )

      expand(contracted_tree, cycle_vertices, selected_incoming_edges)
    end

    def cheapest_incoming_edges(root, edges)
      selected = {}

      edges.each do |edge|
        next if edge.target == root

        current = selected[edge.target]
        next if current && current.weight <= edge.weight

        selected[edge.target] = edge
      end

      selected
    end

    def selected_cycles(selected)
      state  = Hash.new(:unvisited)
      cycles = []

      selected.each_key do |start|
        next unless state[start] == :unvisited

        path   = []
        vertex = start

        while vertex && state[vertex] == :unvisited
          state[vertex] = :visiting
          path << vertex
          edge = selected[vertex]
          vertex = edge&.source
        end

        if vertex && state[vertex] == :visiting
          cycle_start = path.index(vertex)
          cycles << path[cycle_start..]
        end

        path.each { |member| state[member] = :visited }
      end

      cycles
    end

    def expand(contracted_tree, cycle_vertices, selected_incoming_edges)
      entering_edges = contracted_tree.group_by(&:target)
      expanded       = contracted_tree.map(&:parent_edge)

      cycle_vertices.each do |component, cycle|
        entering_edge = entering_edges.fetch(component).first

        cycle.each do |vertex|
          next if vertex == entering_edge.parent_edge.target

          expanded << selected_incoming_edges[vertex]
        end
      end

      expanded
    end

  end # class MinimumArborescenceAlgorithm

  module Graph

    # Finds the minimum-cost directed spanning tree rooted at _root_.
    #
    # Edge weights may be negative. Edges are selected in their directed source-to-target order, so edges (u, v) and
    # (v, u) are considered independently. Returns the selected edges from {#edges}.
    #
    # Raises NotDirectedError if the graph is not directed.
    # Raises ArgumentError if _root_ is missing, an edge weight is undefined,
    # or any vertex cannot be reached from _root_.
    #
    # @return [Array] original edge objects of the graph
    def minimum_cost_arborescence(edge_weights_map, root)
      MinimumArborescenceAlgorithm.new(self, edge_weights_map, root).minimum_cost_arborescence
    end

    alias directed_minimum_spanning_tree minimum_cost_arborescence

  end # module Graph

end # module RGL
