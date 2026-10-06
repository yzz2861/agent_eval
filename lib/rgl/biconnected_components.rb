# frozen_string_literal: true

require 'rgl/base'
require 'rgl/adjacency'

module RGL

  # A biconnected component (also called a block) is represented by its
  # vertices and the edges contained in the component. A bridge is represented
  # by a component containing that edge. An isolated vertex is represented by
  # a component containing no edges.
  class BiconnectedComponent

    attr_reader :vertices, :edges

    def initialize(vertices, edges)
      @vertices = vertices
      @edges = edges
    end

    def eql?(other)
      other.is_a?(BiconnectedComponent) &&
        vertices == other.vertices &&
        edges == other.edges
    end

    alias == eql?

    def hash
      [vertices, edges].hash
    end

    def to_s
      "(#{vertices.inspect}, #{edges.map(&:to_a).inspect})"
    end

    alias inspect to_s

  end

  # Result of a single biconnectivity analysis. It contains the articulation
  # points, bridges, biconnected components, and the block-cut tree.
  class Biconnectivity

    attr_reader :articulation_points, :bridges, :biconnected_components,
                :block_cut_tree

    alias blocks biconnected_components

    def initialize(articulation_points, bridges, biconnected_components,
                   block_cut_tree)
      @articulation_points = articulation_points
      @bridges = bridges
      @biconnected_components = biconnected_components
      @block_cut_tree = block_cut_tree
    end

  end

  module Graph

    # Computes articulation points, bridges, biconnected components, and the
    # block-cut tree with one DFS per connected component.
    #
    # Each graph edge belongs to exactly one biconnected component. Isolated
    # vertices are represented by components with no edges. For a disconnected
    # graph, #block_cut_tree is a forest with one tree for each connected
    # component.
    #
    # The original graph is not modified.
    #
    # @return [Biconnectivity]
    def biconnectivity
      raise NotUndirectedError,
            'biconnectivity only works for undirected graphs.' if directed?

      BiconnectivityAnalyzer.new(self).result
    end

    # @return [Array<BiconnectedComponent>]
    def biconnected_components
      biconnectivity.biconnected_components
    end

    # @return [Array] articulation points
    def articulation_points
      biconnectivity.articulation_points
    end

    # @return [Array<UnDirectedEdge>] bridges
    def bridges
      biconnectivity.bridges
    end

    # @return [AdjacencyGraph] block-cut tree (or forest for disconnected graphs)
    def block_cut_tree
      biconnectivity.block_cut_tree
    end

  end

  # @private
  class BiconnectivityAnalyzer

    def initialize(graph)
      @graph = graph
      @edges = []
      @incident = Hash.new { |hash, vertex| hash[vertex] = [] }
      @discovery_time = {}
      @low = {}
      @timer = 0
      @edge_stack = []
      @articulation_points = []
      @articulation = {}
      @bridges = []
      @components = []
      @vertex_index = {}

      build_incidence
    end

    def result
      @incident.each_key do |root|
        next if @discovery_time.key?(root)

        child_count = dfs(root, nil, true)
        mark_articulation(root) if child_count > 1
        flush_component
      end

      add_isolated_vertex_components
      build_block_cut_tree

      Biconnectivity.new(
        @articulation_points,
        @bridges,
        @components,
        @block_cut_tree
      )
    end

    private

    def build_incidence
      edge_counts = Hash.new(0)
      self_loop_counts = Hash.new(0)

      @graph.each_vertex.with_index do |vertex, index|
        @vertex_index[vertex] = index
        @incident[vertex]
      end

      @graph.each_vertex do |source|
        @graph.each_adjacent(source) do |target|
          if source == target
            self_loop_counts[[source, target]] += 1
          else
            key = if @vertex_index[source] < @vertex_index[target]
                    [source, target]
                  else
                    [target, source]
                  end
            edge_counts[key] += 1
          end
        end
      end

      edge_counts.each do |(source, target), count|
        multiplicity = count / 2
        multiplicity.times do
          edge_id = @edges.size
          @edges << [source, target]
          @incident[source] << [target, edge_id]
          @incident[target] << [source, edge_id] unless source == target
        end
      end

      self_loop_counts.each do |(source, target), count|
        multiplicity = count.even? ? count / 2 : count

        multiplicity.times do
          edge_id = @edges.size
          @edges << [source, target]
          @incident[source] << [target, edge_id]
        end
      end
    end

    def dfs(vertex, parent_edge_id, root)
      @timer += 1
      @discovery_time[vertex] = @timer
      @low[vertex] = @timer
      child_count = 0

      @incident[vertex].each do |neighbor, edge_id|
        next if edge_id == parent_edge_id

        if !@discovery_time.key?(neighbor)
          child_count += 1
          @edge_stack << edge_id
          dfs(neighbor, edge_id, false)
          @low[vertex] = [@low[vertex], @low[neighbor]].min

          if root
            pop_component(edge_id) if child_count > 1
          elsif @low[neighbor] >= @discovery_time[vertex]
            pop_component(edge_id)
            mark_articulation(vertex)
          end

          if @low[neighbor] > @discovery_time[vertex]
            @bridges << edge_object(edge_id)
          end
        elsif @discovery_time[neighbor] <= @discovery_time[vertex]
          @edge_stack << edge_id
          @low[vertex] = [@low[vertex], @discovery_time[neighbor]].min
        end
      end

      child_count
    end

    def mark_articulation(vertex)
      return if @articulation[vertex]

      @articulation[vertex] = true
      @articulation_points << vertex
    end

    def pop_component(until_edge_id)
      edge_ids = []

      loop do
        edge_id = @edge_stack.pop
        edge_ids << edge_id
        break if edge_id == until_edge_id
      end

      add_component(edge_ids.reverse)
    end

    def flush_component
      return if @edge_stack.empty?

      add_component(@edge_stack)
      @edge_stack = []
    end

    def add_component(edge_ids)
      vertices = []
      edges = []

      edge_ids.each do |edge_id|
        source, target = @edges[edge_id]
        vertices << source unless vertices.include?(source)
        vertices << target unless vertices.include?(target)
        edges << edge_object(edge_id)
      end

      @components << BiconnectedComponent.new(vertices, edges)
    end

    def add_isolated_vertex_components
      vertices_in_components = {}
      @components.each do |component|
        component.vertices.each { |vertex| vertices_in_components[vertex] = true }
      end

      @graph.each_vertex do |vertex|
        next if vertices_in_components[vertex]

        @components << BiconnectedComponent.new([vertex], [])
      end
    end

    def build_block_cut_tree
      @block_cut_tree = AdjacencyGraph.new

      @components.each do |component|
        @block_cut_tree.add_vertex(component)

        component.vertices.each do |vertex|
          next unless @articulation[vertex]

          @block_cut_tree.add_vertex(vertex)
          @block_cut_tree.add_edge(component, vertex)
        end
      end
    end

    def edge_object(edge_id)
      source, target = @edges[edge_id]
      @graph.edge_class.new(source, target)
    end

  end

end
