# frozen_string_literal: true

require 'rgl/adjacency'
require 'rgl/connected_components'
require 'set'

module RGL

  # Node used in a block-cut tree to distinguish articulation vertices from
  # biconnected component (block) nodes.
  class BlockCutNode
    attr_reader :type, :value

    def initialize(type, value)
      @type = type
      @value = value
    end

    def articulation?
      type == :articulation
    end

    def block?
      type == :block
    end

    def ==(other)
      other.is_a?(BlockCutNode) &&
        type == other.type &&
        value == other.value
    end

    alias eql? ==

    def hash
      [type, value].hash
    end

    def inspect
      "#{type}(#{value.inspect})"
    end

    alias to_s inspect
  end

  # Result returned by Graph#biconnected_components.
  class BiconnectedComponentsResult

    # @return [Set] articulation vertices
    attr_reader :articulation_points

    # @return [Array<Edge::UnDirectedEdge>] bridges in DFS discovery order
    attr_reader :bridges

    # @return [Array<Array>] biconnected components in completion order
    attr_reader :components

    # @return [AdjacencyGraph] block-cut forest
    attr_reader :block_cut_tree

    def initialize(articulation_points, bridges, components)
      @articulation_points = articulation_points
      @bridges = bridges
      @components = components
      @block_nodes = {}
      @articulation_nodes = {}
      build_block_cut_tree
    end

    # @return [Hash{Edge::UnDirectedEdge => Integer}] mapping from an edge to its component id
    def component_map
      @component_map ||= @components.each_with_index.flat_map do |component, id|
        edge_component?(component) ? component.map { |edge| [edge, id] } : []
      end.to_h
    end

    # @return [Hash{Object => Integer}] mapping from an isolated vertex to its component id
    def isolated_vertex_map
      @isolated_vertex_map ||= @components.each_with_index.each_with_object({}) do |(component, id), result|
        result[component.first] = id if isolated_component?(component)
      end
    end

    # @return [Array<Object>] vertices without incident edges
    def isolated_vertices
      isolated_vertex_map.keys
    end

    # @return [Array<Integer>] ids of components containing no edges
    def isolated_vertex_component_ids
      isolated_vertex_map.values
    end

    def block_node(component_id)
      @block_nodes[component_id]
    end

    def articulation_node(vertex)
      @articulation_nodes[vertex]
    end

    private

    def build_block_cut_tree
      @block_cut_tree = AdjacencyGraph.new

      @components.each_with_index do |component, id|
        block = add_node(:block, id, @block_nodes)
        next if isolated_component?(component)

        component_vertices(component).each do |vertex|
          next unless @articulation_points.include?(vertex)

          articulation = add_node(:articulation, vertex, @articulation_nodes)
          @block_cut_tree.add_edge(block, articulation)
        end
      end
    end

    def component_vertices(component)
      component.flat_map do |edge|
        edge.source == edge.target ? [edge.source] : [edge.source, edge.target]
      end.uniq
    end

    def isolated_component?(component)
      component.size == 1 && !component.first.is_a?(Edge::UnDirectedEdge)
    end

    def edge_component?(component)
      !isolated_component?(component)
    end

    def add_node(type, value, nodes)
      nodes[value] ||= begin
        node = BlockCutNode.new(type, value)
        @block_cut_tree.add_vertex(node)
        node
      end
    end

  end

  module Graph

    # Finds articulation vertices, bridges, biconnected components, and the
    # block-cut forest of an undirected graph.
    #
    # Every edge belongs to exactly one edge-containing component. A self-loop
    # is returned as a one-edge component. Every isolated vertex is returned as
    # a one-vertex component. The block-cut forest contains one block node per
    # component, one node per articulation vertex, and edges from each
    # articulation vertex to the blocks that contain it.
    #
    # The receiver is not modified.
    #
    # @return [BiconnectedComponentsResult]
    def biconnected_components
      raise NotUndirectedError,
            'biconnected_components only works for undirected graphs.' if directed?

      BiconnectedComponentsAnalyzer.new(self).analyze
    end

  end

  class BiconnectedComponentsAnalyzer

    def initialize(graph)
      @graph = graph
      @discovery_time = {}
      @low = {}
      @parent = {}
      @timer = 0
      @edge_stack = []
      @components = []
      @bridges = []
      @articulation_points = Set.new
      @adjacency = Hash.new { |hash, vertex| hash[vertex] = [] }
      build_internal_adjacency
    end

    def analyze
      @graph.each_vertex do |vertex|
        next if @discovery_time.key?(vertex)

        @parent[vertex] = nil
        @root_children = 0
        dfs(vertex)
      end

      add_isolated_vertex_components
      result = BiconnectedComponentsResult.new(
        @articulation_points,
        @bridges,
        @components
      )
      result
    end

    private

    def dfs(vertex)
      @timer += 1
      @discovery_time[vertex] = @timer
      @low[vertex] = @timer

      @adjacency[vertex].each do |edge, neighbor, multiplicity|

        if vertex == neighbor
          push_edge(edge)
          pop_component(edge)
          next
        end

        if undiscovered?(neighbor)
          @parent[neighbor] = vertex
          @root_children += 1 if @parent[vertex].nil?
          push_edge(edge)
          dfs(neighbor)
          @low[vertex] = [@low[vertex], @low[neighbor]].min

          if bridge?(vertex, neighbor)
            @articulation_points.add(vertex) if articulation_vertex?(vertex)
            @bridges << edge
            pop_component(edge)
          elsif @parent[vertex].nil? && @root_children > 1
            @articulation_points.add(vertex)
            pop_component(edge)
          elsif !@parent[vertex].nil? && @low[neighbor] >= @discovery_time[vertex]
            @articulation_points.add(vertex)
            pop_component(edge)
          end
        elsif @discovery_time[neighbor] < @discovery_time[vertex] &&
              !(neighbor == @parent[vertex] && multiplicity == 1)
          push_edge(edge)
          @low[vertex] = [@low[vertex], @discovery_time[neighbor]].min
        end
      end

      pop_remaining_root_component if @parent[vertex].nil?
    end

    def bridge?(vertex, neighbor)
      @low[neighbor] > @discovery_time[vertex]
    end

    def articulation_vertex?(vertex)
      @parent[vertex].nil? ? @root_children > 1 : true
    end

    def undiscovered?(vertex)
      !@discovery_time.key?(vertex)
    end

    def push_edge(edge)
      @edge_stack << edge unless @edge_stack.include?(edge)
    end

    def pop_component(edge)
      component = []
      loop do
        stacked_edge = @edge_stack.pop
        component.unshift(stacked_edge)
        break if stacked_edge.nil? || stacked_edge == edge
      end
      @components << component unless component.empty?
    end

    def pop_remaining_root_component
      return if @edge_stack.empty?

      @components << @edge_stack
      @edge_stack = []
    end

    def add_isolated_vertex_components
      @graph.each_vertex do |vertex|
        has_incident_edge = false
        @graph.each_adjacent(vertex) do |neighbor|
          has_incident_edge = true
          break
        end
        @components << [vertex] unless has_incident_edge
      end
    end

    def build_internal_adjacency
      edge_multiplicity = Hash.new(0)
      @graph.each_vertex do |vertex|
        @graph.each_adjacent(vertex) do |neighbor|
          edge_multiplicity[[vertex, neighbor]] += 1
        end
        edge_multiplicity[[vertex, vertex]] /= 2 if edge_multiplicity.key?([vertex, vertex])
      end

      @graph.each_edge do |source, target|
        edge = @graph.edge_class.new(source, target)
        multiplicity = edge_multiplicity[[source, target]].nonzero? || 1
        @adjacency[source] << [edge, target, multiplicity]
        @adjacency[target] << [edge, source, multiplicity] unless source == target
      end
    end
  end
end
