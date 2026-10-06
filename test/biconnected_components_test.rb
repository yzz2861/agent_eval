# frozen_string_literal: true

require 'test_helper'

require 'rgl/adjacency'
require 'rgl/biconnected_components'

class TestBiconnectedComponents < Test::Unit::TestCase

  def setup
    @graph = RGL::AdjacencyGraph.new
    [[1, 2], [2, 3], [3, 1], [3, 4], [4, 5], [5, 6], [6, 4], [6, 7]].each do |edge|
      @graph.add_edge(*edge)
    end
    @graph.add_vertex(8)
  end

  def test_articulation_points_bridges_and_components
    result = @graph.biconnected_components

    assert_equal(Set[3, 4, 6], result.articulation_points)
    assert_equal(
      sorted_edges([edge(3, 4), edge(6, 7)]),
      sorted_edges(result.bridges)
    )
    assert_equal(
      [
        [edge(1, 2), edge(2, 3), edge(1, 3)],
        [edge(4, 5), edge(5, 6), edge(4, 6)],
        [edge(6, 7)],
        [edge(3, 4)],
        [8]
      ].map { |component| normalized_component(component) }.to_set,
      normalized_components(result).to_set
    )
    assert_equal({ 8 => 4 }, result.isolated_vertex_map)
    assert_equal([8], result.isolated_vertices)
  end

  def test_every_edge_belongs_to_exactly_one_component
    result = @graph.biconnected_components
    component_edges = result.component_map.keys

    assert_equal(sorted_edges(@graph.edges), sorted_edges(component_edges))
    assert_equal(@graph.num_edges, result.component_map.size)
  end

  def test_removing_articulation_vertex_increases_component_count
    result = @graph.biconnected_components

    result.articulation_points.each do |vertex|
      without_vertex = @graph.to_adjacency
      without_vertex.remove_vertex(vertex)

      assert(
        connected_components(without_vertex).size > connected_components_in_original_component(vertex),
        "expected removing #{vertex.inspect} to increase connected component count"
      )
    end
  end

  def test_non_articulation_vertex_removal_does_not_split_its_component
    non_articulation = [1, 2, 5, 7]

    non_articulation.each do |vertex|
      original_count = connected_components_in_original_component(vertex)
      without_vertex = @graph.to_adjacency
      without_vertex.remove_vertex(vertex)
      components = connected_components(without_vertex)
      affected_count = components.count { |component| component != [8] }

      assert_equal(original_count, affected_count, "removing #{vertex.inspect} split its component")
    end
  end

  def test_removing_bridge_increases_component_count
    result = @graph.biconnected_components

    result.bridges.each do |bridge|
      without_edge = @graph.to_adjacency
      without_edge.remove_edge(bridge.source, bridge.target)

      assert_equal(3, connected_components(without_edge).size)
    end
  end

  def test_removing_non_bridge_does_not_increase_component_count
    result = @graph.biconnected_components
    bridges = result.bridges

    @graph.edges.each do |graph_edge|
      next if bridges.include?(graph_edge)

      without_edge = @graph.to_adjacency
      without_edge.remove_edge(graph_edge.source, graph_edge.target)

      assert_equal(2, connected_components(without_edge).size)
    end
  end

  def test_block_cut_forest
    result = @graph.biconnected_components
    tree = result.block_cut_tree

    assert_equal(8, tree.num_vertices)
    assert_equal(6, tree.num_edges)
    expected_edges = [
      [block_node(result, [edge(1, 2), edge(2, 3), edge(1, 3)]), result.articulation_node(3)],
      [block_node(result, [edge(3, 4)]), result.articulation_node(3)],
      [block_node(result, [edge(3, 4)]), result.articulation_node(4)],
      [block_node(result, [edge(4, 5), edge(5, 6), edge(4, 6)]), result.articulation_node(4)],
      [block_node(result, [edge(4, 5), edge(5, 6), edge(4, 6)]), result.articulation_node(6)],
      [block_node(result, [edge(6, 7)]), result.articulation_node(6)]
    ]
    expected_tree_edges = expected_edges.map { |u, v| Set[u, v] }
    actual_tree_edges = tree.edges.map { |tree_edge| Set[tree_edge.source, tree_edge.target] }
    assert_equal(Set.new(expected_tree_edges), Set.new(actual_tree_edges))
  end

  def test_empty_graph
    result = RGL::AdjacencyGraph.new.biconnected_components

    assert_empty(result.articulation_points)
    assert_empty(result.bridges)
    assert_empty(result.components)
    assert_empty(result.isolated_vertices)
    assert(result.block_cut_tree.empty?)
  end

  def test_isolated_vertices_self_loops_and_disconnected_components
    graph = RGL::AdjacencyGraph.new
    graph.add_vertex(:isolated)
    graph.add_edge(:self, :self)
    graph.add_edge(:root, :root)
    graph.add_edge(:root, :left)
    graph.add_edge(:root, :right)
    graph.add_edge(:cycle_a, :cycle_b)
    graph.add_edge(:cycle_b, :cycle_c)
    graph.add_edge(:cycle_c, :cycle_a)
    graph.add_edge(:bridge_left, :bridge_right)

    result = graph.biconnected_components

    assert_equal(Set[:root], result.articulation_points)
    assert_equal(
      [
        [edge(:self, :self)],
        [edge(:root, :root)],
        [edge(:root, :left)],
        [edge(:root, :right)],
        [edge(:cycle_a, :cycle_b), edge(:cycle_b, :cycle_c), edge(:cycle_c, :cycle_a)],
        [edge(:bridge_left, :bridge_right)],
        [:isolated]
      ].map { |component| normalized_component(component) }.to_set,
      normalized_components(result).to_set
    )
    assert_equal(
      [edge(:root, :left), edge(:root, :right), edge(:bridge_left, :bridge_right)],
      result.bridges
    )
    assert_equal([:isolated], result.isolated_vertices)
    assert_equal(5, tree_connected_components(result.block_cut_tree).size)
    root_block = result.block_node(result.components.index { |component| component == [edge(:root, :root)] })
    assert_include(result.block_cut_tree.adjacent_vertices(root_block), result.articulation_node(:root))
  end

  def test_self_loop_with_array_adjacency_list
    graph = RGL::AdjacencyGraph.new(Array)
    graph.add_edge(:vertex, :vertex)

    result = graph.biconnected_components

    assert_equal([[edge(:vertex, :vertex)]], normalized_components(result))
    assert_empty(result.articulation_points)
    assert_empty(result.bridges)
  end

  def test_self_loop_does_not_change_connectivity_when_removed
    graph = RGL::AdjacencyGraph.new
    graph.add_edge(:vertex, :vertex)
    result = graph.biconnected_components

    without_self_loop = graph.to_adjacency
    without_self_loop.remove_edge(:vertex, :vertex)

    assert_empty(result.articulation_points)
    assert_empty(result.bridges)
    assert_equal(1, connected_components(without_self_loop).size)
  end

  def test_parallel_edges_are_not_bridges
    graph = RGL::AdjacencyGraph.new(Array)
    graph.add_edge(1, 2)
    graph.add_edge(2, 1)
    graph.add_edge(2, 3)

    result = graph.biconnected_components

    assert_equal(Set[2], result.articulation_points)
    assert_equal([edge(2, 3)], result.bridges)
    assert_equal(1, result.component_map.keys.count { |component_edge| component_edge == edge(1, 2) })
  end

  def test_directed_graph_is_rejected
    graph = RGL::DirectedAdjacencyGraph.new
    graph.add_edge(1, 2)

    assert_raise(RGL::NotUndirectedError) { graph.biconnected_components }
  end

  def test_original_graph_is_not_modified
    vertices = @graph.vertices
    edges = @graph.edges

    @graph.biconnected_components

    assert_equal(vertices, @graph.vertices)
    assert_equal(edges, @graph.edges)
  end

  private

  def edge(source, target)
    RGL::Edge::UnDirectedEdge.new(source, target)
  end

  def normalized_components(result)
    result.components.map do |component|
      normalized_component(component)
    end
  end

  def normalized_component(component)
    return component if component.size == 1 && !component.first.is_a?(RGL::Edge::UnDirectedEdge)

    component.map { |component_edge| component_edge.to_a.sort }
             .sort
             .map { |source, target| edge(source, target) }
  end

  def sorted_edges(edges)
    edges.map { |graph_edge| graph_edge.to_a.sort }.sort
  end

  def block_node(result, expected_component)
    component_id = result.components.index do |component|
      next false unless component.first.is_a?(RGL::Edge::UnDirectedEdge)

      component.map { |component_edge| component_edge.to_a.sort }.sort ==
        expected_component.map { |component_edge| component_edge.to_a.sort }.sort
    end
    result.block_node(component_id)
  end

  def connected_components(graph)
    components = []
    graph.each_connected_component { |component| components << component.sort }
    components
  end

  def tree_connected_components(graph)
    components = []
    graph.each_connected_component { |component| components << component }
    components
  end

  def connected_components_in_original_component(vertex)
    connected_components(@graph).count { |component| component.include?(vertex) }
  end
end
