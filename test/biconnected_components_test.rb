# frozen_string_literal: true

require 'test_helper'

require 'rgl/adjacency'
require 'rgl/biconnected_components'
require 'rgl/connected_components'

include RGL

class TestBiconnectedComponents < Test::Unit::TestCase

  def edge_pairs(edges)
    edges.map { |edge| edge.to_a.sort }.sort
  end

  def component_pairs(result)
    result.biconnected_components.map do |component|
      edge_pairs(component.edges)
    end.sort
  end

  def connected_component_count(graph)
    count = 0
    graph.each_connected_component { count += 1 }
    count
  end

  def graph_without_vertex(graph, vertex)
    copy = graph.dup
    copy.remove_vertex(vertex)
    copy
  end

  def graph_without_edge(graph, edge)
    copy = graph.dup
    copy.remove_edge(edge.source, edge.target)
    copy
  end

  def test_empty_graph
    graph = AdjacencyGraph.new
    result = graph.biconnectivity

    assert_equal([], result.articulation_points)
    assert_equal([], result.bridges)
    assert_equal([], result.biconnected_components)
    assert_equal([], result.block_cut_tree.vertices)
    assert_equal(0, result.block_cut_tree.num_edges)
  end

  def test_isolated_vertices_have_empty_components
    graph = AdjacencyGraph.new
    graph.add_vertex(1)
    graph.add_vertex(2)
    result = graph.biconnectivity

    assert_equal([], result.articulation_points)
    assert_equal([], result.bridges)
    assert_equal([[[1], []], [[2], []]].sort,
                 result.biconnected_components.map { |component|
                   [component.vertices, component.edges]
                 }.sort)
    assert_equal(2, result.block_cut_tree.num_vertices)
    assert_equal(0, result.block_cut_tree.num_edges)
    assert_equal(2, connected_component_count(result.block_cut_tree))
  end

  def test_self_loops_are_components_and_are_not_bridges_or_articulations
    graph = AdjacencyGraph.new
    graph.add_edge(1, 1)
    graph.add_edge(2, 2)
    graph.add_vertex(3)
    result = graph.biconnectivity

    assert_equal([], result.articulation_points)
    assert_equal([], result.bridges)
    assert_equal([[[1, 1]], [[2, 2]], []].sort,
                 component_pairs(result))
    assert_equal(3, result.block_cut_tree.num_vertices)
    assert_equal(0, result.block_cut_tree.num_edges)
    assert_equal(3, connected_component_count(result.block_cut_tree))
  end

  def test_parallel_self_loops_share_their_vertex_block
    graph = AdjacencyGraph.new(Array)
    graph.add_edge(1, 1)
    graph.add_edge(1, 1)
    result = graph.biconnectivity

    assert_equal([], result.articulation_points)
    assert_equal([], result.bridges)
    assert_equal([[[1, 1], [1, 1]]], component_pairs(result))
    assert_equal(1, result.block_cut_tree.num_vertices)
  end

  def test_disconnected_graph_returns_a_block_cut_forest
    graph = AdjacencyGraph.new
    [[1, 2], [2, 3], [3, 1], [5, 5], [6, 7]].each do |edge|
      graph.add_edge(*edge)
    end
    graph.add_vertex(4)
    result = graph.biconnectivity

    assert_equal([], result.articulation_points.sort)
    assert_equal([[6, 7]], edge_pairs(result.bridges))
    assert_equal([[[1, 2], [1, 3], [2, 3]], [[5, 5]], [[6, 7]], []].sort,
                 component_pairs(result))
    assert_equal(4, result.block_cut_tree.num_vertices)
    assert_equal(0, result.block_cut_tree.num_edges)
    assert_equal(4, connected_component_count(result.block_cut_tree))
  end

  def test_articulation_points_bridges_and_block_cut_tree
    graph = AdjacencyGraph.new
    [[1, 2], [2, 3], [3, 1], [3, 4], [4, 5], [5, 6], [6, 4]].each do |edge|
      graph.add_edge(*edge)
    end
    result = graph.biconnectivity

    assert_equal([3, 4], result.articulation_points.sort)
    assert_equal([[3, 4]], edge_pairs(result.bridges))
    assert_equal([
      [[1, 2], [1, 3], [2, 3]],
      [[3, 4]],
      [[4, 5], [4, 6], [5, 6]]
    ], component_pairs(result))

    block_cut_tree = result.block_cut_tree
    assert_equal(5, block_cut_tree.num_vertices)
    assert_equal(4, block_cut_tree.num_edges)
    assert_equal(1, connected_component_count(block_cut_tree))

    result.biconnected_components.each do |component|
      component.vertices.each do |vertex|
        next unless result.articulation_points.include?(vertex)

        assert(block_cut_tree.has_edge?(component, vertex))
      end
    end
  end

  def test_dfs_root_uses_child_count_for_articulation_detection
    star = AdjacencyGraph.new
    [[1, 2], [1, 3], [1, 4]].each { |edge| star.add_edge(*edge) }
    result = star.biconnectivity

    assert_equal([1], result.articulation_points)
    assert_equal([[[1, 2]], [[1, 3]], [[1, 4]]], component_pairs(result))
    assert_equal(4, result.block_cut_tree.num_vertices)
    assert_equal(3, result.block_cut_tree.num_edges)

    triangle = AdjacencyGraph.new
    [[1, 2], [2, 3], [3, 1]].each { |edge| triangle.add_edge(*edge) }
    triangle_result = triangle.biconnectivity

    assert_equal([], triangle_result.articulation_points)
    assert_equal([], triangle_result.bridges)
    assert_equal(1, triangle_result.block_cut_tree.num_vertices)
  end

  def test_dfs_root_with_one_child_is_not_an_articulation_point
    path = AdjacencyGraph.new
    [[1, 2], [2, 3]].each { |edge| path.add_edge(*edge) }
    result = path.biconnectivity

    assert_equal([2], result.articulation_points)
    assert_equal([[1, 2], [2, 3]], edge_pairs(result.bridges))
    assert_equal(3, result.block_cut_tree.num_vertices)
    assert_equal(2, result.block_cut_tree.num_edges)
  end

  def test_parallel_edges_are_not_bridges
    graph = AdjacencyGraph.new(Array)
    graph.add_edge(1, 2)
    graph.add_edge(1, 2)
    graph.add_edge(2, 3)
    result = graph.biconnectivity

    assert_equal([2], result.articulation_points)
    assert_equal([[2, 3]], edge_pairs(result.bridges))
    assert_equal([[[1, 2], [1, 2]], [[2, 3]]], component_pairs(result))
  end

  def test_deleting_reported_critical_vertices_and_edges_increases_components
    graph = AdjacencyGraph.new
    [[1, 2], [2, 3], [3, 1], [3, 4], [4, 5], [5, 6], [6, 4], [7, 7]].each do |edge|
      graph.add_edge(*edge)
    end
    graph.add_vertex(8)
    result = graph.biconnectivity
    original_count = connected_component_count(graph)

    graph.vertices.each do |vertex|
      count = connected_component_count(graph_without_vertex(graph, vertex))

      if result.articulation_points.include?(vertex)
        assert_operator(count, :>, original_count)
      else
        assert_operator(count, :<=, original_count)
      end
    end

    graph.edges.each do |edge|
      count = connected_component_count(graph_without_edge(graph, edge))

      if result.bridges.include?(edge)
        assert_operator(count, :>, original_count)
      else
        assert_equal(original_count, count)
      end
    end
  end

  def test_every_edge_belongs_to_exactly_one_component
    graph = AdjacencyGraph.new
    [[1, 2], [2, 3], [3, 1], [3, 4], [4, 4]].each { |edge| graph.add_edge(*edge) }
    result = graph.biconnectivity
    component_edges = result.biconnected_components.flat_map(&:edges)

    assert_equal(edge_pairs(graph.edges), edge_pairs(component_edges))
    assert_equal(graph.edges.size, component_edges.size)
  end

  def test_analysis_does_not_modify_the_original_graph
    graph = AdjacencyGraph.new
    [[1, 2], [2, 3], [3, 1], [4, 4]].each { |edge| graph.add_edge(*edge) }
    graph.add_vertex(5)
    vertices = graph.vertices.sort
    edges = edge_pairs(graph.edges)
    adjacency = graph.vertices.map { |vertex| [vertex, graph.adjacent_vertices(vertex).sort] }.sort

    graph.biconnectivity

    assert_equal(vertices, graph.vertices.sort)
    assert_equal(edges, edge_pairs(graph.edges))
    assert_equal(adjacency,
                 graph.vertices.map { |vertex|
                   [vertex, graph.adjacent_vertices(vertex).sort]
                 }.sort)
  end

  def test_convenience_accessors
    graph = AdjacencyGraph.new
    graph.add_edge(1, 2)

    assert_equal(graph.biconnectivity.articulation_points,
                 graph.articulation_points)
    assert_equal(graph.biconnectivity.bridges,
                 graph.bridges)
    assert_equal(graph.biconnectivity.biconnected_components,
                 graph.biconnected_components)
    assert_equal(graph.biconnectivity.block_cut_tree,
                 graph.block_cut_tree)
  end

  def test_directed_graphs_are_rejected
    graph = DirectedAdjacencyGraph.new
    graph.add_edge(1, 2)

    assert_raises(NotUndirectedError) { graph.biconnectivity }
  end

end
