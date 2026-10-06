require 'test_helper'

require 'rgl/adjacency'
require 'rgl/minimum_arborescence'

include RGL
include RGL::Edge

class TestMinimumArborescence < Test::Unit::TestCase

  def test_breaks_cycle_of_cheapest_incoming_edges
    graph = DirectedAdjacencyGraph[1, 2, 1, 3, 2, 3, 3, 2]
    fixed_edges = [
      DirectedEdge.new(1, 2),
      DirectedEdge.new(1, 3),
      DirectedEdge.new(2, 3),
      DirectedEdge.new(3, 2)
    ]
    graph.define_singleton_method(:edges) { fixed_edges }
    weights = {
      [1, 2] => 5,
      [1, 3] => 6,
      [2, 3] => -10,
      [3, 2] => -10
    }

    tree = graph.minimum_cost_arborescence(weights, 1)

    assert_equal([[1, 2], [2, 3]], edge_pairs(tree).sort)
    assert_equal(-5, tree.sum { |edge| weights[[edge.source, edge.target]] })
    assert_rooted_arborescence(graph, 1, tree)
    assert(tree.all? { |edge| fixed_edges.any? { |fixed_edge| fixed_edge.equal?(edge) } })
  end

  def test_negative_weights_and_opposite_edges_match_exhaustive_solution
    edges = [1, 2, 3, 4].permutation(2).to_a
    graph = DirectedAdjacencyGraph[*edges.flatten]
    weights = {
      [1, 2] => 3,
      [1, 3] => 8,
      [1, 4] => 4,
      [2, 1] => 9,
      [2, 3] => -4,
      [2, 4] => 6,
      [3, 1] => 7,
      [3, 2] => 2,
      [3, 4] => -2,
      [4, 1] => 5,
      [4, 2] => -6,
      [4, 3] => 1
    }

    tree = graph.minimum_cost_arborescence(weights, 1)
    best_tree, best_cost = exhaustive_minimum_arborescence(graph, weights, 1)

    assert_equal(edge_pairs(best_tree).sort, edge_pairs(tree).sort)
    assert_equal(best_cost, tree.sum { |edge| weights[[edge.source, edge.target]] })
    assert_rooted_arborescence(graph, 1, tree)
    assert_equal([[1, 4], [2, 3], [4, 2]], edge_pairs(tree).sort)
  end

  def test_accepts_lambda_weights
    graph = DirectedAdjacencyGraph[1, 2, 1, 3, 2, 3, 3, 2]
    weights = lambda do |edge|
      {
        [1, 2] => 5,
        [1, 3] => 6,
        [2, 3] => -10,
        [3, 2] => -10
      }[edge]
    end

    tree = graph.minimum_cost_arborescence(weights, 1)

    assert_equal([[1, 2], [2, 3]], edge_pairs(tree).sort)
  end

  def test_directed_minimum_spanning_tree_alias
    graph = DirectedAdjacencyGraph[1, 2, 1, 3, 2, 3, 3, 2]
    weights = {
      [1, 2] => 5,
      [1, 3] => 6,
      [2, 3] => -10,
      [3, 2] => -10
    }

    tree = graph.directed_minimum_spanning_tree(weights, 1)

    assert_equal([[1, 2], [2, 3]], edge_pairs(tree).sort)
  end

  def test_multiple_disjoint_cycles
    graph = DirectedAdjacencyGraph[
      :root, :a1, :root, :b1,
      :a1, :a2, :a2, :a1,
      :b1, :b2, :b2, :b1
    ]
    weights = {
      [:root, :a1] => 1,
      [:root, :b1] => 2,
      [:a1, :a2] => -1,
      [:a2, :a1] => -1,
      [:b1, :b2] => -1,
      [:b2, :b1] => -1
    }

    tree = graph.minimum_cost_arborescence(weights, :root)

    assert_equal(4, tree.size)
    assert_rooted_arborescence(graph, :root, tree)
    assert_equal(1, tree.sum { |edge| weights[[edge.source, edge.target]] })
  end

  def test_unreachable_vertex_is_an_error
    graph = DirectedAdjacencyGraph[1, 2, 3, 2]
    weights = { [1, 2] => 1, [3, 2] => 1 }

    error = assert_raises(ArgumentError) do
      graph.minimum_cost_arborescence(weights, 1)
    end

    assert_equal('vertices 3 are not reachable from root 1', error.message)
  end

  def test_missing_root_is_an_error
    graph = DirectedAdjacencyGraph[1, 2]

    error = assert_raises(ArgumentError) do
      graph.minimum_cost_arborescence({ [1, 2] => 1 }, 3)
    end

    assert_equal('root vertex 3 is not a vertex of the graph', error.message)
  end

  def test_requires_directed_graph
    graph = AdjacencyGraph[1, 2]

    assert_raises(NotDirectedError) do
      graph.minimum_cost_arborescence({ [1, 2] => 1 }, 1)
    end
  end

  def test_missing_edge_weight_is_an_error
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 2]
    weights = { [1, 2] => 1, [2, 3] => 1 }

    assert_raises(ArgumentError, 'property of edge (3, 2) is not defined') do
      graph.minimum_cost_arborescence(weights, 1)
    end
  end

  private

  def exhaustive_minimum_arborescence(graph, weights, root)
    incoming_edges = graph.edges
                           .reject { |edge| edge.target == root }
                           .group_by(&:target)
    choices = graph.vertices.reject { |vertex| vertex == root }.map { |vertex| incoming_edges.fetch(vertex) }

    choices.first.product(*choices.drop(1)).map do |candidate|
      next unless rooted_arborescence?(graph, root, candidate)

      cost = candidate.sum { |edge| weights[[edge.source, edge.target]] }
      [candidate, cost]
    end.compact.min_by(&:last)
  end

  def assert_rooted_arborescence(graph, root, edges)
    assert(rooted_arborescence?(graph, root, edges))
  end

  def rooted_arborescence?(graph, root, edges)
    return false unless edges.size == graph.num_vertices - 1

    children = Hash.new { |hash, key| hash[key] = [] }
    edges.each { |edge| children[edge.source] << edge.target }

    visited = {}
    pending = [root]

    until pending.empty?
      vertex = pending.shift
      next if visited.key?(vertex)

      visited[vertex] = true
      pending.concat(children[vertex])
    end

    graph.vertices.all? { |vertex| visited.key?(vertex) }
  end

  def edge_pairs(edges)
    edges.map { |edge| [edge.source, edge.target] }
  end

end
