require 'test_helper'

require 'rgl/adjacency'
require 'rgl/minimum_spanning_arborescence'

include RGL

class TestMinimumSpanningArborescence < Test::Unit::TestCase

  def test_breaks_cycle_of_cheapest_incoming_edges
    graph = DirectedAdjacencyGraph.new
    [
      [:root, :a, 10],
      [:root, :b, 100],
      [:a, :b, -5],
      [:b, :a, -5],
      [:a, :c, -2],
      [:a, :root, -100],
      [:b, :root, -100],
      [:c, :root, -100],
      [:c, :a, 100],
      [:c, :b, 100]
    ].each { |u, v, _| graph.add_edge(u, v) }
    weights = weight_map([
      [:root, :a, 10],
      [:root, :b, 100],
      [:a, :b, -5],
      [:b, :a, -5],
      [:a, :c, -2],
      [:a, :root, -100],
      [:b, :root, -100],
      [:c, :root, -100],
      [:c, :a, 100],
      [:c, :b, 100]
    ])

    tree = graph.minimum_spanning_arborescence(weights, :root)

    assert_equal(
      [
        [:a, :b],
        [:a, :c],
        [:root, :a]
      ],
      tree.map { |edge| [edge.source, edge.target] }.sort
    )
    assert_equal(3, tree.sum { |edge| weights[[edge.source, edge.target]] })
  end

  def test_expands_nested_contracted_cycles
    graph = DirectedAdjacencyGraph.new
    weighted_edges = [
      [:root, :a, 10],
      [:a, :b, 1],
      [:b, :a, 1],
      [:a, :c, 2],
      [:c, :d, 1],
      [:d, :c, 1],
      [:d, :b, 2],
      [:b, :d, 20],
      [:c, :a, 2]
    ]
    weighted_edges.each { |u, v, _| graph.add_edge(u, v) }
    weights = weight_map(weighted_edges)

    tree = graph.minimum_spanning_arborescence(weights, :root)
    optimal_trees, optimal_cost = brute_force_optimal_arborescences(graph, weights, :root)

    assert_equal(optimal_cost, tree.sum { |edge| weights[[edge.source, edge.target]] })
    assert(optimal_trees.include?(Set.new(tree)))
  end

  def test_small_graphs_match_exhaustive_optimum
    weighted_edges = [
      [:root, :a, 4],
      [:root, :b, 7],
      [:a, :b, -2],
      [:b, :a, -3],
      [:a, :root, -10],
      [:b, :root, -10],
      [:a, :c, 5],
      [:c, :a, 6],
      [:b, :c, 1],
      [:c, :b, 8],
      [:root, :c, 12],
      [:c, :root, -10]
    ]
    graph = DirectedAdjacencyGraph.new
    weighted_edges.each { |u, v, _| graph.add_edge(u, v) }
    weights = weight_map(weighted_edges)

    tree = graph.minimum_spanning_arborescence(weights, :root)
    optimal_trees, optimal_cost = brute_force_optimal_arborescences(graph, weights, :root)

    assert_equal(graph.num_vertices - 1, tree.size)
    assert_equal(optimal_cost, tree.sum { |edge| weights[[edge.source, edge.target]] })
    assert(optimal_trees.include?(Set.new(tree)))
  end

  def test_returns_edges_from_original_graph
    graph = DirectedAdjacencyGraph[:root, :a, :a, :b]
    weights = { [:root, :a] => 1, [:a, :b] => 2 }

    tree = graph.minimum_spanning_arborescence(weights, :root)
    original_edges = graph.edges

    assert_equal(original_edges.sort, tree.sort)
    assert(tree.all? { |edge| edge.is_a?(Edge::DirectedEdge) })
    assert(tree.all? { |edge| graph.has_edge?(edge.source, edge.target) })
  end

  def test_accepts_callable_weight_map_and_negative_weights
    graph = DirectedAdjacencyGraph[:root, :a, :a, :b, :b, :a]
    weights = {
      [:root, :a] => -1,
      [:a, :b] => -2,
      [:b, :a] => -3
    }
    weight_lambda = lambda { |edge| weights[edge] }

    tree = graph.minimum_spanning_arborescence(weight_lambda, :root)

    assert_equal([[:a, :b], [:root, :a]], tree.map { |edge| [edge.source, edge.target] }.sort)
    assert_equal(-3, tree.sum { |edge| weights[[edge.source, edge.target]] })
  end

  def test_raises_for_unreachable_vertex
    graph = DirectedAdjacencyGraph[:root, :a, :a, :b]
    graph.add_vertex(:isolated)
    weights = {
      [:root, :a] => 1,
      [:a, :b] => 2
    }

    error = assert_raise(ArgumentError) do
      graph.minimum_spanning_arborescence(weights, :root)
    end
    assert_match(/isolated cannot be reached/, error.message)
  end

  def test_raises_for_undirected_graph
    graph = AdjacencyGraph[:root, :a]

    assert_raise(NotDirectedError) do
      graph.minimum_spanning_arborescence({ [:root, :a] => 1 }, :root)
    end
  end

  def test_raises_for_missing_root
    graph = DirectedAdjacencyGraph[:root, :a]

    assert_raise(ArgumentError) do
      graph.minimum_spanning_arborescence({ [:root, :a] => 1 }, :missing)
    end
  end

  private

  def weight_map(weighted_edges)
    weighted_edges.each_with_object({}) do |(u, v, weight), weights|
      weights[[u, v]] = weight
    end
  end

  def brute_force_optimal_arborescences(graph, weights, root)
    edges = graph.edges
    candidates = edges.combination(graph.num_vertices - 1).select do |candidate|
      valid_arborescence?(candidate, graph.vertices, root)
    end

    optimal_cost = candidates.map { |candidate| candidate.sum { |edge| weights[[edge.source, edge.target]] } }.min
    optimal_trees = candidates.select do |candidate|
      candidate.sum { |edge| weights[[edge.source, edge.target]] } == optimal_cost
    end.map { |candidate| Set.new(candidate) }

    [optimal_trees, optimal_cost]
  end

  def valid_arborescence?(edges, vertices, root)
    targets = edges.map(&:target)
    return false unless targets.sort == (vertices - [root]).sort
    return false if edges.any? { |edge| edge.target == root }

    children = edges.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |edge, hash|
      hash[edge.source] << edge.target
    end
    visited = {}
    waiting = [root]

    until waiting.empty?
      vertex = waiting.shift
      next if visited[vertex]

      visited[vertex] = true
      waiting.concat(children[vertex])
    end

    vertices.all? { |vertex| visited[vertex] }
  end

end
