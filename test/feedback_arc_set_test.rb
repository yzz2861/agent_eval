require 'test_helper'

require 'rgl/adjacency'
require 'rgl/feedback_arc_set'
require 'rgl/topsort'

include RGL

class TestFeedbackArcSet < Test::Unit::TestCase

  def graph_with(edges)
    g = DirectedAdjacencyGraph.new
    edges.each { |(u, v)| g.add_edge(u, v) }
    g
  end

  def acyclic_after_removal?(edges, removed)
    g = graph_with(edges)
    removed.each { |e| g.remove_edge(e.source, e.target) }
    g.acyclic?
  end

  def test_acyclic_graph_returns_empty_set
    edges = [[1, 2], [2, 3], [1, 3]]
    result = graph_with(edges).minimum_feedback_arc_set
    assert_equal [], result.edges
    assert_equal 0, result.cost
    assert_equal 0, result.lower_bound
    assert result.optimal?
  end

  def test_empty_graph
    result = DirectedAdjacencyGraph.new.minimum_feedback_arc_set
    assert_equal [], result.edges
    assert_equal 0, result.cost
    assert result.optimal?
  end

  def test_self_loop_is_always_removed
    edges = [[1, 1], [1, 2], [2, 3]]
    result = graph_with(edges).minimum_feedback_arc_set({ [1, 1] => 7 })
    assert_equal [Edge::DirectedEdge[1, 1]], result.edges
    assert_equal 7, result.cost
    assert_equal 7, result.lower_bound
    assert result.optimal?
  end

  def test_self_loop_plus_cycle
    edges = [[1, 1], [2, 3], [3, 2]]
    weights = { [1, 1] => 7, [2, 3] => 2, [3, 2] => 3 }
    result = graph_with(edges).minimum_feedback_arc_set(weights)
    assert_equal [Edge::DirectedEdge[1, 1], Edge::DirectedEdge[2, 3]], result.edges
    assert_equal 9, result.cost
    assert result.optimal?
    assert acyclic_after_removal?(edges, result.edges)
  end

  def test_unweighted_cycle_loses_one_edge
    edges = [[1, 2], [2, 3], [3, 1]]
    result = graph_with(edges).minimum_feedback_arc_set
    assert_equal 1, result.edges.size
    assert_equal 1, result.cost
    assert result.optimal?
    assert acyclic_after_removal?(edges, result.edges)
  end

  def test_weighted_cycle_loses_cheapest_edge
    edges = [[1, 2], [2, 3], [3, 1]]
    weights = { [1, 2] => 5, [2, 3] => 2, [3, 1] => 9 }
    result = graph_with(edges).minimum_feedback_arc_set(weights)
    assert_equal [Edge::DirectedEdge[2, 3]], result.edges
    assert_equal 2, result.cost
    assert_equal 2, result.lower_bound
    assert result.optimal?
  end

  # Two cycles overlapping in the edge 2->1 (weight 5). Removing the cheapest
  # edge of each cycle separately costs 4 + 4 = 8, while removing the shared
  # edge breaks both cycles for 5.
  def test_overlapping_cycles_prefer_shared_edge
    edges = [[1, 2], [2, 1], [1, 3], [3, 2]]
    weights = { [1, 2] => 4, [2, 1] => 5, [1, 3] => 4, [3, 2] => 4 }
    result = graph_with(edges).minimum_feedback_arc_set(weights)
    assert_equal [Edge::DirectedEdge[2, 1]], result.edges
    assert_equal 5, result.cost
    assert_equal 5, result.lower_bound
    assert result.optimal?
    assert acyclic_after_removal?(edges, result.edges)
  end

  def test_zero_weight_edges_break_cycles_for_free
    edges = [[1, 2], [2, 1]]
    result = graph_with(edges).minimum_feedback_arc_set({ [1, 2] => 0, [2, 1] => 5 })
    assert_equal [Edge::DirectedEdge[1, 2]], result.edges
    assert_equal 0, result.cost
    assert result.optimal?
  end

  def test_weights_as_callable_and_default_weight
    edges = [[1, 2], [2, 1]]
    result = graph_with(edges).minimum_feedback_arc_set(->(u, v) { u + v })
    assert_equal [Edge::DirectedEdge[1, 2]], result.edges
    assert_equal 3, result.cost
    # Unmentioned edges default to weight 1
    result = graph_with(edges).minimum_feedback_arc_set({ [2, 1] => 10 })
    assert_equal [Edge::DirectedEdge[1, 2]], result.edges
    assert_equal 1, result.cost
  end

  def dense_graph
    edges = []
    weights = {}
    4.times do |u|
      4.times do |v|
        next if u == v
        edges << [u, v]
        weights[[u, v]] = ((u * 4 + v) % 5) + 1
      end
    end
    [edges, weights]
  end

  def test_budget_exhausted_returns_feasible_solution_with_lower_bound
    edges, weights = dense_graph
    optimal = graph_with(edges).minimum_feedback_arc_set(weights)
    assert optimal.optimal?

    limited = graph_with(edges).minimum_feedback_arc_set(weights, max_iterations: 1)
    assert !limited.optimal?
    assert acyclic_after_removal?(edges, limited.edges)
    # The lower bound is comparable to both the returned and the optimal cost
    assert limited.lower_bound > 0
    assert limited.lower_bound <= limited.cost
    assert limited.lower_bound <= optimal.cost
    assert limited.cost >= optimal.cost
    assert_equal optimal.cost, optimal.lower_bound
  end

  def test_zero_budget_still_returns_greedy_solution
    edges, weights = dense_graph
    result = graph_with(edges).minimum_feedback_arc_set(weights, max_iterations: 0)
    assert !result.optimal?
    assert acyclic_after_removal?(edges, result.edges)
    assert result.lower_bound <= result.cost
  end

  def test_size_limits
    g = graph_with([[1, 2], [2, 3], [3, 1]])
    assert_raise(ArgumentError) { g.minimum_feedback_arc_set(max_vertices: 2) }
    assert_raise(ArgumentError) { g.minimum_feedback_arc_set(max_edges: 2) }
    assert_raise(ArgumentError) { g.minimum_feedback_arc_set(max_iterations: -1) }
  end

  def test_negative_weight_rejected
    g = graph_with([[1, 2], [2, 1]])
    assert_raise(ArgumentError) { g.minimum_feedback_arc_set({ [1, 2] => -1 }) }
  end

  def test_undirected_graph_rejected
    ug = AdjacencyGraph.new
    ug.add_edge(1, 2)
    assert_raise(NotDirectedError) { ug.minimum_feedback_arc_set }
  end

end
