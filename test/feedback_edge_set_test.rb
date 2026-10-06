# frozen_string_literal: true

require 'test_helper'

require 'rgl/adjacency'
require 'rgl/topsort'
require 'rgl/feedback_edge_set'

include RGL

class TestMinimumFeedbackEdgeSet < Test::Unit::TestCase

  # Builds a directed graph from [u, v, weight] triples and returns [graph, weights].
  def build_graph(rows)
    graph = DirectedAdjacencyGraph.new
    weights = {}
    rows.each do |u, v, weight|
      graph.add_edge(u, v)
      weights[[u, v]] = weight
    end
    [graph, weights]
  end

  # Removes the given edges from a copy of the graph and asserts that the
  # remainder is a DAG.
  def assert_breaking_edges(graph, edges)
    remainder = DirectedAdjacencyGraph.new
    removed = edges.map(&:to_a)
    graph.each_edge do |u, v|
      remainder.add_edge(u, v) unless removed.include?([u, v])
    end
    assert remainder.acyclic?, 'the reported feedback edge set must break every cycle'
  end

  def test_empty_graph_returns_empty_set
    result = DirectedAdjacencyGraph.new.minimum_feedback_edge_set

    assert_equal [], result.edges
    assert_equal 0, result.cost
    assert_equal 0, result.cost_lower_bound
    assert result.optimal?
    assert_equal 0, result.optimality_gap
    assert !result.budget_exhausted
  end

  def test_acyclic_graph_returns_empty_set
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 1, 3, 3, 4]

    result = graph.minimum_feedback_edge_set

    assert_equal [], result.edges
    assert_equal 0, result.cost
    assert result.optimal?
  end

  def test_single_self_loop_is_always_removed
    graph, weights = build_graph([[:v, :v, 7], [:v, :a, 1], [:a, :b, 1]])

    result = graph.minimum_feedback_edge_set(weights)

    assert_equal [[:v, :v]], result.edges.map(&:to_a)
    assert_equal 7, result.cost
    assert result.optimal?
    assert_breaking_edges(graph, result.edges)
  end

  def test_self_loops_are_forced_even_when_expensive
    # The cheap non-loop edge belongs to no cycle; both self-loops have to go.
    graph, weights = build_graph([[:x, :x, 100], [:y, :y, 50], [:x, :y, 1]])

    result = graph.minimum_feedback_edge_set(weights)

    assert_equal [[:x, :x], [:y, :y]], result.edges.map(&:to_a)
    assert_equal 150, result.cost
    assert_equal 150, result.cost_lower_bound
    assert result.optimal?
  end

  def test_simple_cycle_picks_cheapest_edge
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]
    weights = { [1, 2] => 10, [2, 3] => 1, [3, 1] => 2 }

    result = graph.minimum_feedback_edge_set(weights)

    assert_equal [[2, 3]], result.edges.map(&:to_a)
    assert_equal 1, result.cost
    assert_equal 1, result.cost_lower_bound
    assert result.optimal?
  end

  def test_overlapping_cycles_prefers_shared_expensive_edge
    # Three cycles share the edge s -> t. Deleting it (cost 5) breaks all
    # three cycles; deleting the cheapest edge of every single cycle costs
    # 3 + 3 + 3 = 9 and is what a purely greedy strategy would do.
    rows = [
      [:s, :t, 5],
      [:t, :a1, 3], [:a1, :s, 4],
      [:t, :a2, 3], [:a2, :s, 4],
      [:t, :a3, 3], [:a3, :s, 4],
    ]
    graph, weights = build_graph(rows)

    # Sanity check: the greedy upper bound is indeed suboptimal here.
    solver = MinimumFeedbackEdgeSet.new(graph, weights)
    greedy = solver.send(:greedy_feedback_edges, solver.send(:build_adjacency))
    assert_equal 9, greedy.sum { |u, v| weights[[u, v]] }

    result = graph.minimum_feedback_edge_set(weights)

    assert_equal [[:s, :t]], result.edges.map(&:to_a)
    assert_equal 5, result.cost
    assert_equal 5, result.cost_lower_bound
    assert_equal 0, result.optimality_gap
    assert result.optimal?
    assert_breaking_edges(graph, result.edges)
  end

  def test_overlapping_cycles_with_a_self_loop
    rows = [
      [:s, :t, 5],
      [:t, :a1, 3], [:a1, :s, 4],
      [:t, :a2, 3], [:a2, :s, 4],
      [:z, :z, 2],
    ]
    graph, weights = build_graph(rows)

    result = graph.minimum_feedback_edge_set(weights)

    assert_equal [[:s, :t], [:z, :z]], result.edges.map(&:to_a)
    assert_equal 7, result.cost
    assert result.optimal?
    assert_breaking_edges(graph, result.edges)
  end

  def test_zero_node_budget_returns_greedy_solution_without_proof
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]
    weights = { [1, 2] => 10, [2, 3] => 1, [3, 1] => 2 }

    result = graph.minimum_feedback_edge_set(weights, max_nodes: 0)

    assert !result.optimal?
    assert result.budget_exhausted
    assert result.cost_lower_bound <= result.cost
    assert_breaking_edges(graph, result.edges)
  end

  def test_exhausted_budget_reports_comparable_lower_bound
    # Theta graph: two edge-disjoint cycles share only vertex c. The packing
    # lower bound sums the per-cycle minima (1 + 1) and the cheapest feasible
    # set costs 2. Limit the search so that it must stop mid-way.
    rows = [
      [:a, :b, 1], [:b, :c, 10], [:c, :a, 10],
      [:c, :d, 1], [:d, :e, 10], [:e, :c, 10],
    ]
    graph, weights = build_graph(rows)

    result = graph.minimum_feedback_edge_set(weights, max_nodes: 1)

    assert_breaking_edges(graph, result.edges)
    assert result.cost_lower_bound <= result.cost
    assert result.cost_lower_bound >= 0
  end

  def test_time_budget_can_stop_the_search
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]
    weights = { [1, 2] => 10, [2, 3] => 1, [3, 1] => 2 }

    # Zero time budget on an already optimally solvable tiny graph: even when
    # the budget triggers, the returned set must remain feasible.
    result = graph.minimum_feedback_edge_set(weights, time_budget: 0.0)

    assert_breaking_edges(graph, result.edges)
    assert result.cost_lower_bound <= result.cost
  end

  def test_result_is_feasible_for_a_dense_random_graph_under_budget
    srand 1234
    graph = DirectedAdjacencyGraph.new
    weights = {}
    vertices = (0...10).to_a
    vertices.combination(2).each do |u, v|
      if rand < 0.5
        graph.add_edge(u, v)
        weights[[u, v]] = rand(1..100)
      else
        graph.add_edge(v, u)
        weights[[v, u]] = rand(1..100)
      end
    end

    result = graph.minimum_feedback_edge_set(weights, max_nodes: 50, max_edges: 100)

    assert_breaking_edges(graph, result.edges)
    assert result.cost_lower_bound <= result.cost
    assert result.budget_exhausted unless result.optimal?
  end

  def test_default_weights_are_one
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1, 1, 3]

    result = graph.minimum_feedback_edge_set

    assert_equal 1, result.cost
    assert result.optimal?
    assert_breaking_edges(graph, result.edges)
  end

  def test_zero_weights_are_allowed
    graph, weights = build_graph([[:a, :b, 0], [:b, :c, 5], [:c, :a, 5]])

    result = graph.minimum_feedback_edge_set(weights)

    assert_equal 0, result.cost
    assert_equal [[:a, :b]], result.edges.map(&:to_a)
  end

  def test_negative_weight_is_rejected
    graph, weights = build_graph([[1, 2, -1], [2, 3, 1], [3, 1, 1]])

    assert_raise(ArgumentError) { graph.minimum_feedback_edge_set(weights) }
  end

  def test_undirected_graph_is_rejected
    assert_raise(NotDirectedError) do
      AdjacencyGraph[1, 2, 2, 3].minimum_feedback_edge_set
    end
  end

  def test_size_limits_are_enforced
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]

    assert_raise(ArgumentError) { graph.minimum_feedback_edge_set(nil, max_vertices: 2) }
    assert_raise(ArgumentError) { graph.minimum_feedback_edge_set(nil, max_edges: 2) }
    assert_raise(ArgumentError) { graph.minimum_feedback_edge_set(nil, max_nodes: -1) }
  end

  def test_graph_is_not_modified
    graph, weights = build_graph([[1, 2, 10], [2, 3, 1], [3, 1, 2], [4, 4, 3]])
    edges_before = graph.edges

    graph.minimum_feedback_edge_set(weights)

    assert_equal edges_before, graph.edges
    assert_equal 4, graph.num_vertices
  end

  def test_alias_returns_equivalent_result
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]
    weights = { [1, 2] => 10, [2, 3] => 1, [3, 1] => 2 }

    assert_equal graph.minimum_feedback_edge_set(weights).edges,
                 graph.minimum_feedback_arc_set(weights).edges
  end

end
