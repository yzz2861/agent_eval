# frozen_string_literal: true

require 'test_helper'

require 'rgl/adjacency'
require 'rgl/pareto_paths'

class TestParetoPaths < Test::Unit::TestCase
  include RGL

  def setup
    @graph = DirectedAdjacencyGraph.new
    @graph.add_edges(
      [:s, :a], [:a, :b],
      [:s, :c], [:c, :b],
      [:b, :t], [:s, :t]
    )

    @edge_costs = {
      [:s, :a] => [1, 100],
      [:a, :b] => [1, 10],
      [:s, :c] => [100, 1],
      [:c, :b] => [10, 1],
      [:b, :t] => [1, 1],
      [:s, :t] => [120, 120]
    }
  end

  def test_returns_all_pareto_optimal_simple_paths
    result = @graph.pareto_optimal_paths(@edge_costs, :s, :t)

    assert_predicate(result, :complete?)
    assert_equal(
      [
        ParetoPath.new([:s, :a, :b, :t], [3, 111]),
        ParetoPath.new([:s, :c, :b, :t], [111, 3])
      ],
      result.paths
    )
    assert_equal(
      [
        { vertices: [:s, :a, :b, :t], cost: [3, 111] },
        { vertices: [:s, :c, :b, :t], cost: [111, 3] }
      ],
      result.to_h[:paths]
    )
  end

  def test_single_objective_shortest_path_would_miss_a_pareto_path
    latency_only = Hash.new { |costs, edge| costs[edge] = [@edge_costs[edge].first] }
    result = @graph.pareto_optimal_paths(latency_only, :s, :t)

    assert_equal([[:s, :a, :b, :t]], result.map(&:vertices))

    result = @graph.pareto_optimal_paths(@edge_costs, :s, :t)

    assert_include(result.map(&:vertices), [:s, :a, :b, :t])
    assert_include(result.map(&:vertices), [:s, :c, :b, :t])
  end

  def test_retains_distinct_paths_with_equal_vectors
    @graph.add_edges([:s, :d], [:d, :t])
    @edge_costs[[:s, :a]] = [1, 0]
    @edge_costs[[:s, :d]] = [2, 5]
    @edge_costs[[:d, :t]] = [1, 6]

    result = @graph.pareto_optimal_paths(@edge_costs, :s, :t)

    equal_cost_paths = result.paths.select { |path| path.cost == [3, 11] }

    assert_equal(
      [[:s, :a, :b, :t], [:s, :d, :t]],
      equal_cost_paths.map(&:vertices)
    )
  end

  def test_cost_limits_are_feasibility_constraints
    result = @graph.pareto_optimal_paths(
      @edge_costs, :s, :t, cost_limits: [nil, 10]
    )

    assert_predicate(result, :complete?)
    assert_equal(
      [ParetoPath.new([:s, :c, :b, :t], [111, 3])],
      result.paths
    )
  end

  def test_work_limit_marks_result_incomplete
    graph = DirectedAdjacencyGraph.new
    graph.add_edges([1, 2], [2, 3])
    edge_costs = { [1, 2] => [1, 1], [2, 3] => [1, 1] }

    result = graph.pareto_optimal_paths(edge_costs, 1, 3, work_limit: 1)

    assert_predicate(result, :incomplete?)
    assert_empty(result.paths)
  end

  def test_work_limit_counts_expanded_path_states
    graph = DirectedAdjacencyGraph.new
    graph.add_edges([1, 2], [2, 3])
    edge_costs = { [1, 2] => [1, 1], [2, 3] => [1, 1] }

    result = graph.pareto_optimal_paths(edge_costs, 1, 3, work_limit: 3)

    assert_predicate(result, :complete?)
    assert_equal([ParetoPath.new([1, 2, 3], [2, 2])], result.paths)
  end

  def test_work_limit_keeps_confirmed_results_and_marks_incomplete
    result = @graph.pareto_optimal_paths(@edge_costs, :s, :t, work_limit: 4)

    assert_predicate(result, :incomplete?)
    assert_equal(
      [ParetoPath.new([:s, :a, :b, :t], [3, 111])],
      result.paths
    )
  end

  def test_zero_cost_trivial_path
    result = @graph.pareto_optimal_paths(@edge_costs, :s, :s)

    assert_predicate(result, :complete?)
    assert_equal([ParetoPath.new([:s], [0, 0])], result.paths)
  end

  def test_trivial_path_uses_one_state_of_work_limit
    result = @graph.pareto_optimal_paths(@edge_costs, :s, :s, work_limit: 1)

    assert_predicate(result, :complete?)
    assert_equal([ParetoPath.new([:s], [0, 0])], result.paths)
  end

  def test_unreachable_target
    @graph.add_vertex(:x)
    result = @graph.pareto_optimal_paths(@edge_costs, :s, :x)

    assert_predicate(result, :complete?)
    assert_empty(result.paths)
  end

  def test_accepts_callable_edge_costs
    edge_costs = lambda { |edge| @edge_costs[edge] }
    result = @graph.pareto_optimal_paths(edge_costs, :s, :t)

    assert_equal(
      [[:s, :a, :b, :t], [:s, :c, :b, :t]],
      result.map(&:vertices)
    )
  end

  def test_works_for_undirected_graphs
    graph = AdjacencyGraph.new
    graph.add_edges([1, 2], [2, 3], [1, 3])
    edge_costs = {
      [1, 2] => [1, 10],
      [2, 3] => [1, 10],
      [1, 3] => [10, 1]
    }

    result = graph.pareto_optimal_paths(edge_costs, 1, 3)

    assert_equal(
      [
        ParetoPath.new([1, 2, 3], [2, 20]),
        ParetoPath.new([1, 3], [10, 1])
      ],
      result.paths
    )
  end

  def test_undirected_zero_cost_reverse_edge_key
    graph = AdjacencyGraph.new
    graph.add_edges([1, 2], [2, 3])
    edge_costs = {
      [2, 1] => [0, 0],
      [2, 3] => [0, 0]
    }

    result = graph.pareto_optimal_paths(edge_costs, 1, 3)

    assert_equal([ParetoPath.new([1, 2, 3], [0, 0])], result.paths)
  end

  def test_result_is_enumerable
    result = @graph.pareto_optimal_paths(@edge_costs, :s, :t)

    assert_equal(2, result.count)
    assert(result.all? { |path| path.is_a?(ParetoPath) })
  end

  def test_rejects_negative_cost
    @edge_costs[[:s, :a]] = [-1, 100]

    assert_raises(ArgumentError, 'cost 0 of edge (s, a) is negative') do
      @graph.pareto_optimal_paths(@edge_costs, :s, :t)
    end
  end

  def test_rejects_inconsistent_cost_dimensions
    @edge_costs[[:s, :a]] = [1]

    assert_raises(ArgumentError, 'edge costs have 1 dimensions, expected 2') do
      @graph.pareto_optimal_paths(@edge_costs, :s, :t)
    end
  end

  def test_rejects_missing_vertex
    assert_raises(ArgumentError, 'source vertex missing is not in the graph') do
      @graph.pareto_optimal_paths(@edge_costs, :missing, :t)
    end
  end

end
