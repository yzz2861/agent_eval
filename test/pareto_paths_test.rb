require 'test_helper'

require 'rgl/pareto_paths'
require 'rgl/adjacency'
require 'rgl/dijkstra'

include RGL

class TestParetoPaths < Test::Unit::TestCase

  def setup
    # A call path from :s to :t with two cost dimensions: [latency, fee].
    @graph = DirectedAdjacencyGraph[:s, :a, :s, :b, :a, :t, :b, :t, :s, :t]

    @costs = {
        [:s, :a] => [1, 6],
        [:a, :t] => [1, 3],
        [:s, :b] => [5, 1],
        [:b, :t] => [4, 1],
        [:s, :t] => [6, 6]
    }
  end

  def pareto(costs = @costs, source = :s, target = :t, **options)
    @graph.pareto_shortest_paths(costs, source, target, **options)
  end

  def test_pareto_optimal_paths_with_vertices_and_cost_vectors
    result = pareto

    assert(result.complete?)
    assert(!result.truncated?)
    assert_equal(
        [
            ParetoPath.new([:s, :a, :t], [2, 9]),
            ParetoPath.new([:s, :t], [6, 6]),
            ParetoPath.new([:s, :b, :t], [9, 2])
        ],
        result.paths
    )
  end

  # The acceptance case: every single-metric (or weighted-sum) shortest path
  # misses feasible solutions of this graph.
  def test_single_metric_shortest_path_misses_feasible_solutions
    latency = @costs.transform_values(&:first)
    fee     = @costs.transform_values(&:last)
    total   = @costs.transform_values(&:sum)

    assert_equal([:s, :a, :t], @graph.dijkstra_shortest_path(latency, :s, :t))
    assert_equal([:s, :b, :t], @graph.dijkstra_shortest_path(fee, :s, :t))
    # [2, 9] and [9, 2] tie at 11; either way the direct [6, 6] path loses
    assert_include([[:s, :a, :t], [:s, :b, :t]], @graph.dijkstra_shortest_path(total, :s, :t))

    # No weighted sum of latency and fee ever ranks [6, 6] first:
    # it is 6*w + 6*(1-w) = 6, while [2, 9] or [9, 2] is always cheaper.
    assert((0..10).all? { |i| w = i / 10.0; [2 * w + 9 * (1 - w), 9 * w + 2 * (1 - w)].min < 6 })

    costs = pareto.map(&:cost)
    assert_include(costs, [6, 6])
    assert_include(costs, [2, 9])
    assert_include(costs, [9, 2])
  end

  def test_routes_sharing_an_intermediate_vertex_are_all_kept
    graph = DirectedAdjacencyGraph[:s, :x, :s, :y, :x, :v, :y, :v, :v, :t]
    costs = {
        [:s, :x] => [1, 5],
        [:x, :v] => [0, 0],
        [:s, :y] => [5, 1],
        [:y, :v] => [0, 0],
        [:v, :t] => [1, 1]
    }

    result = graph.pareto_shortest_paths(costs, :s, :t)

    assert_equal(
        [
            ParetoPath.new([:s, :x, :v, :t], [2, 6]),
            ParetoPath.new([:s, :y, :v, :t], [6, 2])
        ],
        result.paths
    )
  end

  def test_identical_cost_vectors_are_deduplicated
    graph = DirectedAdjacencyGraph[:s, :t, :s, :u, :u, :t]
    costs = {
        [:s, :t] => [2, 2],
        [:s, :u] => [1, 1],
        [:u, :t] => [1, 1]
    }

    result = graph.pareto_shortest_paths(costs, :s, :t)

    # both simple paths accumulate to [2, 2]; the one discovered first wins
    assert_equal([ParetoPath.new([:s, :t], [2, 2])], result.paths)
  end

  def test_paths_are_simple
    graph = DirectedAdjacencyGraph[:s, :a, :a, :b, :b, :s, :a, :t, :b, :t, :s, :t]
    costs = {
        [:s, :a] => [1, 1],
        [:a, :b] => [1, 1],
        [:b, :s] => [0, 0],
        [:a, :t] => [1, 4],
        [:b, :t] => [1, 1],
        [:s, :t] => [4, 2]
    }

    result = graph.pareto_shortest_paths(costs, :s, :t)

    assert_equal(
        [
            ParetoPath.new([:s, :a, :t], [2, 5]),
            ParetoPath.new([:s, :a, :b, :t], [3, 3]),
            ParetoPath.new([:s, :t], [4, 2])
        ],
        result.paths
    )
    result.each { |path| assert_equal(path.vertices.uniq, path.vertices) }
  end

  def test_max_states_marks_result_incomplete
    result = pareto(max_states: 1)

    assert(!result.complete?)
    assert(result.truncated?)

    assert(pareto(max_states: 100).complete?)
  end

  def test_invalid_max_states
    assert_raise(ArgumentError) { pareto(max_states: 0) }
    assert_raise(ArgumentError) { pareto(max_states: -1) }
    assert_raise(ArgumentError) { pareto(max_states: 1.5) }
  end

  def test_path_to_the_source
    result = pareto(@costs, :s, :s)

    assert(result.complete?)
    assert_equal([ParetoPath.new([:s], [0, 0])], result.paths)
  end

  def test_unreachable_target
    @graph.add_vertex(:isolated)
    result = pareto(@costs, :s, :isolated)

    assert(result.complete?)
    assert_equal([], result.paths)
  end

  def test_costs_map_lambda
    costs_lambda = lambda { |edge| @costs[edge] }

    assert_equal(
        [[2, 9], [6, 6], [9, 2]],
        pareto(costs_lambda).map(&:cost)
    )
  end

  def test_undirected_graph
    graph = AdjacencyGraph[1, 2, 2, 3, 1, 3]
    costs = {
        [1, 2] => [1, 4],
        [2, 3] => [1, 4],
        [1, 3] => [3, 3]
    }

    result = graph.pareto_shortest_paths(costs, 1, 3)

    assert_equal(
        [
            ParetoPath.new([1, 2, 3], [2, 8]),
            ParetoPath.new([1, 3], [3, 3])
        ],
        result.paths
    )
  end

  def test_negative_cost_component
    @costs[[:s, :a]] = [1, -6]
    assert_raise(ArgumentError) { pareto }
  end

  def test_inconsistent_cost_dimension
    @costs[[:s, :a]] = [1, 6, 0]
    assert_raise(ArgumentError) { pareto }
  end

  def test_non_numeric_cost
    @costs[[:s, :a]] = [1, 'x']
    assert_raise(ArgumentError) { pareto }
  end

  def test_undefined_edge_cost
    @costs.delete([:s, :a])
    assert_raise(ArgumentError) { pareto }
  end

end
