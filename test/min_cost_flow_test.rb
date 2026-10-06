require 'test_helper'

require 'rgl/adjacency'
require 'rgl/min_cost_flow'

include RGL

class TestMinCostFlow < Test::Unit::TestCase

  def build_graph(vertices, edges)
    graph = DirectedAdjacencyGraph.new
    vertices.each { |v| graph.add_vertex(v) }
    edges.each { |u, v| graph.add_edge(u, v) }
    graph
  end

  # Exhaustively enumerates all integer flows within [lower, capacity] and
  # returns the minimum total cost among the flows that conserve flow at
  # every vertex and ship exactly +target+ units from source to sink.
  # Returns nil when no such flow exists.
  def brute_force_min_cost(vertices, edges, capacities, costs, lowers, source, sink, target)
    best = nil
    balance = Hash.new(0)
    flow = {}

    enumerate = lambda do |i|
      if i == edges.size
        feasible = vertices.all? do |v|
          expected = v == source ? target : (v == sink ? -target : 0)
          balance[v] == expected
        end

        if feasible
          cost = edges.sum { |edge| flow[edge] * costs[edge] }
          best = cost if best.nil? || cost < best
        end
      else
        u, v = edges[i]
        ((lowers[[u, v]] || 0)..capacities[[u, v]]).each do |f|
          flow[[u, v]] = f
          balance[u] += f
          balance[v] -= f
          enumerate.call(i + 1)
          balance[u] -= f
          balance[v] += f
        end
      end
    end

    enumerate.call(0)
    best
  end

  def assert_valid_flow(result, edges, capacities, costs, lowers, source, sink, target)
    flow_map = result.flow_map

    assert_equal(edges.map(&:sort).sort, flow_map.keys.map(&:sort).sort, 'flow map should contain every original edge')

    balance = Hash.new(0)
    flow_map.each do |(u, v), f|
      assert_operator(f, :>=, lowers[[u, v]] || 0, "flow of edge (#{u}, #{v}) violates its lower bound")
      assert_operator(f, :<=, capacities[[u, v]], "flow of edge (#{u}, #{v}) exceeds its capacity")
      balance[u] += f
      balance[v] -= f
    end

    balance.each do |v, b|
      expected = v == source ? target : (v == sink ? -target : 0)
      assert_equal(expected, b, "flow conservation violated at vertex #{v}")
    end

    assert_equal(target, result.flow_value)
    assert_equal(edges.sum { |edge| flow_map[edge] * costs[edge] }, result.total_cost)
  end

  def test_textbook_example
    capacities = { [1, 2] => 4, [1, 3] => 2, [2, 3] => 2, [2, 4] => 3, [3, 4] => 4 }
    costs       = { [1, 2] => 2, [1, 3] => 1, [2, 3] => 1, [2, 4] => 3, [3, 4] => 2 }
    graph = build_graph([1, 2, 3, 4], capacities.keys)

    result = graph.min_cost_flow(capacities, costs, 1, 4, 5)

    assert(result.feasible?)
    assert_equal(5, result.flow_value)
    assert_equal(21, result.total_cost)
    assert_valid_flow(result, capacities.keys, capacities, costs, {}, 1, 4, 5)
  end

  # The optimum can only be reached by rerouting the first augmenting path:
  # after shipping one unit along s->a->b->t, the a->b assignment must be
  # withdrawn (via the residual backward edge) so that a->t and b->t are
  # used instead.
  def test_rerouting_previous_assignment
    capacities = { [:s, :a] => 1, [:a, :b] => 1, [:b, :t] => 1, [:s, :b] => 1, [:a, :t] => 1 }
    costs       = { [:s, :a] => 0, [:a, :b] => 0, [:b, :t] => 0, [:s, :b] => 1, [:a, :t] => 1 }
    graph = build_graph([:s, :a, :b, :t], capacities.keys)

    result = graph.min_cost_flow(capacities, costs, :s, :t, 2)

    assert(result.feasible?)
    assert_equal(2, result.total_cost)
    assert_equal(0, result.flow_map[[:a, :b]])
    assert_equal(1, result.flow_map[[:a, :t]])
    assert_equal(1, result.flow_map[[:b, :t]])
    assert_valid_flow(result, capacities.keys, capacities, costs, {}, :s, :t, 2)
  end

  def test_negative_cost_cycle_is_used_for_circulation
    capacities = { [:s, :t] => 2, [:a, :b] => 1, [:b, :c] => 1, [:c, :a] => 1 }
    costs       = { [:s, :t] => 5, [:a, :b] => -2, [:b, :c] => -1, [:c, :a] => 0 }
    graph = build_graph([:s, :t, :a, :b, :c], capacities.keys)

    result = graph.min_cost_flow(capacities, costs, :s, :t, 0)

    assert(result.feasible?)
    assert_equal(0, result.flow_value)
    assert_equal(-3, result.total_cost)
    assert_equal(1, result.flow_map[[:a, :b]])
    assert_equal(1, result.flow_map[[:b, :c]])
    assert_equal(1, result.flow_map[[:c, :a]])
    assert_equal(0, result.flow_map[[:s, :t]])
  end

  def test_lower_bounds_are_respected
    capacities = { [:s, :a] => 2, [:a, :t] => 2, [:s, :t] => 1 }
    costs       = { [:s, :a] => 1, [:a, :t] => 1, [:s, :t] => 5 }
    lowers      = { [:s, :a] => 1 }
    graph = build_graph([:s, :a, :t], capacities.keys)

    result = graph.min_cost_flow(capacities, costs, :s, :t, 2, lowers)

    assert(result.feasible?)
    assert_equal(2, result.flow_map[[:s, :a]])
    assert_equal(2, result.flow_map[[:a, :t]])
    assert_equal(0, result.flow_map[[:s, :t]])
    assert_equal(4, result.total_cost)
    assert_valid_flow(result, capacities.keys, capacities, costs, lowers, :s, :t, 2)
  end

  def test_unsatisfiable_lower_bound_reports_failure
    capacities = { [:s, :a] => 3, [:a, :b] => 3, [:b, :t] => 1 }
    costs       = { [:s, :a] => 0, [:a, :b] => 0, [:b, :t] => 0 }
    lowers      = { [:a, :b] => 2 }
    graph = build_graph([:s, :a, :b, :t], capacities.keys)

    result = graph.min_cost_flow(capacities, costs, :s, :t, 0, lowers)

    assert(!result.feasible?)
    assert_equal(:infeasible_flow, result.failure_reason)
    assert_equal({ b: 2 }, result.unsatisfied_demands)
    assert_equal(0, result.achieved_flow)
    assert_nil(result.flow_map)
    assert_match(/cannot satisfy/, result.failure_message)
  end

  def test_unreachable_target_flow_reports_failure
    capacities = { [:s, :a] => 1, [:a, :t] => 1 }
    costs       = { [:s, :a] => 1, [:a, :t] => 1 }
    graph = build_graph([:s, :a, :t], capacities.keys)

    result = graph.min_cost_flow(capacities, costs, :s, :t, 3)

    assert(!result.feasible?)
    assert_equal(:infeasible_flow, result.failure_reason)
    assert_equal({ s: 2 }, result.unsatisfied_demands)
    assert_equal(1, result.achieved_flow)
  end

  def test_does_not_modify_inputs
    capacities = { ['s', 'a'] => 2, ['a', 't'] => 2, ['s', 't'] => 1 }
    costs       = { ['s', 'a'] => 1, ['a', 't'] => -1, ['s', 't'] => 3 }
    lowers      = { ['s', 'a'] => 1 }
    graph = build_graph(['s', 'a', 't'], capacities.keys)

    capacities_before = capacities.dup
    costs_before = costs.dup
    lowers_before = lowers.dup
    edges_before = graph.edges

    result = graph.min_cost_flow(capacities, costs, 's', 't', 2, lowers)

    assert(result.feasible?)
    assert_equal(capacities_before, capacities)
    assert_equal(costs_before, costs)
    assert_equal(lowers_before, lowers)
    assert_equal(edges_before, graph.edges)
  end

  def test_validation_errors
    capacities = { [1, 2] => 1 }
    costs = { [1, 2] => 1 }
    graph = build_graph([1, 2], [[1, 2]])

    assert_raise(ArgumentError) { graph.min_cost_flow({}, costs, 1, 2, 1) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, {}, 1, 2, 1) }
    assert_raise(ArgumentError) { graph.min_cost_flow({ [1, 2] => -1 }, costs, 1, 2, 1) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, { [1, 2] => 1.5 }, 1, 2, 1) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, costs, 1, 2, 1, { [1, 2] => 2 }) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, costs, 1, 2, 1, { [1, 2] => -1 }) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, costs, 1, 2, 1, { [2, 1] => 0 }) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, costs, 1, 2, -1) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, costs, 1, 2, 1.0) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, costs, 1, 1, 1) }
    assert_raise(ArgumentError) { graph.min_cost_flow(capacities, costs, 1, 3, 1) }
    assert_raise(NotDirectedError) { AdjacencyGraph[1, 2].min_cost_flow(capacities, costs, 1, 2, 1) }
  end

  # Verifies optimality against exhaustive enumeration on several small
  # networks, including negative costs, lower bounds and cases that are
  # only optimal after withdrawing a previous assignment.
  def test_exhaustive_optimality_on_small_networks
    rng = Random.new(20261002)

    40.times do
      n = 4 + rng.rand(2)
      vertices = (0...n).to_a
      source = 0
      sink = n - 1

      edges = []
      vertices.each do |u|
        vertices.each do |v|
          edges << [u, v] if u != v && rng.rand < 0.4
        end
      end

      # guarantee at least one source-sink path so that feasible instances
      # (where optimality can be checked) are common
      path = [source] + (vertices - [source, sink]).shuffle(random: rng).take(rng.rand(n - 1)) + [sink]
      path.each_cons(2) { |u, v| edges << [u, v] unless edges.include?([u, v]) }

      next if edges.empty? || edges.size > 8

      capacities = {}
      costs = {}
      lowers = {}
      edges.each do |edge|
        capacities[edge] = 1 + rng.rand(3)
        costs[edge] = rng.rand(8) - 3
        lowers[edge] = rng.rand(capacities[edge] + 1) if rng.rand < 0.25
      end
      lowers.delete_if { |_, lower| lower.zero? }

      target = rng.rand(3)
      graph = build_graph(vertices, edges)

      expected = brute_force_min_cost(vertices, edges, capacities, costs, lowers, source, sink, target)
      result = graph.min_cost_flow(capacities, costs, source, sink, target, lowers)

      if expected.nil?
        assert(!result.feasible?, "expected infeasible for edges=#{edges.inspect} target=#{target}")
        assert_equal(:infeasible_flow, result.failure_reason)
        assert(!result.unsatisfied_demands.empty?)
      else
        assert(result.feasible?, "expected feasible for edges=#{edges.inspect} target=#{target}")
        assert_equal(expected, result.total_cost,
                     "suboptimal cost for edges=#{edges.inspect} capacities=#{capacities.inspect} " \
                     "costs=#{costs.inspect} lowers=#{lowers.inspect} target=#{target}")
        assert_valid_flow(result, edges, capacities, costs, lowers, source, sink, target)
      end
    end
  end

end
