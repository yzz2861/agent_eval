# frozen_string_literal: true

require 'test_helper'

require 'rgl/adjacency'
require 'rgl/min_cost_flow'

include RGL

class TestMinCostFlow < Test::Unit::TestCase

  def test_small_diamond_network_is_optimal
    edges = [
      [:s, :a], [:s, :b], [:a, :t], [:b, :t], [:a, :b]
    ]
    capacities = {
      [:s, :a] => 2, [:s, :b] => 2, [:a, :t] => 2, [:b, :t] => 2,
      [:a, :b] => 1
    }
    costs = {
      [:s, :a] => 6, [:s, :b] => 0, [:a, :t] => 0, [:b, :t] => 5,
      [:a, :b] => -100
    }

    assert_optimal(edges, capacities, costs, {}, :s, :t, 2)
  end

  def test_negative_residual_cycle_withdraws_previous_assignment
    edges = [
      [:a, :s], [:s, :b], [:b, :t], [:b, :a], [:s, :a], [:a, :t]
    ]
    capacities = edges.product([1]).to_h
    capacities[[:a, :s]] = 0
    costs = {
      [:s, :a] => 0,
      [:s, :b] => 100,
      [:a, :t] => 100,
      [:b, :t] => 0,
      [:b, :a] => -201,
      [:a, :s] => 0
    }

    result = run_flow(edges, capacities, costs, {}, :s, :t, 1)

    assert_equal(0, result.flows[[:s, :a]])
    assert_equal(1, result.flows[[:s, :b]])
    assert_equal(1, result.flows[[:a, :t]])
    assert_equal(0, result.flows[[:b, :t]])
    assert_equal(0, result.flows[[:a, :s]])
    assert_equal(1, result.flows[[:b, :a]])
    assert_equal(-1, result.total_cost)
    assert_optimal(edges, capacities, costs, {}, :s, :t, 1)
  end

  def test_small_network_with_lower_bound_is_optimal
    edges = [[:s, :a], [:s, :b], [:a, :t], [:b, :t]]
    capacities = edges.product([1]).to_h
    costs = {
      [:s, :a] => 0,
      [:s, :b] => 10,
      [:a, :t] => 0,
      [:b, :t] => 10
    }
    lower_bounds = {[:s, :a] => 1}

    result = assert_optimal(edges, capacities, costs, lower_bounds, :s, :t, 1)
    assert_equal(1, result[[:s, :a]])
  end

  def test_negative_cost_circulation_when_required_flow_is_zero
    edges = [[:a, :b], [:b, :c], [:c, :a]]
    capacities = edges.product([2]).to_h
    costs = {[:a, :b] => -3, [:b, :c] => 1, [:c, :a] => 1}
    lower_bounds = {[:a, :b] => 1}

    result = run_flow(edges, capacities, costs, lower_bounds, :a, :b, 0)

    assert_equal(2, result[[:a, :b]])
    assert_equal(2, result[[:b, :c]])
    assert_equal(2, result[[:c, :a]])
    assert_equal(-2, result.total_cost)
    assert_optimal(edges, capacities, costs, lower_bounds, :a, :b, 0)
  end

  def test_unsatisfied_lower_bound_reports_checkable_reason
    edges = [[:s, :a], [:a, :t], [:a, :dead]]
    capacities = edges.product([1]).to_h
    costs = edges.product([0]).to_h
    lower_bounds = {[:a, :dead] => 1}
    graph = build_graph(edges)

    error = assert_raises(InfeasibleFlowError) do
      graph.minimum_cost_flow(capacities, costs, :s, :t, 0, lower_bounds)
    end

    assert_equal(:lower_bounds_infeasible, error.reason)
    assert_equal('minimum flow requirements cannot be satisfied', error.message)
  end

  def test_unsatisfied_target_flow_reports_checkable_reason
    edges = [[:s, :a], [:a, :t]]
    capacities = {[:s, :a] => 1, [:a, :t] => 2}
    costs = edges.product([0]).to_h
    graph = build_graph(edges)

    error = assert_raises(InfeasibleFlowError) do
      graph.minimum_cost_flow(capacities, costs, :s, :t, 2)
    end

    assert_equal(:required_flow_infeasible, error.reason)
    assert_match(/required flow of 2/, error.message)
    assert_match(/1 unit can be sent/, error.message)
  end

  def test_algorithm_does_not_modify_inputs_or_require_reverse_edges
    edges = [[:s, :a], [:a, :t]]
    capacities = {[:s, :a] => 1, [:a, :t] => 1}
    costs = {[:s, :a] => -2, [:a, :t] => 3}
    lower_bounds = {[:s, :a] => 1}
    graph = build_graph(edges)
    original_edges = graph.edges.map(&:to_a).sort
    capacities_copy = capacities.dup
    costs_copy = costs.dup
    lower_bounds_copy = lower_bounds.dup

    result = graph.minimum_cost_flow(capacities, costs, :s, :t, 1, lower_bounds)

    assert_equal(1, result.total_cost)
    assert_equal(original_edges, graph.edges.map(&:to_a).sort)
    assert_equal(capacities_copy, capacities)
    assert_equal(costs_copy, costs)
    assert_equal(lower_bounds_copy, lower_bounds)
  end

  def test_callable_property_maps
    capacities = {[:s, :a] => 1, [:a, :t] => 1}
    costs = {[:s, :a] => 2, [:a, :t] => 3}
    graph = build_graph(capacities.keys)

    result = graph.minimum_cost_flow(
      ->(edge) { capacities[edge] },
      ->(edge) { costs[edge] },
      :s, :t, 1
    )

    assert_equal(5, result.total_cost)
  end

  def test_invalid_integer_properties_and_bounds
    edges = [[:s, :a], [:a, :t]]
    capacities = {[:s, :a] => 1, [:a, :t] => 1}
    costs = edges.product([0]).to_h
    graph = build_graph(edges)

    assert_raises(ArgumentError) { graph.minimum_cost_flow({}, costs, :s, :t, 1) }
    assert_raises(ArgumentError) { graph.minimum_cost_flow(capacities, {}, :s, :t, 1) }
    assert_raises(ArgumentError) { graph.minimum_cost_flow(capacities, costs, :s, :t, 1.5) }
    assert_raises(ArgumentError) do
      graph.minimum_cost_flow(capacities, costs, :s, :t, 1, {[:s, :a] => -1})
    end
    assert_raises(ArgumentError) do
      graph.minimum_cost_flow(capacities, costs, :s, :t, 1, {[:s, :a] => 2})
    end
  end

  def test_undirected_graph_is_rejected
    graph = AdjacencyGraph.new
    graph.add_edge(:s, :a)

    assert_raises(NotDirectedError) do
      graph.minimum_cost_flow({}, {}, :s, :a, 1)
    end
  end

  private

  def build_graph(edges)
    graph = DirectedAdjacencyGraph.new
    edges.each { |u, v| graph.add_edge(u, v) }
    graph
  end

  def run_flow(edges, capacities, costs, lower_bounds, source, sink, required_flow)
    build_graph(edges).minimum_cost_flow(
      capacities, costs, source, sink, required_flow, lower_bounds
    )
  end

  def assert_optimal(edges, capacities, costs, lower_bounds, source, sink, required_flow)
    result = run_flow(edges, capacities, costs, lower_bounds, source, sink, required_flow)
    expected_flows, expected_cost = enumerate_optimal(
      edges, capacities, costs, lower_bounds, source, sink, required_flow
    )

    assert(expected_flows, 'exhaustive search found a feasible optimum')
    assert_bounds(result, capacities, lower_bounds)
    assert_flow_conservation(result.flows, source, sink, required_flow)
    assert_equal(expected_flows, result.flows)
    assert_equal(expected_cost, result.total_cost)
    result
  end

  def enumerate_optimal(edges, capacities, costs, lower_bounds, source, sink, required_flow)
    enumerate_flows(edges, capacities, costs, lower_bounds, source, sink, required_flow).min_by(&:last)
  end

  def enumerate_flows(edges, capacities, costs, lower_bounds, source, sink, required_flow)
    balances = {}
    flows = {}
    results = []

    enumerate_edge_flows = lambda do |index|
      if index == edges.size
        intermediate_vertices = edges.flatten.uniq - [source, sink]
        if balances.fetch(source, 0) == required_flow &&
           balances.fetch(sink, 0) == -required_flow &&
           intermediate_vertices.all? { |vertex| balances.fetch(vertex, 0).zero? }
          results << [flows.dup, flows.sum { |edge, flow| flow * costs[edge] }]
        end
        return
      end

      edge = edges[index]
      u, v = edge
      lower_bound = lower_bounds.fetch(edge, 0)

      (lower_bound..capacities[edge]).each do |flow|
        flows[edge] = flow
        balances[u] = balances.fetch(u, 0) + flow
        balances[v] = balances.fetch(v, 0) - flow
        enumerate_edge_flows.call(index + 1)
        balances[u] -= flow
        balances[v] += flow
      end
    end

    enumerate_edge_flows.call(0)
    results
  end

  def feasible_flow?(flows, source, sink, required_flow)
    vertices = flows.keys.flatten.uniq

    vertices.all? do |vertex|
      net_flow = flows.sum do |(u, v), flow|
        if vertex == u
          flow
        elsif vertex == v
          -flow
        else
          0
        end
      end

      if vertex == source
        net_flow == required_flow
      elsif vertex == sink
        net_flow == -required_flow
      else
        net_flow.zero?
      end
    end
  end

  def assert_bounds(result, capacities, lower_bounds)
    capacities.each_key do |edge|
      lower_bound = lower_bounds.fetch(edge, 0)
      assert_operator(lower_bound, :<=, result[edge])
      assert_operator(result[edge], :<=, capacities[edge])
    end
  end

  def assert_flow_conservation(flows, source, sink, required_flow)
    assert(feasible_flow?(flows, source, sink, required_flow))
  end

end
