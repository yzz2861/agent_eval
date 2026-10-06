# frozen_string_literal: true

require 'rgl/base'

module RGL

  # Result of a {Graph#min_cost_flow} computation.
  #
  # When the requested flow is feasible, +feasible?+ is true and +flow_map+
  # maps every original edge of the graph to its final (integer) flow, while
  # +total_cost+ is the minimum total cost and +flow_value+ is the achieved
  # net flow from source to sink (equal to the requested target flow).
  #
  # When the lower bounds or the target flow cannot be satisfied, +feasible?+
  # is false and the failure can be inspected through +failure_reason+,
  # +unsatisfied_demands+ (a hash mapping each vertex to the amount of its
  # required net outflow that could not be routed) and +achieved_flow+ (the
  # net flow from source to sink that could still be routed).
  class MinCostFlowResult

    attr_reader :flow_map, :total_cost, :flow_value, :failure_reason, :unsatisfied_demands, :achieved_flow

    def initialize(flow_map: nil, total_cost: nil, flow_value: nil, failure_reason: nil, unsatisfied_demands: nil, achieved_flow: nil)
      @flow_map = flow_map
      @total_cost = total_cost
      @flow_value = flow_value
      @failure_reason = failure_reason
      @unsatisfied_demands = unsatisfied_demands
      @achieved_flow = achieved_flow
    end

    # Whether a flow satisfying all lower bounds and the target flow exists.
    def feasible?
      @failure_reason.nil?
    end
    alias success? feasible?

    def failure_message
      return nil if feasible?

      details = @unsatisfied_demands.map { |vertex, deficit| vertex.inspect + ' (deficit ' + deficit.to_s + ')' }.join(', ')
      'cannot satisfy lower bounds or target flow: unsatisfied net outflow at ' + details +
        '; only ' + @achieved_flow.to_s + ' units of the requested flow could be routed'
    end

  end # MinCostFlowResult


  # Minimum-cost flow with a prescribed source-sink flow value and optional
  # per-edge lower bounds.
  #
  # Capacities, costs and lower bounds must be integers; costs may be
  # negative. The algorithm first cancels negative-cost cycles in the
  # residual network, then satisfies the node imbalances (created by lower
  # bounds and the target flow) with successive shortest augmenting paths
  # from a super source, using Bellman-Ford so that negative costs are
  # handled correctly.
  #
  # All residual bookkeeping is kept in internal data structures: the graph,
  # the property maps and the vertex objects passed by the caller are never
  # modified.
  #
  # @see Graph#min_cost_flow
  class MinCostFlowAlgorithm

    # One directed arc of the internal residual network. +capacity+ is the
    # remaining residual capacity; +original_edge+ identifies the graph edge
    # this arc carries flow for (nil for artificial arcs).
    class ResidualEdge

      attr_accessor :capacity, :reverse
      attr_reader :from, :to, :cost, :original_edge

      def initialize(from, to, capacity, cost, original_edge = nil)
        @from = from
        @to = to
        @capacity = capacity
        @cost = cost
        @original_edge = original_edge
      end

    end # ResidualEdge

    # Initializes the algorithm for a directed _graph_ with integer edge
    # capacities, integer (possibly negative) unit costs and optional
    # non-negative integer lower bounds, each mapping +[u, v]+ pairs to a
    # value.
    def initialize(graph, edge_capacities_map, edge_costs_map, edge_lower_bounds_map = {})
      raise NotDirectedError.new('min-cost flow can only be applied to a directed graph') unless graph.directed?

      @graph = graph
      @edge_capacities_map = edge_capacities_map
      @edge_costs_map = edge_costs_map
      @edge_lower_bounds_map = edge_lower_bounds_map
    end

    # Computes a flow of exactly _target_flow_ units from _source_ to _sink_
    # that respects all lower bounds and capacities and has minimum total
    # cost.
    #
    # @return [MinCostFlowResult]
    def min_cost_flow(source, sink, target_flow)
      validate_inputs(source, sink, target_flow)
      build_residual_network(source, sink, target_flow)

      cancel_negative_cycles

      shipped = satisfy_supplies
      return infeasible_result(source, target_flow) if shipped < @total_supply

      # Successive shortest paths preserve optimality, so this is a safety net only.
      cancel_negative_cycles

      feasible_result(source)
    end

    private

    def validate_inputs(source, sink, target_flow)
      raise ArgumentError.new('source and sink cannot be equal') if source == sink
      raise ArgumentError.new('source is not a vertex of the graph') unless @graph.has_vertex?(source)
      raise ArgumentError.new('sink is not a vertex of the graph') unless @graph.has_vertex?(sink)
      unless target_flow.is_a?(Integer) && target_flow >= 0
        raise ArgumentError.new('target flow must be a non-negative Integer, got ' + target_flow.inspect)
      end

      @edge_lower_bounds_map.each_key do |(u, v)|
        unless @graph.has_edge?(u, v)
          raise ArgumentError.new('lower bound given for (' + u.to_s + ', ' + v.to_s + ') which is not an edge of the graph')
        end
      end

      @graph.each_edge do |u, v|
        capacity = edge_property(@edge_capacities_map, u, v, 'capacity')
        cost = edge_property(@edge_costs_map, u, v, 'cost')
        lower = @edge_lower_bounds_map.fetch([u, v], 0)

        validate_integer(capacity, 'capacity of edge (' + u.to_s + ', ' + v.to_s + ')')
        validate_integer(cost, 'cost of edge (' + u.to_s + ', ' + v.to_s + ')')
        validate_integer(lower, 'lower bound of edge (' + u.to_s + ', ' + v.to_s + ')')

        raise ArgumentError.new('capacity of edge (' + u.to_s + ', ' + v.to_s + ') is negative') if capacity < 0
        raise ArgumentError.new('lower bound of edge (' + u.to_s + ', ' + v.to_s + ') is negative') if lower < 0
        if lower > capacity
          raise ArgumentError.new('lower bound ' + lower.to_s + ' of edge (' + u.to_s + ', ' + v.to_s + ') exceeds its capacity ' + capacity.to_s)
        end
      end
    end

    def edge_property(map, u, v, name)
      map.fetch([u, v]) { raise ArgumentError.new(name + ' of edge (' + u.to_s + ', ' + v.to_s + ') is not defined') }
    end

    def validate_integer(value, description)
      raise ArgumentError.new(description + ' is not an Integer: ' + value.inspect) unless value.is_a?(Integer)
    end

    def build_residual_network(source, sink, target_flow)
      @super_source = Object.new
      @super_sink = Object.new
      @residual_adjacent = Hash.new { |hash, key| hash[key] = [] }
      @residual_edges = []
      @forward_edges = {}
      @lower_bounds = {}
      @supply_edges = []

      supply = Hash.new(0)

      @graph.each_edge do |u, v|
        capacity = @edge_capacities_map[[u, v]]
        cost = @edge_costs_map[[u, v]]
        lower = @edge_lower_bounds_map.fetch([u, v], 0)

        @lower_bounds[[u, v]] = lower
        @forward_edges[[u, v]] = add_residual_edge(u, v, capacity - lower, cost, [u, v])

        supply[u] -= lower
        supply[v] += lower
      end

      supply[source] += target_flow
      supply[sink] -= target_flow

      @total_supply = 0
      supply.each do |vertex, amount|
        next if amount.zero?

        if amount > 0
          @supply_edges << add_residual_edge(@super_source, vertex, amount, 0)
          @total_supply += amount
        else
          add_residual_edge(vertex, @super_sink, -amount, 0)
        end
      end
    end

    def add_residual_edge(from, to, capacity, cost, original_edge = nil)
      forward = ResidualEdge.new(from, to, capacity, cost, original_edge)
      backward = ResidualEdge.new(to, from, 0, -cost)
      forward.reverse = backward
      backward.reverse = forward
      @residual_adjacent[from] << forward
      @residual_adjacent[to] << backward
      @residual_edges << forward << backward
      forward
    end

    def augment(edge, amount)
      edge.capacity -= amount
      edge.reverse.capacity += amount
    end

    # Repeatedly augments along a minimum-cost path from the super source to
    # the super sink (Bellman-Ford, so negative costs are supported) and
    # returns the total amount shipped.
    def satisfy_supplies
      shipped = 0
      while (path = shortest_path(@super_source, @super_sink))
        bottleneck = path.map(&:capacity).min
        path.each { |edge| augment(edge, bottleneck) }
        shipped += bottleneck
      end
      shipped
    end

    def shortest_path(from, to)
      dist = Hash.new(INFINITY)
      dist[from] = 0
      parent = {}

      @residual_adjacent.size.times do
        updated = false
        @residual_edges.each do |edge|
          next if edge.capacity <= 0 || dist[edge.from] == INFINITY

          if dist[edge.from] + edge.cost < dist[edge.to]
            dist[edge.to] = dist[edge.from] + edge.cost
            parent[edge.to] = edge
            updated = true
          end
        end
        break unless updated
      end

      return nil if dist[to] == INFINITY

      path = []
      vertex = to
      until vertex == from
        edge = parent[vertex]
        path.unshift(edge)
        vertex = edge.from
      end
      path
    end

    # Cancels negative-cost cycles in the residual network (Bellman-Ford
    # initialized with zero distances detects cycles in every component).
    def cancel_negative_cycles
      while (cycle = find_negative_cycle)
        bottleneck = cycle.map(&:capacity).min
        cycle.each { |edge| augment(edge, bottleneck) }
      end
    end

    def find_negative_cycle
      dist = Hash.new(0)
      parent = {}
      relaxed_vertex = nil

      @residual_adjacent.size.times do
        relaxed_vertex = nil
        @residual_edges.each do |edge|
          next if edge.capacity <= 0

          if dist[edge.from] + edge.cost < dist[edge.to]
            dist[edge.to] = dist[edge.from] + edge.cost
            parent[edge.to] = edge
            relaxed_vertex = edge.to
          end
        end
        break unless relaxed_vertex
      end

      return nil unless relaxed_vertex

      vertex = relaxed_vertex
      @residual_adjacent.size.times { vertex = parent[vertex].from }

      cycle = []
      start = vertex
      begin
        edge = parent[vertex]
        cycle.unshift(edge)
        vertex = edge.from
      end until vertex == start
      cycle
    end

    def infeasible_result(source, target_flow)
      deficits = {}
      @supply_edges.each do |edge|
        deficits[edge.to] = edge.capacity if edge.capacity > 0
      end

      MinCostFlowResult.new(
        failure_reason: :infeasible_flow,
        unsatisfied_demands: deficits,
        achieved_flow: target_flow - (deficits[source] || 0)
      )
    end

    def feasible_result(source)
      flow_map = {}
      total_cost = 0

      @graph.each_edge do |u, v|
        capacity = @edge_capacities_map[[u, v]]
        lower = @lower_bounds[[u, v]]
        flow = lower + (capacity - lower) - @forward_edges[[u, v]].capacity

        flow_map[[u, v]] = flow
        total_cost += flow * @edge_costs_map[[u, v]]
      end

      flow_value = 0
      @graph.each_edge do |u, v|
        flow_value += flow_map[[u, v]] if u == source
        flow_value -= flow_map[[u, v]] if v == source
      end

      MinCostFlowResult.new(flow_map: flow_map, total_cost: total_cost, flow_value: flow_value)
    end

  end # MinCostFlowAlgorithm


  module Graph

    # Finds a flow of exactly _target_flow_ units from _source_ to _sink_
    # with minimum total cost.
    #
    # _edge_capacities_map_ and _edge_costs_map_ map each edge (as a +[u, v]+
    # pair) to its non-negative integer capacity and its integer unit cost
    # (costs may be negative). _edge_lower_bounds_map_ optionally maps edges
    # to non-negative integer lower bounds (edges missing from the map have
    # lower bound 0).
    #
    # Returns a {MinCostFlowResult}. When feasible, its +flow_map+ contains
    # the final flow of every original edge and +total_cost+ the minimum
    # total cost. When the lower bounds or the target flow cannot be
    # satisfied, the result is not +feasible?+ and the failure can be
    # inspected via +failure_reason+, +unsatisfied_demands+ and
    # +achieved_flow+.
    #
    # Neither the graph, the property maps, nor the vertex objects are
    # modified; all residual adjustments happen in internal structures.
    #
    # Raises NotDirectedError if the graph is not directed.
    #
    # Raises ArgumentError if a capacity, cost or lower bound is missing or
    # not an Integer, if a capacity or lower bound is negative, if a lower
    # bound exceeds its capacity, or if the target flow is not a
    # non-negative Integer.
    #
    # @return [MinCostFlowResult]
    def min_cost_flow(edge_capacities_map, edge_costs_map, source, sink, target_flow, edge_lower_bounds_map = {})
      MinCostFlowAlgorithm.new(self, edge_capacities_map, edge_costs_map, edge_lower_bounds_map)
                          .min_cost_flow(source, sink, target_flow)
    end

  end # module Graph

end
