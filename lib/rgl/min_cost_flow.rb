# frozen_string_literal: true

require 'rgl/base'

module RGL

  # Base error for minimum cost flow calculations that cannot be completed.
  class MinCostFlowError < StandardError

    attr_reader :reason

    def initialize(message, reason)
      super(message)
      @reason = reason
    end

  end

  # Raised when a requested flow or a lower bound cannot be satisfied.
  class InfeasibleFlowError < MinCostFlowError; end

  # Contains a feasible minimum cost flow.
  class MinCostFlowResult

    attr_reader :flows, :total_cost

    def initialize(flows, total_cost)
      @flows = flows
      @total_cost = total_cost
    end

    alias flow_map flows
    alias cost total_cost

    def [](edge)
      @flows[edge]
    end

    def to_h
      @flows.dup
    end

  end

  # Computes a minimum-cost integral flow with optional lower bounds.
  #
  # Lower bounds and the requested source-to-sink flow are converted into one
  # feasible circulation problem and checked with a super source and super
  # sink. Negative edge costs are handled by cancelling negative residual
  # cycles. Residual reverse arcs let the algorithm withdraw flow assigned
  # during earlier augmentations.
  class MinCostFlowAlgorithm

    # Represents one directed arc in the algorithm's private residual network.
    class ResidualArc

      attr_accessor :source, :target, :remaining_capacity, :cost, :reverse,
                    :original_edge, :flow, :auxiliary

      def initialize(source, target, remaining_capacity, cost, original_edge: nil,
                     flow: 0, auxiliary: false)
        @source = source
        @target = target
        @remaining_capacity = remaining_capacity
        @cost = cost
        @original_edge = original_edge
        @flow = flow
        @auxiliary = auxiliary
      end

    end

    # Initializes the algorithm for _graph_.
    #
    # Capacities and lower bounds must be non-negative integers. Edge costs may
    # be any integer, including negative values. Unlike {EdmondsKarpAlgorithm},
    # callers do not have to add reverse edges to the graph.
    def initialize(graph, edge_capacities_map, edge_costs_map, edge_lower_bounds_map = {})
      raise NotDirectedError.new('minimum cost flow can only be applied to a directed graph') unless graph.directed?

      @graph = graph
      @edges = []

      graph.each_edge do |u, v|
        capacity = read_integer_property(edge_capacities_map, [u, v], 'capacity', true)
        cost = read_integer_property(edge_costs_map, [u, v], 'cost', true)
        lower_bound = read_integer_property(edge_lower_bounds_map, [u, v], 'lower bound', false, 0)

        raise ArgumentError.new("capacity of edge (#{u}, #{v}) is negative") if capacity.negative?
        raise ArgumentError.new("lower bound of edge (#{u}, #{v}) is negative") if lower_bound.negative?

        if lower_bound > capacity
          raise ArgumentError.new("lower bound of edge (#{u}, #{v}) exceeds its capacity")
        end

        @edges << [u, v, capacity, lower_bound, cost]
      end
    end

    # Finds a minimum cost flow carrying _required_flow_ units from _source_ to
    # _sink_.
    #
    # @return [MinCostFlowResult]
    def min_cost_flow(source, sink, required_flow)
      validate_flow_request(source, sink, required_flow)

      find_feasible_flow(source, sink, required_flow)
      cancel_negative_cycles

      flow_map = @original_arcs.to_h { |arc| [arc.original_edge, arc.flow] }
      total_cost = flow_map.sum do |(u, v), flow|
        flow * cost_of(u, v)
      end

      MinCostFlowResult.new(flow_map, total_cost)
    end

    alias minimum_cost_flow min_cost_flow

    private

    def validate_flow_request(source, sink, required_flow)
      raise ArgumentError.new("source and sink can't be equal") if source == sink

      unless required_flow.is_a?(Integer)
        raise ArgumentError.new('required flow must be an integer')
      end
      raise ArgumentError.new('required flow cannot be negative') if required_flow.negative?
      raise ArgumentError.new("source (#{source}) is not a vertex") unless @graph.has_vertex?(source)
      raise ArgumentError.new("sink (#{sink}) is not a vertex") unless @graph.has_vertex?(sink)
    end

    def read_integer_property(properties, edge, property_name, required, default = nil)
      value = if properties.respond_to?(:call)
                properties.call(edge)
              elsif required
                properties.fetch(edge) do
                  raise ArgumentError.new("#{property_name} for edge (#{edge[0]}, #{edge[1]}) is missing")
                end
              else
                properties.fetch(edge, default)
              end

      unless value.is_a?(Integer)
        raise ArgumentError.new("#{property_name} of edge (#{edge[0]}, #{edge[1]}) must be an integer")
      end

      value
    end

    def find_feasible_flow(source, sink, required_flow)
      build_residual_network(nil, true)

      balances = Hash.new(0)
      @edges.each do |u, v, _capacity, lower_bound, _cost|
        balances[u] -= lower_bound
        balances[v] += lower_bound
      end
      balances[source] += required_flow
      balances[sink] -= required_flow

      required_flow_value = add_lower_bound_auxiliary_arcs(balances)
      sent_flow = maximize_auxiliary_flow

      if sent_flow != required_flow_value
        available_flow = maximum_flow_without_lower_bounds(source, sink)

        if available_flow >= required_flow
          raise InfeasibleFlowError.new(
            'minimum flow requirements cannot be satisfied',
            :lower_bounds_infeasible
          )
        else
          unit_text = available_flow == 1 ? 'unit' : 'units'
          raise InfeasibleFlowError.new(
            "required flow of #{required_flow} cannot be sent from (#{source}) to (#{sink}); " \
            "#{available_flow} #{unit_text} can be sent",
            :required_flow_infeasible
          )
        end
      end
    end

    def build_residual_network(initial_flows, start_at_lower_bounds = false)
      @vertices = @graph.vertices
      @adjacent = Hash.new { |hash, vertex| hash[vertex] = [] }
      @original_arcs = []
      @super_source = Object.new
      @super_sink = Object.new

      @vertices.each { |vertex| @adjacent[vertex] = [] }
      @adjacent[@super_source] = []
      @adjacent[@super_sink] = []

      @edges.each do |u, v, capacity, lower_bound, cost|
        flow = if initial_flows.nil? && start_at_lower_bounds
                 lower_bound
               elsif initial_flows.nil?
                 0
               else
                 initial_flows[[u, v]]
               end
        forward = ResidualArc.new(
          u, v, capacity - flow, cost,
          original_edge: [u, v], flow: flow
        )
        backward = ResidualArc.new(v, u, flow - lower_bound, -cost)
        forward.reverse = backward
        backward.reverse = forward

        @adjacent[u] << forward
        @adjacent[v] << backward
        @original_arcs << forward
      end
    end

    def add_lower_bound_auxiliary_arcs(balances)
      required_flow_value = 0

      balances.each do |vertex, balance|
        next if balance.zero?

        if balance.positive?
          add_arc(@super_source, vertex, balance, 0, auxiliary: true)
        else
          add_arc(vertex, @super_sink, -balance, 0, auxiliary: true)
        end
        required_flow_value += balance if balance.positive?
      end

      required_flow_value
    end

    def add_arc(source, target, capacity, cost, auxiliary: false)
      forward = ResidualArc.new(
        source, target, capacity, cost, auxiliary: auxiliary
      )
      backward = ResidualArc.new(
        target, source, 0, -cost, auxiliary: auxiliary
      )
      forward.reverse = backward
      backward.reverse = forward

      @adjacent[source] << forward
      @adjacent[target] << backward
      forward
    end

    def maximize_auxiliary_flow
      sent_flow = 0

      while (path = find_augmenting_path(@super_source, @super_sink))
        additional_flow = path.map(&:remaining_capacity).min
        path.each { |arc| push(arc, additional_flow) }
        sent_flow += additional_flow
      end

      sent_flow
    end

    def find_augmenting_path(source, sink)
      incoming_arc = { source => nil }
      queue = [source]

      until queue.empty?
        vertex = queue.shift

        @adjacent[vertex].each do |arc|
          next unless arc.remaining_capacity.positive?
          next if incoming_arc.key?(arc.target)

          incoming_arc[arc.target] = arc
          return reconstruct_path(arc.target, incoming_arc) if arc.target == sink

          queue << arc.target
        end
      end

      nil
    end

    def reconstruct_path(vertex, incoming_arc)
      path = []

      until vertex.nil?
        arc = incoming_arc[vertex]
        break if arc.nil?

        path.unshift(arc)
        vertex = arc.source
      end

      path
    end

    def push(arc, amount)
      arc.remaining_capacity -= amount
      arc.reverse.remaining_capacity += amount

      if arc.original_edge
        arc.flow += amount
      elsif arc.reverse.original_edge
        arc.reverse.flow -= amount
      end
    end

    def cancel_negative_cycles
      iteration_count = @vertices.size

      loop do
        distances = Hash.new(0)
        predecessor = {}
        relaxed_vertex = nil

        iteration_count.times do
          relaxed_vertex = nil

          @vertices.each do |vertex|
            each_residual_arc(vertex) do |arc|
              candidate_distance = distances[vertex] + arc.cost
              next if candidate_distance >= distances[arc.target]

              distances[arc.target] = candidate_distance
              predecessor[arc.target] = arc
              relaxed_vertex = arc.target
            end
          end

          break if relaxed_vertex.nil?
        end

        break if relaxed_vertex.nil?

        cycle_start = relaxed_vertex
        iteration_count.times { cycle_start = predecessor[cycle_start].source }

        cycle = []
        vertex = cycle_start
        loop do
          arc = predecessor.fetch(vertex)
          cycle << arc
          vertex = arc.source
          break if vertex == cycle_start
        end

        amount = cycle.map(&:remaining_capacity).min
        cycle.each { |arc| push(arc, amount) }
      end
    end

    def each_residual_arc(vertex)
      @adjacent[vertex].each do |arc|
        next if arc.auxiliary
        next unless arc.remaining_capacity.positive?

        yield arc
      end
    end

    def maximum_flow_without_lower_bounds(source, sink)
      capacity_bound = @edges.sum { |_u, _v, capacity, _lower_bound, _cost| capacity }

      @adjacent = Hash.new { |hash, vertex| hash[vertex] = [] }
      @original_arcs = []
      @super_source = Object.new
      @super_sink = Object.new
      @vertices.each { |vertex| @adjacent[vertex] = [] }
      @adjacent[@super_source] = []
      @adjacent[@super_sink] = []

      @edges.each do |u, v, capacity, _lower_bound, cost|
        forward = ResidualArc.new(
          u, v, capacity, cost, original_edge: [u, v], flow: 0
        )
        backward = ResidualArc.new(v, u, 0, -cost)
        forward.reverse = backward
        backward.reverse = forward

        @adjacent[u] << forward
        @adjacent[v] << backward
        @original_arcs << forward
      end

      add_arc(@super_source, source, capacity_bound, 0, auxiliary: true)
      add_arc(sink, @super_sink, capacity_bound, 0, auxiliary: true)

      maximize_auxiliary_flow
    end

    def cost_of(source, target)
      @edges.each do |u, v, _capacity, _lower_bound, cost|
        return cost if u == source && v == target
      end
    end

  end # class MinCostFlowAlgorithm

  module Graph

    # Finds the minimum cost flow carrying _required_flow_ units from
    # _source_ to _sink_.
    #
    # The returned {MinCostFlowResult} contains the integral flow assigned to
    # every original edge and the total cost. The graph and supplied property
    # maps are not modified. Negative costs are supported.
    #
    # @return [MinCostFlowResult]
    def minimum_cost_flow(edge_capacities_map, edge_costs_map, source, sink,
                          required_flow, edge_lower_bounds_map = {})
      MinCostFlowAlgorithm
        .new(self, edge_capacities_map, edge_costs_map, edge_lower_bounds_map)
        .min_cost_flow(source, sink, required_flow)
    end

    alias min_cost_flow minimum_cost_flow

  end # module Graph

end
