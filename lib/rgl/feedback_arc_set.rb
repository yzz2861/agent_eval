# frozen_string_literal: true

# feedback_arc_set.rb

require 'rgl/base'

module RGL

  # The result of {Graph#minimum_feedback_arc_set}.
  #
  # +edges+ is the set of edges (as {Edge::DirectedEdge} instances) whose
  # removal makes the graph acyclic. +cost+ is the total weight of those
  # edges. +lower_bound+ is a lower bound on the cost of _any_ feedback arc
  # set of the graph, so +cost+ and +lower_bound+ are always directly
  # comparable. When the search budget was exhausted before optimality could
  # be proven, +optimal?+ is false and the gap between +cost+ and
  # +lower_bound+ tells you how far the returned solution can be from the
  # optimum at most. +iterations+ reports how many branch-and-bound nodes
  # were expanded.
  class FeedbackArcSetResult

    attr_reader :edges, :cost, :lower_bound, :iterations

    # @private
    def initialize(edges, cost, lower_bound, optimal, iterations)
      @edges = edges
      @cost = cost
      @lower_bound = lower_bound
      @optimal = optimal
      @iterations = iterations
    end

    # Returns true iff +edges+ is proven to be a minimum cost feedback arc
    # set. False means the search budget ran out; the returned set is still
    # feasible, only the optimality proof is missing.
    def optimal?
      @optimal
    end

  end # class FeedbackArcSetResult


  module Graph

    # Computes a minimum cost feedback arc set of a directed graph: a set of
    # edges of minimum total weight whose removal makes the graph acyclic.
    #
    # The problem is NP-hard, so this entry point is meant for small graphs
    # only and enforces explicit limits. It raises ArgumentError if the graph
    # exceeds +max_vertices+ or +max_edges+. The branch-and-bound search
    # expands at most +max_iterations+ nodes; if the budget runs out, the
    # returned {FeedbackArcSetResult} still contains the best feasible set
    # found so far, +optimal?+ is false, and +lower_bound+ remains a valid
    # bound on the optimum.
    #
    # Edge weights must be non-negative numbers. Self-loops can never be part
    # of an acyclic graph, so they are always included in the result. A graph
    # that is already acyclic yields an empty edge set with cost 0.
    #
    # @param weights [Hash, #call, nil] edge weights, either as a Hash keyed
    #   by (+source+, +target+) pairs (two element arrays or
    #   {Edge::DirectedEdge}) or as a callable taking (+source+, +target+).
    #   Edges without an entry default to weight 1.
    # @param max_vertices [Integer] raise ArgumentError above this size
    # @param max_edges [Integer] raise ArgumentError above this size
    # @param max_iterations [Integer] branch-and-bound node budget
    # @return [FeedbackArcSetResult]
    #
    # @example
    #   g = RGL::DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]
    #   result = g.minimum_feedback_arc_set([1, 2] => 5, [2, 3] => 1, [3, 1] => 1)
    #   result.edges     # => [(2-3)] (weight 1 edge)
    #   result.cost      # => 1
    #   result.optimal?  # => true
    def minimum_feedback_arc_set(weights = nil, max_vertices: 64, max_edges: 512, max_iterations: 10_000)
      raise NotDirectedError, 'minimum_feedback_arc_set is only defined for directed graphs' unless directed?
      raise ArgumentError, "graph has #{num_vertices} vertices, more than max_vertices=#{max_vertices}" if num_vertices > max_vertices
      raise ArgumentError, "graph has #{num_edges} edges, more than max_edges=#{max_edges}" if num_edges > max_edges
      raise ArgumentError, "max_iterations must be non-negative, got #{max_iterations}" if max_iterations < 0

      FeedbackArcSetSolver.new(self, weights, max_iterations).solve
    end

  end # module Graph


  # @private
  #
  # Exact branch and bound for the weighted feedback arc set problem. Each
  # node finds a cycle and branches on which of its edges to remove. The
  # lower bound is a packing bound: the minimum edge weight of each cycle of
  # a greedy edge-disjoint cycle packing sums to a value every feasible
  # solution must pay.
  class FeedbackArcSetSolver

    def initialize(graph, weights, max_iterations)
      @graph = graph
      @max_iterations = max_iterations
      @weight_fn =
        case weights
        when nil
          ->(_u, _v) { 1 }
        when Hash
          ->(u, v) { weights.fetch([u, v]) { weights[Edge::DirectedEdge.new(u, v)] || 1 } }
        else
          if weights.respond_to?(:call)
            weights
          else
            raise ArgumentError, "weights must be a Hash or respond to :call, got #{weights.class}"
          end
        end
    end

    def solve
      @sources = []
      @targets = []
      @ws = []
      @graph.each_edge do |u, v|
        w = @weight_fn.call(u, v)
        unless w.is_a?(Numeric) && w >= 0
          raise ArgumentError, "edge weights must be non-negative numbers, got #{w.inspect} for (#{u.inspect}, #{v.inspect})"
        end
        @sources << u
        @targets << v
        @ws << w
      end

      # Self-loops can never survive in an acyclic graph; removing them is
      # forced and costs no search effort.
      forced = []
      @adj = Hash.new { |h, k| h[k] = [] }
      @sources.each_index do |i|
        if @sources[i].eql?(@targets[i])
          forced << i
        else
          @adj[@sources[i]] << [@targets[i], i]
        end
      end
      @graph.each_vertex { |v| @adj[v] } # register sink vertices as keys
      forced_cost = forced.inject(0) { |sum, i| sum + @ws[i] }
      forced_edges = forced.map { |i| Edge::DirectedEdge.new(@sources[i], @targets[i]) }

      @removed = Array.new(@sources.size, false)
      @iterations = 0

      # Greedy incumbent: repeatedly break a cycle at its cheapest edge. Not
      # optimal in general (overlapping cycles can make the shared edge the
      # better choice), but it guarantees a feasible answer even when the
      # search budget is zero.
      greedy_incumbent

      root_lower_bound = packing_lower_bound

      if @best_cost.zero?
        # Already acyclic, or all cycles break for free: cannot do better.
        return build_result(forced_edges, forced_cost, forced_cost, true)
      end

      @open_bounds = []
      completed = (catch(:budget_exceeded) { search(0); :done } == :done)
      lower_bound = completed ? @best_cost : [@open_bounds.min || root_lower_bound, @best_cost].min

      build_result(forced_edges, forced_cost, forced_cost + lower_bound, completed)
    end

    private

    def build_result(forced_edges, forced_cost, lower_bound, optimal)
      edges = forced_edges + @best_removed.map { |i| Edge::DirectedEdge.new(@sources[i], @targets[i]) }
      FeedbackArcSetResult.new(edges, forced_cost + @best_cost, lower_bound, optimal, @iterations)
    end

    def search(cost)
      @iterations += 1
      throw :budget_exceeded if @iterations > @max_iterations

      cycle = find_cycle(@removed)
      if cycle.nil?
        if cost < @best_cost
          @best_cost = cost
          @best_removed = @removed.each_index.select { |i| @removed[i] }
        end
        return
      end

      bound = cost + packing_lower_bound
      @open_bounds.push(bound)
      begin
        return if bound >= @best_cost

        # Try expensive edges first to find good incumbents early.
        cycle.sort_by { |i| [-@ws[i], i] }.each do |i|
          @removed[i] = true
          search(cost + @ws[i])
          @removed[i] = false
        end
      ensure
        @open_bounds.pop
      end
    end

    def greedy_incumbent
      blocked = Array.new(@removed.size, false)
      cost = 0
      while (cycle = find_cycle(blocked))
        cheapest = cycle.min_by { |i| [@ws[i], i] }
        blocked[cheapest] = true
        cost += @ws[cheapest]
      end
      @best_cost = cost
      @best_removed = blocked.each_index.select { |i| blocked[i] }
    end

    # Sum of the minimum edge weights of a greedy edge-disjoint cycle
    # packing. Every feedback arc set must contain at least one edge of each
    # of those cycles, and since they share no edges the weights add up to a
    # valid lower bound.
    def packing_lower_bound
      blocked = @removed.dup
      bound = 0
      while (cycle = find_cycle(blocked))
        bound += cycle.map { |i| @ws[i] }.min
        cycle.each { |i| blocked[i] = true }
      end
      bound
    end

    # Returns one cycle of the remaining graph as an Array of edge indices,
    # or nil if the remaining graph is acyclic.
    def find_cycle(blocked)
      color = Hash.new(:white)
      path = [] # [vertex, index of the edge taken out of it] along the DFS stack
      cycle = nil
      visit = lambda do |u|
        color[u] = :gray
        @adj[u].each do |(v, i)|
          next if blocked[i]
          if color[v] == :gray
            start = path.index { |(pv, _)| pv.eql?(v) }
            cycle = path[start..-1].map { |(_, edge_index)| edge_index } + [i]
            throw :cycle_found
          elsif color[v] == :white
            path.push([u, i])
            visit.call(v)
            path.pop
          end
        end
        color[u] = :black
      end
      catch(:cycle_found) do
        @adj.each_key { |u| visit.call(u) if color[u] == :white }
      end
      cycle
    end

  end # class FeedbackArcSetSolver

end # module RGL
