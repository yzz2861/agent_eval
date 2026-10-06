# frozen_string_literal: true

# feedback_edge_set.rb

require 'rgl/base'

require 'pairing_heap'

module RGL

  # Result of {MinimumFeedbackEdgeSet#solve} and {Graph#minimum_feedback_edge_set}.
  #
  # A feedback edge set (also called feedback arc set for directed graphs) is a
  # set of edges whose removal leaves the graph acyclic. The edges are always
  # returned sorted and contain every self-loop of the input graph.
  #
  class MinimumFeedbackEdgeSetResult

    # @return [Array<Edge::DirectedEdge>] the edges that should be removed.
    attr_reader :edges

    # @return [Numeric] sum of the weights of {#edges}.
    attr_reader :cost

    # @return [Numeric] a lower bound on the cost of any feasible feedback
    #   edge set. Equals {#cost} iff {#optimal?}.
    attr_reader :cost_lower_bound

    # @return [Integer] number of branch-and-bound nodes that were expanded.
    attr_reader :nodes_expanded

    # @return [Boolean] whether the search stopped because it ran out of the
    #   node or time budget before proving optimality.
    attr_reader :budget_exhausted

    def initialize(edges, cost, cost_lower_bound, nodes_expanded, budget_exhausted)
      @edges = edges.map { |u, v| Edge::DirectedEdge.new(u, v) }.sort_by(&:to_a)
      @cost = cost
      @cost_lower_bound = cost_lower_bound
      @nodes_expanded = nodes_expanded
      @budget_exhausted = budget_exhausted
    end

    # @return [Boolean] true iff the returned {#edges} are guaranteed to have
    #   minimum total weight. If false, {#cost_lower_bound} states how much
    #   cheaper a better solution could be at most.
    def optimal?
      !@budget_exhausted
    end

    # @return [Numeric] gap between the achieved {#cost} and the proven
    #   {#cost_lower_bound}; zero for an optimal solution.
    def optimality_gap
      @cost - @cost_lower_bound
    end

    def to_s
      "#<#{self.class.name} cost=#{@cost} lower_bound=#{@cost_lower_bound} " \
        "optimal=#{optimal?} nodes=#{@nodes_expanded} edges=#{@edges.map(&:to_s)}>"
    end

    alias inspect to_s

  end # class MinimumFeedbackEdgeSetResult

  # Computes a minimum weight feedback edge set of a directed graph, i.e. a
  # minimum total weight set of edges whose deletion makes the graph a DAG.
  #
  # The minimum feedback arc set problem is NP-hard. This implementation is
  # intended for *small* graphs only and therefore enforces explicit size
  # limits ({#initialize}) and a search budget. It performs a best-first
  # branch-and-bound search:
  #
  # 1. Every self-loop is forced into the solution (a self-loop can only be
  #    broken by removing the loop itself).
  # 2. A greedy feasible solution (repeatedly delete the cheapest edge of a
  #    shortest found cycle) provides an initial upper bound.
  # 3. Each search node branches on the edges of one cycle: any feasible
  #    solution must remove at least one of them.
  # 4. Nodes are fathomed with a lower bound obtained from an edge-disjoint
  #    cycle packing: packed cycles share no edges, so every feasible set must
  #    contain at least one edge of each and the sum of the minimum edge weight
  #    per packed cycle is a valid lower bound.
  #
  # Edge weights are non-negative and default to 1 for edges missing from the
  # weights map. Parallel edges are collapsed (removing an edge removes all of
  # its parallel copies, as does {MutableGraph#remove_edge}).
  #
  # @example
  #   g = RGL::DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]
  #   weights = { [1,2] => 10, [2,3] => 1, [3,1] => 1 }
  #   result = RGL::MinimumFeedbackEdgeSet.new(g, weights).solve
  #   result.edges.map(&:to_a) # => [[2,3]]
  #   result.optimal?           # => true
  #
  class MinimumFeedbackEdgeSet

    # @return [Integer] default maximum number of vertices accepted.
    DEFAULT_MAX_VERTICES = 20

    # @return [Integer] default maximum number of edges accepted.
    DEFAULT_MAX_EDGES = 60

    # @return [Integer] default maximum number of expanded search nodes.
    DEFAULT_MAX_NODES = 10_000

    # @param graph [Graph] a directed graph; it is never modified.
    # @param edge_weights_map [#[]] maps edge pairs +[u, v]+ to their
    #   non-negative weight. Edges without an entry have weight 1. Values must
    #   not be negative.
    # @param max_vertices [Integer, nil] reject graphs larger than this many
    #   vertices (default {DEFAULT_MAX_VERTICES}).
    # @param max_edges [Integer, nil] reject graphs larger than this many edges
    #   (default {DEFAULT_MAX_EDGES}).
    # @param max_nodes [Integer, nil] search budget: expand at most this many
    #   branch-and-bound nodes (default {DEFAULT_MAX_NODES}). With 0 no search
    #   is performed at all and the initial greedy feasible solution is
    #   returned as a non-certified result.
    # @param time_budget [Numeric, nil] optional wall-clock budget in seconds;
    #   with 0 the search is skipped entirely.
    #
    # @raise [NotDirectedError] if _graph_ is undirected.
    # @raise [ArgumentError] if the graph exceeds a size limit or if an edge
    #   weight is negative.
    def initialize(graph,
                   edge_weights_map = nil,
                   max_vertices: DEFAULT_MAX_VERTICES,
                   max_edges: DEFAULT_MAX_EDGES,
                   max_nodes: DEFAULT_MAX_NODES,
                   time_budget: nil)
      raise NotDirectedError, 'feedback edge sets are only defined for directed graphs' unless graph.directed?
      raise ArgumentError, "graph has more than #{max_vertices} vertices" if graph.num_vertices > max_vertices
      raise ArgumentError, "graph has more than #{max_edges} edges" if graph.num_edges > max_edges
      raise ArgumentError, 'max_nodes must not be negative' if max_nodes.negative?
      raise ArgumentError, 'time_budget must not be negative' if time_budget && time_budget.negative?

      @graph = graph
      @max_nodes = max_nodes
      @time_budget = time_budget

      @weights = {}
      graph.each_edge do |u, v|
        weight = edge_weights_map.nil? ? 1 : edge_weights_map[[u, v]]
        weight = 1 if weight.nil?
        unless weight.is_a?(Numeric) && weight >= 0
          raise ArgumentError, "weight of edge (#{u}, #{v}) must be non-negative, got #{weight.inspect}"
        end
        @weights[[u, v]] = weight
      end
    end

    # Runs the search.
    # @return [MinimumFeedbackEdgeSetResult]
    def solve
      adjacency = build_adjacency

      mandatory, @base_cost = extract_self_loops(adjacency)

      cycle = find_cycle(adjacency)
      return result(mandatory, @base_cost, @base_cost, 0, false) if cycle.nil?

      greedy_removed = greedy_feedback_edges(adjacency)
      best_removed = greedy_removed
      best_cost = weight_sum(greedy_removed)

      queue = PairingHeap::MinPriorityQueue.new
      root = State.new(adjacency, [], 0, packing_lower_bound(adjacency))
      queue.push(root, root.lower_bound)
      # Pending state bounds in a plain sorted structure (the search budget
      # keeps the number of states small). The minimum of this multiset is the
      # best remaining lower bound when the budget runs out.
      pending_bounds = [root.lower_bound]

      nodes_expanded = 0
      deadline = @time_budget ? Process.clock_gettime(Process::CLOCK_MONOTONIC) + @time_budget : nil

      until queue.empty?
        if nodes_expanded >= @max_nodes || (deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline)
          return finalize(mandatory, best_removed, best_cost, pending_bounds, nodes_expanded, true)
        end

        state = queue.pop
        nodes_expanded += 1
        remove_one(pending_bounds, state.lower_bound)

        if state.lower_bound >= best_cost
          next
        end

        cycle = find_cycle(state.adjacency)

        if cycle.nil?
          best_removed = state.removed
          best_cost = state.cost
          next
        end

        # Every feasible completion removes at least one edge of this cycle.
        # Try cheap edges first so a tight upper bound is found early.
        cycle.sort_by { |u, v| @weights[[u, v]] }.each do |u, v|
          child_cost = state.cost + @weights[[u, v]]
          next if child_cost >= best_cost

          child_adjacency = copy_adjacency(state.adjacency)
          child_adjacency[u].delete(v)

          child_removed = state.removed + [[u, v]]
          child_lower_bound = child_cost + packing_lower_bound(child_adjacency)
          next if child_lower_bound >= best_cost

          child = State.new(child_adjacency, child_removed, child_cost, child_lower_bound)
          queue.push(child, child_lower_bound)
          insert_sorted(pending_bounds, child_lower_bound)
        end
      end

      finalize(mandatory, best_removed, best_cost, pending_bounds, nodes_expanded, false)
    end

    private

    # A state of the branch-and-bound search: a graph with some edges already
    # deleted and the cost accumulated so far.
    class State
      attr_accessor :adjacency, :removed, :cost, :lower_bound

      def initialize(adjacency, removed, cost, lower_bound)
        @adjacency = adjacency
        @removed   = removed
        @cost      = cost
        @lower_bound = lower_bound
      end
    end

    def build_adjacency
      adjacency = Hash.new { |hash, v| hash[v] = Set.new }
      @graph.each_vertex { |v| adjacency[v] }
      @graph.each_edge { |u, v| adjacency[u].add(v) }
      adjacency
    end

    # Deletes every self-loop. A self-loop can only be hit by deleting itself,
    # so it belongs unconditionally to any feasible set and its weight is a
    # fixed part of the cost.
    def extract_self_loops(adjacency)
      mandatory = []
      fixed_cost = 0
      adjacency.each_key do |v|
        next unless adjacency[v].include?(v)

        adjacency[v].delete(v)

        mandatory << [v, v]
        fixed_cost += @weights[[v, v]]
      end
      [mandatory, fixed_cost]
    end

    # Greedy feasible solution: always break the discovered cycle at its
    # cheapest edge. This is only an upper bound; overlapping cycles are
    # handled correctly because the search re-evaluates remaining cycles.
    def greedy_feedback_edges(adjacency)
      work = copy_adjacency(adjacency)
      removed = []
      while (cycle = find_cycle(work))
        edge = cycle.min_by { |u, v| @weights[[u, v]] }
        work[edge[0]].delete(edge[1])
        removed << edge
      end
      removed
    end

    # Edge-disjoint cycle packing lower bound. Each packed cycle requires at
    # least one deleted edge; as packed cycles do not share edges, their
    # cheapest-edge costs add up to a valid bound.
    def packing_lower_bound(adjacency)
      work = copy_adjacency(adjacency)
      bound = 0
      while (cycle = find_cycle(work))
        bound += cycle.map { |u, v| @weights[[u, v]] }.min
        cycle.each { |u, v| work[u].delete(v) }
      end
      bound
    end

    # Returns one simple cycle as an ordered list of edge pairs [u, v], or nil
    # if the graph is acyclic. Uses iterative depth-first search coloring.
    def find_cycle(adjacency)
      color = Hash.new(:WHITE)
      parent_edge = {}

      adjacency.each_key do |root|
        next unless color[root] == :WHITE

        stack = [[root, adjacency[root].to_a.each]]
        color[root] = :GRAY

        until stack.empty?
          vertex, neighbors = stack.last
          begin
            neighbor = neighbors.next
          rescue StopIteration
            color[vertex] = :BLACK
            stack.pop
            next
          end

          if color[neighbor] == :GRAY
            return reconstruct_cycle(vertex, neighbor, parent_edge)
          elsif color[neighbor] == :WHITE
            color[neighbor] = :GRAY
            parent_edge[neighbor] = [vertex, neighbor]
            stack << [neighbor, adjacency[neighbor].to_a.each]
          end
        end
      end

      nil
    end

    def reconstruct_cycle(vertex, back_target, parent_edge)
      path = []
      current = vertex
      until current == back_target
        edge = parent_edge[current]
        path << edge
        current = edge[0]
      end
      path.reverse! << [vertex, back_target]
    end

    def copy_adjacency(adjacency)
      copy = {}
      adjacency.each { |v, neighbors| copy[v] = neighbors.dup }
      copy
    end

    def weight_sum(edges)
      edges.sum { |u, v| @weights[[u, v]] }
    end

    def insert_sorted(list, value)
      index = list.bsearch_index { |x| x >= value } || list.size
      list.insert(index, value)
    end

    def remove_one(list, value)
      index = list.bsearch_index { |x| x >= value }
      list.delete_at(index) if index && list[index] == value
    end

    # Best remaining lower bound: the smallest queued node bound, clamped so
    # that the reported bound can never exceed the achieved cost.
    def finalize(mandatory, best_removed, best_cost, pending_bounds, nodes_expanded, budget_exhausted)
      # Costs of non-self-loop edges are relative to the fixed self-loop cost.
      relative_bound =
        if budget_exhausted
          pending_bounds.empty? ? best_cost : [pending_bounds.first, best_cost].min
        else
          best_cost
        end

      result(mandatory + best_removed,
             @base_cost + best_cost,
             @base_cost + relative_bound,
             nodes_expanded,
             budget_exhausted)
    end

    def result(edges, cost, cost_lower_bound, nodes_expanded, budget_exhausted)
      MinimumFeedbackEdgeSetResult.new(edges, cost, cost_lower_bound,
                                       nodes_expanded, budget_exhausted)
    end

  end # class MinimumFeedbackEdgeSet

  module Graph

    # Convenience wrapper around {MinimumFeedbackEdgeSet}; see that class for
    # parameters, guarantees and the meaning of the search budget.
    #
    # @return [MinimumFeedbackEdgeSetResult]
    def minimum_feedback_edge_set(edge_weights_map = nil,
                                  max_vertices: MinimumFeedbackEdgeSet::DEFAULT_MAX_VERTICES,
                                  max_edges: MinimumFeedbackEdgeSet::DEFAULT_MAX_EDGES,
                                  max_nodes: MinimumFeedbackEdgeSet::DEFAULT_MAX_NODES,
                                  time_budget: nil)
      MinimumFeedbackEdgeSet.new(
        self, edge_weights_map,
        max_vertices: max_vertices,
        max_edges: max_edges,
        max_nodes: max_nodes,
        time_budget: time_budget
      ).solve
    end

    alias minimum_feedback_arc_set minimum_feedback_edge_set

  end # module Graph

end # module RGL
