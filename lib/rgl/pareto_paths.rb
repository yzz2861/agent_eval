# frozen_string_literal: true

require 'rgl/edge_properties_map'

require 'pairing_heap'

module RGL

  # A single Pareto-optimal simple path, as returned by {Graph#pareto_shortest_paths}.
  #
  # +vertices+ is the ordered sequence of vertices from the source to the target,
  # +cost+ is the accumulated cost vector (one component per cost dimension).
  ParetoPath = Struct.new(:vertices, :cost)

  # The result of {Graph#pareto_shortest_paths}: the Pareto frontier plus a flag
  # telling whether the search ran to completion or hit the configured work limit.
  class ParetoPathsResult

    include Enumerable

    # @return [Array<ParetoPath>] the Pareto-optimal simple paths that were found,
    #   sorted lexicographically by their cost vector
    attr_reader :paths

    def initialize(paths, complete) # :nodoc:
      @paths    = paths
      @complete = complete
    end

    def each(&block)
      @paths.each(&block)
    end

    # Returns true if the whole Pareto frontier was enumerated.
    def complete?
      @complete
    end

    # Returns true if the search stopped at the configured work limit
    # and {#paths} may be only a subset of the Pareto frontier.
    def truncated?
      !@complete
    end

  end # class ParetoPathsResult

  # An {EdgePropertiesMap} whose properties are cost vectors: Arrays of
  # non-negative Numeric components, all of the same dimension.
  class CostVectorPropertiesMap < EdgePropertiesMap

    # @return [Integer, nil] the common dimension of the cost vectors,
    #   nil if no edge cost has been validated yet (lazy maps)
    attr_reader :dimension

    private

    def validate_property(property, u, v)
      super

      unless property.is_a?(Array) && property.all? { |component| component.is_a?(Numeric) }
        raise ArgumentError.new("cost of edge (#{u}, #{v}) is not a vector of numbers")
      end

      if property.any? { |component| component < 0 }
        raise ArgumentError.new("cost of edge (#{u}, #{v}) has a negative component")
      end

      if @dimension.nil?
        @dimension = property.size
      elsif property.size != @dimension
        raise ArgumentError.new("cost of edge (#{u}, #{v}) has dimension #{property.size}, expected #{@dimension}")
      end
    end

  end # class CostVectorPropertiesMap

  # This class implements {Graph#pareto_shortest_paths}.
  #
  # It runs a multi-label search (a Pareto generalization of Dijkstra's
  # algorithm): instead of a single best distance, every vertex carries a set of
  # mutually non-dominated labels. Labels are expanded in lexicographic order of
  # their cost vector. A label is only discarded when another label at the same
  # vertex _strictly_ dominates it (at most as costly in every dimension and
  # strictly cheaper in at least one); with non-negative costs such a label can
  # never be extended into a Pareto-optimal path.
  #
  # Labels with identical cost vectors are all kept at intermediate vertices,
  # because their different sets of already visited vertices may unblock
  # different extensions. Deduplication of identical cost vectors happens only
  # at the target: among several simple paths with the same accumulated cost
  # vector, the one discovered first is reported.
  class ParetoPathsAlgorithm

    Label = Struct.new(:vertex, :cost, :path) # :nodoc:

    # Initializes the algorithm for a _graph_ with a map of edge cost vectors.
    #
    # _edge_costs_map_ maps each edge (as <tt>[u, v]</tt>) to its cost vector
    # (an Array of non-negative numbers, e.g. <tt>[latency, fee]</tt>). Like
    # {Graph#dijkstra_shortest_path}, a lambda accepting <tt>[u, v]</tt> may be
    # given instead of a Hash.
    #
    # _max_states_ optionally caps the number of label expansions; when the cap
    # is hit the search stops and the result is marked as truncated.
    #
    def initialize(graph, edge_costs_map, max_states = nil)
      @graph           = graph
      @edge_costs_map  = build_edge_costs_map(edge_costs_map)
      @max_states      = max_states

      if max_states && (!max_states.is_a?(Integer) || max_states < 1)
        raise ArgumentError.new('max_states must be a positive Integer or nil')
      end
    end

    # Finds all Pareto-optimal simple paths from _source_ to _target_.
    #
    # Returns a ParetoPathsResult.
    #
    def pareto_paths(source, target)
      labels, queue, complete = search(source, target)
      ParetoPathsResult.new(frontier(labels[target]), complete)
    end

    private

    def search(source, target)
      source_label = Label.new(source, Array.new(cost_dimension, 0), [source])
      labels       = Hash.new { |hash, vertex| hash[vertex] = [] }
      labels[source] << source_label

      # lexicographic order on cost vectors
      queue = PairingHeap::PairingHeap.new { |left, right| (left <=> right) <= 0 }
      queue.push(source_label, source_label.cost)

      states   = 0
      complete = true

      until queue.empty?
        if @max_states && states >= @max_states
          complete = false
          break
        end

        label = queue.pop
        next unless labels[label.vertex].include?(label) # stale label, dominated meanwhile

        states += 1
        next if label.vertex == target # simple paths end at the target

        expand(label, labels, queue)
      end

      [labels, queue, complete]
    end

    # The common dimension of the cost vectors. Hash-like maps are validated
    # eagerly, so the dimension is already known; for lazy (lambda) maps the
    # first edge of the graph is probed, which validates its cost vector.
    def cost_dimension
      unless @edge_costs_map.dimension
        @graph.each_edge do |u, v|
          @edge_costs_map.edge_property(u, v)
          break
        end
      end

      @edge_costs_map.dimension || 0
    end

    def expand(label, labels, queue)
      @graph.each_adjacent(label.vertex) do |neighbor|
        next if label.path.include?(neighbor) # keep paths simple

        cost          = add_vectors(label.cost, @edge_costs_map.edge_property(label.vertex, neighbor))
        vertex_labels = labels[neighbor]

        next if vertex_labels.any? { |other| strictly_dominates?(other.cost, cost) }

        vertex_labels.reject! { |other| strictly_dominates?(cost, other.cost) }

        new_label = Label.new(neighbor, cost, label.path + [neighbor])
        vertex_labels << new_label
        queue.push(new_label, cost)
      end
    end

    # Builds the result paths from the non-dominated labels at the target.
    # Identical cost vectors are deduplicated: the path discovered first wins.
    def frontier(target_labels)
      seen = {}

      target_labels.each_with_object([]) do |label, paths|
        next if seen[label.cost]

        seen[label.cost] = true
        paths << ParetoPath.new(label.path, label.cost)
      end.sort_by { |path| path.cost }
    end

    def add_vectors(vector, other)
      vector.zip(other).map { |component, other_component| component + other_component }
    end

    # _a_ strictly dominates _b_ iff a_i <= b_i for every dimension i and
    # a_i < b_i for at least one dimension.
    def strictly_dominates?(a, b)
      strictly_better = false

      a.zip(b) do |component, other_component|
        return false if component > other_component

        strictly_better = true if component < other_component
      end

      strictly_better
    end

    def build_edge_costs_map(edge_costs_map)
      edge_costs_map.is_a?(EdgePropertiesMap) ? edge_costs_map : CostVectorPropertiesMap.new(edge_costs_map, @graph.directed?)
    end

  end # class ParetoPathsAlgorithm


  module Graph

    # Finds all Pareto-optimal simple paths from the _source_ to the _target_
    # in the graph, where every edge carries a vector of non-negative costs
    # (e.g. latency and fee) instead of a single scalar weight.
    #
    # A path is Pareto-optimal if no other simple path from _source_ to
    # _target_ is at most as costly in every dimension and strictly cheaper in
    # at least one. No scalarization (weighted sum) is applied, so solutions
    # that any single-metric shortest path would miss are reported as well.
    #
    # Returns a ParetoPathsResult whose +paths+ are ParetoPath structs of the
    # vertex sequence and the accumulated cost vector, sorted lexicographically
    # by cost. Several simple paths accumulating to the identical cost vector
    # are deduplicated: only the one discovered first is reported.
    #
    # _max_states_ optionally caps the number of label expansions (the search
    # work). If the cap is hit, the search stops early and the result answers
    # +false+ to +complete?+ / +true+ to +truncated?+, meaning the returned
    # paths are a subset of the Pareto frontier.
    #
    # Raises ArgumentError if an edge cost is undefined, negative, not numeric,
    # or has an inconsistent dimension.
    #
    def pareto_shortest_paths(edge_costs_map, source, target, max_states: nil)
      ParetoPathsAlgorithm.new(self, edge_costs_map, max_states).pareto_paths(source, target)
    end

  end # module Graph

end # module RGL
