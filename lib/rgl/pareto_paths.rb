# frozen_string_literal: true

require 'set'

require 'rgl/base'

module RGL

  # A complete simple path together with its accumulated multi-dimensional
  # cost vector.
  class ParetoPath

    # @return [Array] vertices in path order, beginning with the source and
    #   ending with the target
    attr_reader :vertices

    # @return [Array<Numeric>] accumulated edge costs
    attr_reader :cost

    # @param vertices [Array]
    # @param cost [Array<Numeric>]
    def initialize(vertices, cost)
      @vertices = vertices.dup.freeze
      @cost = cost.dup.freeze
    end

    # Duplicate path results have both the same vertex sequence and the same
    # accumulated cost vector.
    #
    # @param other [ParetoPath]
    # @return [Boolean]
    def eql?(other)
      other.is_a?(ParetoPath) && vertices == other.vertices && cost == other.cost
    end

    alias == eql?

    # @return [Integer]
    def hash
      [vertices, cost].hash
    end

    # @return [Hash]
    def to_h
      { vertices: vertices, cost: cost }
    end

  end # class ParetoPath


  # The result of a bounded Pareto path search.
  class ParetoPathSearchResult

    include Enumerable

    # @return [Array<ParetoPath>]
    attr_reader :paths

    # @return [Boolean] +true+ when the configured work limit stopped the
    #   search before every feasible simple path had been examined
    attr_reader :incomplete

    # @param paths [Array<ParetoPath>]
    # @param incomplete [Boolean]
    def initialize(paths, incomplete)
      @paths = paths
      @incomplete = incomplete
    end

    # @return [Boolean] +false+ when the search examined all feasible simple
    #   paths within the cost limits
    def complete?
      !incomplete
    end

    # @return [Boolean] +true+ when the work limit stopped the search
    def incomplete?
      incomplete
    end

    # Iterates over the Pareto-optimal paths.
    def each(&block)
      paths.each(&block)
    end

    # @return [Hash]
    def to_h
      { paths: paths.map(&:to_h), incomplete: incomplete }
    end

  end # class ParetoPathSearchResult


  # Searches for source-target simple paths that are not strictly dominated by
  # another feasible path in any non-negative cost dimension.
  class ParetoPathsAlgorithm

    # @param graph [Graph]
    # @param edge_costs_map [#call, #[]] maps an edge represented by [u, v] to
    #   an Array of non-negative numeric costs
    # @param cost_limits [Array<Numeric, nil>] optional upper bound for each
    #   cost dimension; +nil+ means that dimension is unbounded
    # @param work_limit [Integer, nil] maximum number of simple-path states to
    #   expand; +nil+ means unlimited
    def initialize(graph, edge_costs_map, cost_limits: nil, work_limit: nil)
      @graph = graph
      @edge_costs_map = edge_costs_map
      @cost_limits = normalize_cost_limits(cost_limits)
      @work_limit = work_limit
      @work_done = 0
      @incomplete = false
      @dimension = @cost_limits.size
      @dimension_initialized = !@cost_limits.empty?

      validate_work_limit
      validate_cost_map
    end

    # Finds the Pareto-optimal simple paths from _source_ to _target_.
    #
    # Costs are never combined into a weighted scalar. Two distinct vertex
    # sequences with the same accumulated vector are both returned, because
    # they are separate feasible paths. Only result objects containing both
    # the same sequence and the same vector are treated as duplicates.
    #
    # @param source [Object]
    # @param target [Object]
    # @return [ParetoPathSearchResult]
    def find(source, target)
      validate_vertex(source, 'source')
      validate_vertex(target, 'target')
      initialize_dimension_from_first_edge unless @dimension_initialized

      @results = []
      @result_set = Set.new

      search(source, target)

      ParetoPathSearchResult.new(@results, @incomplete)
    end

    private

    def search(source, target)
      pending_paths = [[Array.new(@dimension, 0), [source]]]

      until pending_paths.empty?
        if @work_limit && @work_done >= @work_limit
          @incomplete = true
          break
        end

        @work_done += 1

        accumulated_cost, vertices = pending_paths.pop
        current_vertex = vertices.last

        if current_vertex == target
          add_result(vertices, accumulated_cost)
          next
        end

        next_paths = []
        @graph.each_adjacent(current_vertex) do |next_vertex|
          next if vertices.include?(next_vertex)

          edge_cost = edge_cost(current_vertex, next_vertex)
          next_cost = accumulated_cost.zip(edge_cost).map { |accumulated, edge| accumulated + edge }

          next unless within_limits?(next_cost)

          next_paths << [next_cost, vertices + [next_vertex]]
        end
        next_paths.reverse_each { |next_path| pending_paths << next_path }
      end
    end

    def add_result(vertices, cost)
      return unless @results.none? { |result| dominates?(result.cost, cost) }

      @results.reject! { |result| dominates?(cost, result.cost) }
      path = ParetoPath.new(vertices, cost)
      @results << path if @result_set.add?(path)
    end

    def dominates?(left_cost, right_cost)
      left_cost.zip(right_cost).all? { |left, right| left <= right } &&
        left_cost.zip(right_cost).any? { |left, right| left < right }
    end

    def within_limits?(cost)
      cost.zip(@cost_limits).all? { |value, limit| limit.nil? || value <= limit }
    end

    def edge_cost(u, v)
      cost = lookup_edge_cost(u, v)
      validate_edge_cost(cost, u, v)
      cost
    end

    def normalize_cost_limits(cost_limits)
      return [] if cost_limits.nil?

      unless cost_limits.is_a?(Array)
        raise ArgumentError, 'cost limits must be an Array or nil'
      end
      raise ArgumentError, 'cost limits must not be empty' if cost_limits.empty?

      cost_limits.each_with_index do |limit, index|
        next if limit.nil?
        raise ArgumentError, "cost limit #{index} is not numeric" unless limit.is_a?(Numeric)
        raise ArgumentError, "cost limit #{index} is negative" if limit.negative?
      end

      cost_limits
    end

    def lookup_edge_cost(u, v)
      if @edge_costs_map.respond_to?(:call)
        @edge_costs_map.call([u, v])
      else
        key = [u, v]
        if @edge_costs_map.key?(key) || @graph.directed?
          @edge_costs_map[key]
        else
          reverse_key = [v, u]
          @edge_costs_map[reverse_key]
        end
      end
    end

    def validate_cost_map
      return if @edge_costs_map.respond_to?(:call)

      unless @edge_costs_map.respond_to?(:key?)
        raise ArgumentError, 'edge costs must be callable or keyed by edge arrays'
      end

      @graph.each_edge do |u, v|
        cost = lookup_edge_cost(u, v)
        validate_edge_cost(cost, u, v)
        update_dimension(cost.size)
      end
    end

    def initialize_dimension_from_first_edge
      @graph.each_edge do |u, v|
        update_dimension(edge_cost(u, v).size)
        break
      end
    end

    def update_dimension(cost_dimension)
      if @dimension_initialized
        unless cost_dimension == @dimension
          raise ArgumentError, "edge costs have #{cost_dimension} dimensions, expected #{@dimension}"
        end
      else
        @dimension = cost_dimension
        @dimension_initialized = true
      end
    end

    def validate_edge_cost(cost, u, v)
      validate_cost_vector(cost, "edge (#{u}, #{v})")

      if @dimension_initialized && cost.size != @dimension
        raise ArgumentError, "cost of edge (#{u}, #{v}) has #{cost.size} dimensions, expected #{@dimension}"
      end

      cost.each_with_index do |value, index|
        unless value.is_a?(Numeric)
          raise ArgumentError, "cost #{index} of edge (#{u}, #{v}) is not numeric"
        end
        raise ArgumentError, "cost #{index} of edge (#{u}, #{v}) is negative" if value.negative?
      end
    end

    def validate_cost_vector(cost, label)
      unless cost.is_a?(Array)
        raise ArgumentError, "cost of #{label} must be an Array"
      end
      raise ArgumentError, "cost of #{label} must not be empty" if cost.empty?
    end

    def validate_work_limit
      return if @work_limit.nil?

      unless @work_limit.is_a?(Integer)
        raise ArgumentError, 'work limit must be an Integer or nil'
      end
      raise ArgumentError, 'work limit must be positive' unless @work_limit.positive?
    end

    def validate_vertex(vertex, label)
      return if @graph.has_vertex?(vertex)

      raise ArgumentError, "#{label} vertex #{vertex} is not in the graph"
    end

  end # class ParetoPathsAlgorithm


  module Graph

    # Finds Pareto-optimal simple paths from _source_ to _target_ using
    # non-negative, multi-dimensional edge costs.
    #
    # A path is Pareto-optimal when no other feasible source-target simple path
    # is at least as cheap in every dimension and strictly cheaper in at least
    # one. Distinct paths with equal cost vectors are retained. Cost limits are
    # feasibility constraints rather than scalar weights. When _work_limit_ is
    # reached, the returned result is marked incomplete.
    #
    # @param edge_costs_map [#call, #[]] maps [u, v] to an Array of costs
    # @param source [Object] source vertex
    # @param target [Object] target vertex
    # @param cost_limits [Array<Numeric, nil>] optional per-dimension limits
    # @param work_limit [Integer, nil] maximum expanded simple-path states
    # @return [ParetoPathSearchResult]
    #
    # @example Two objectives, latency and monetary cost
    #   graph.pareto_optimal_paths(
    #     { [:a, :b] => [1, 10], [:b, :d] => [1, 10], [:a, :c] => [10, 1], [:c, :d] => [10, 1] },
    #     :a, :d
    #   )
    def pareto_optimal_paths(edge_costs_map, source, target,
                             cost_limits: nil, work_limit: nil)
      ParetoPathsAlgorithm.new(
        self,
        edge_costs_map,
        cost_limits: cost_limits,
        work_limit: work_limit
      ).find(source, target)
    end

  end # module Graph

end # module RGL
