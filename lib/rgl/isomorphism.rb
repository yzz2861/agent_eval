# frozen_string_literal: true

require 'rgl/base'
require 'set'

module RGL

  # Graph isomorphism matching for directed and undirected graphs.
  module Isomorphism

    # Outcome of an isomorphism search.
    class Result
      attr_reader :status, :mapping, :attempts

      def initialize(status, mapping = nil, attempts = 0)
        @status = status
        @mapping = mapping
        @attempts = attempts
      end

      def isomorphic?
        status == :isomorphic
      end

      def not_isomorphic?
        status == :not_isomorphic
      end

      def limit_reached?
        status == :limit_reached
      end
    end

    DEFAULT_NODE_LABEL = ->(_graph, _vertex) { nil }
    private_constant :DEFAULT_NODE_LABEL

    DEFAULT_EDGE_LABEL = ->(_graph, _source, _target) { nil }
    private_constant :DEFAULT_EDGE_LABEL

    EMPTY_LABELS = {}.freeze
    private_constant :EMPTY_LABELS

    # Finds a node mapping from +graph1+ to +graph2+.
    #
    # Node IDs are used only as hash keys. Structural matching uses topology
    # together with labels returned by +node_label+ and +edge_label+. A
    # node-label reader accepts either +(vertex)+ or +(graph, vertex)+. An
    # edge-label reader accepts either +(source, target)+ or
    # +(graph, source, target)+. For undirected graphs, edge labels must be
    # unchanged when the two endpoints are reversed.
    #
    # Parallel edges are accepted. Their multiplicity is compared, including
    # self loops. Because RGL edges have no independent edge-object identity,
    # parallel edges between the same endpoints cannot carry distinct labels
    # through this reader API. Use an array-backed adjacency graph, such as
    # <tt>AdjacencyGraph.new(Array)</tt>, when parallel undirected edges must
    # be retained; the default +Set+ representation deduplicates them.
    #
    # +search_limit+ bounds the number of candidate vertex assignments tested.
    # If it is exhausted before the search is complete, the result status is
    # +:limit_reached+ rather than +:not_isomorphic+.
    #
    # @param graph1 [Graph]
    # @param graph2 [Graph]
    # @param node_label [#call]
    # @param edge_label [#call]
    # @param search_limit [Integer, nil]
    # @return [Result]
    def self.find(graph1, graph2, node_label: nil, edge_label: nil, search_limit: nil)
      node_label ||= DEFAULT_NODE_LABEL
      edge_label ||= DEFAULT_EDGE_LABEL
      limit = validate_search_limit(search_limit)
      validate_reader(node_label, :node_label)
      validate_reader(edge_label, :edge_label)

      data1 = GraphData.build(graph1, node_label, edge_label)
      data2 = GraphData.build(graph2, node_label, edge_label)

      return Result.new(:not_isomorphic) unless compatible?(data1, data2)

      status, mapping, attempts = Searcher.new(data1, data2, limit).search
      Result.new(status, mapping, attempts)
    end

    def self.compatible?(data1, data2)
      data1.directed == data2.directed &&
        data1.vertices.size == data2.vertices.size &&
        data1.total_edges == data2.total_edges &&
        signature_distribution(data1) == signature_distribution(data2) &&
        data1.edge_label_counts == data2.edge_label_counts
    end

    def self.signature_distribution(data)
      data.vertices.each_with_object(Hash.new(0)) do |vertex, distribution|
        distribution[signature(data, vertex)] += 1
      end
    end

    def self.signature(data, vertex)
      if data.directed
        [data.node_labels[vertex], data.out_degree[vertex], data.in_degree[vertex]]
      else
        [data.node_labels[vertex], data.out_degree[vertex]]
      end
    end

    def self.validate_reader(reader, name)
      return if reader.respond_to?(:call)

      raise ArgumentError, "#{name} must respond to #call"
    end

    def self.validate_search_limit(search_limit)
      return nil if search_limit.nil?

      limit = search_limit.respond_to?(:to_int) ? search_limit.to_int : search_limit
      unless limit.is_a?(Integer) && limit >= 0
        raise ArgumentError, 'search_limit must be a non-negative Integer or nil'
      end

      limit
    end

    def self.read_label(reader, graph, *arguments)
      reader_arguments = reader.arity == arguments.size ? arguments : [graph, *arguments]
      reader.call(*reader_arguments)
    end

    private_class_method :compatible?, :signature_distribution, :signature,
                         :validate_reader, :validate_search_limit, :read_label

    # @private
    GraphData = Struct.new(:graph, :vertices, :node_labels, :directed, :edge_labels,
                           :out_degree, :in_degree, :edge_label_counts, :total_edges)

    class GraphData
      def self.build(graph, node_label_reader, edge_label_reader)
        vertices = []
        graph.each_vertex { |vertex| vertices << vertex }

        node_labels = vertices.to_h do |vertex|
          [vertex, Isomorphism.send(:read_label, node_label_reader, graph, vertex)]
        end

        edge_labels = build_edge_labels(graph, vertices, edge_label_reader)
        out_degree = vertices.to_h { |vertex| [vertex, 0] }
        in_degree = vertices.to_h { |vertex| [vertex, 0] }

        edge_labels.each do |(source, target), labels|
          multiplicity = labels.values.sum
          if graph.directed?
            out_degree[source] += multiplicity
            in_degree[target] += multiplicity
          else
            out_degree[source] += multiplicity
            out_degree[target] += multiplicity
          end
        end

        edge_label_counts = Hash.new(0)
        edge_labels.each_value do |labels|
          labels.each { |label, count| edge_label_counts[label] += count }
        end

        total_edges = edge_labels.values.sum { |labels| labels.values.sum }

        new(graph, vertices, node_labels, graph.directed?, edge_labels,
            out_degree, in_degree, edge_label_counts, total_edges)
      end

      def self.build_edge_labels(graph, vertices, edge_label_reader)
        adjacency = Hash.new { |labels, key| labels[key] = [] }

        vertices.each do |source|
          graph.each_adjacent(source) do |target|
            adjacency[[source, target]] <<
              Isomorphism.send(:read_label, edge_label_reader, graph, source, target)
          end
        end

        if graph.directed?
          adjacency.transform_values(&:tally)
        else
          undirected_edge_labels(adjacency, vertices)
        end
      end

      def self.undirected_edge_labels(adjacency, vertices)
        edge_labels = {}

        vertices.each do |vertex|
          labels = adjacency[[vertex, vertex]]
          next if labels.empty?

          # Standard undirected RGL graphs report a self loop in both
          # directions; graph adapters may report it only once.
          edge_labels[[vertex, vertex]] = labels.each_slice(2).map(&:first).tally
        end

        processed = {}
        adjacency.each do |(source, target), labels|
          next if source == target
          next if processed[[target, source]]

          processed[[source, target]] = true
          edge_labels[[source, target]] = labels.tally
        end

        edge_labels
      end

      def labels_between(source, target)
        labels = edge_labels[[source, target]]
        return labels if labels
        if !directed
          return edge_labels.fetch([target, source], EMPTY_LABELS)
        end

        EMPTY_LABELS
      end
    end

    # @private
    class Searcher
      def initialize(data1, data2, search_limit)
        @data1 = data1
        @data2 = data2
        @search_limit = search_limit
        @mapping = {}
        @used_targets = Set.new
        @attempts = 0
        @candidate_groups = data2.vertices.group_by do |vertex|
          Isomorphism.send(:signature, data2, vertex)
        end
        @source_order = data1.vertices.each_with_index.sort_by do |vertex, index|
          [-degree(data1, vertex), -data1.out_degree[vertex], index]
        end.map(&:first)
      end

      def search
        search_vertex_set
      end

      private

      def search_vertex_set
        if @mapping.size == @data1.vertices.size
          return complete_mapping_verified? ? verified_result : [:not_isomorphic, nil, @attempts]
        end

        source = choose_source

        candidates(source).each do |target|
          if !@search_limit.nil? && @attempts >= @search_limit
            return [:limit_reached, nil, @attempts]
          end

          @attempts += 1
          next unless compatible_assignment?(source, target)

          assign(source, target)
          status, _mapping, attempts = search_vertex_set
          @attempts = attempts

          if status == :isomorphic
            return [status, @mapping.dup, attempts]
          elsif status == :limit_reached
            return [status, nil, attempts]
          end

          unassign(source)
        end

        [:not_isomorphic, nil, @attempts]
      end

      def choose_source
        unmapped = @source_order.reject { |vertex| @mapping.key?(vertex) }
        unmapped.max_by do |vertex|
          mapped_neighbors = @mapping.count do |mapped, _target|
            linked?(vertex, mapped, @data1) || linked?(mapped, vertex, @data1)
          end
          [mapped_neighbors, degree(@data1, vertex)]
        end
      end

      def candidates(source)
        signature = Isomorphism.send(:signature, @data1, source)
        @candidate_groups.fetch(signature, []).reject do |target|
          @used_targets.include?(target)
        end
      end

      def compatible_assignment?(source, target)
        return false unless same_labels_between?(source, source, target, target)

        @mapping.all? do |mapped_source, mapped_target|
          if @data1.directed
            same_labels_between?(source, mapped_source, target, mapped_target) &&
              same_labels_between?(mapped_source, source, mapped_target, target)
          else
            same_labels_between?(source, mapped_source, target, mapped_target)
          end
        end
      end

      def same_labels_between?(source1, target1, source2, target2)
        @data1.labels_between(source1, target1) ==
          @data2.labels_between(source2, target2)
      end

      def linked?(first, second, data)
        !data.labels_between(first, second).empty?
      end

      def complete_mapping_verified?
        return false unless @mapping.size == @data2.vertices.size
        return false unless @used_targets == Set.new(@data2.vertices)

        @data1.edge_labels.all? do |(source, target), labels|
          mapped_source = @mapping[source]
          mapped_target = @mapping[target]
          @data2.labels_between(mapped_source, mapped_target) == labels
        end
      end

      def verified_result
        mapping = @mapping.dup
        mapping.freeze
        [:isomorphic, mapping, @attempts]
      end

      def assign(source, target)
        @mapping[source] = target
        @used_targets.add(target)
      end

      def unassign(source)
        @used_targets.delete(@mapping.delete(source))
      end

      def degree(data, vertex)
        data.out_degree[vertex] + data.in_degree[vertex]
      end
    end
  end

  module Graph
    def find_isomorphism(other, node_label: nil, edge_label: nil, search_limit: nil)
      Isomorphism.find(self, other,
                       node_label: node_label,
                       edge_label: edge_label,
                       search_limit: search_limit)
    end
  end
end
