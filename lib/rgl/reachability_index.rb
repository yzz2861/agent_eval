# frozen_string_literal: true

require 'set'
require 'rgl/base'
require 'rgl/adjacency'

module RGL

  # Maintains reachability information while directed graph changes are
  # explicitly committed through the index.
  #
  # The index keeps its own copy of the graph. Mutating a graph passed to the
  # constructor does not change the index; callers must use {#add_edge},
  # {#remove_edge}, {#add_vertex}, or {#remove_vertex} for every change.
  class ReachabilityIndex

    # The answer and graph version used by one reachability query.
    Query = Struct.new(:source, :target, :version, :reachable, keyword_init: true) do
      alias reachable? reachable
    end

    # Metadata describing the part of the index touched by one committed
    # change.
    Update = Struct.new(
      :action,
      :changed,
      :version,
      :affected_sources,
      :affected_targets,
      :recomputed_sources,
      :scanned_vertices,
      :added_vertices,
      :removed_vertices,
      keyword_init: true
    ) do
      alias changed? changed
    end

    # @return [Integer] monotonically increasing version of the current graph
    attr_reader :version

    # Builds an index. When +graph+ is supplied, its vertices and directed
    # edges are copied; the index never observes later external mutations.
    #
    # @param graph [Graph, nil] a directed graph to use as the initial snapshot
    def initialize(graph = nil)
      raise NotDirectedError, 'reachability index only supports directed graphs' if graph && !graph.directed?

      @graph = DirectedAdjacencyGraph.new
      @reachable = {}
      @version = 0

      if graph
        graph.each_vertex { |vertex| @graph.add_vertex(vertex) }
        graph.each_edge { |source, target| @graph.add_edge(source, target) }
        rebuild_all_reachability!
      end
    end

    # @return [Array] the vertices in the indexed snapshot
    def vertices
      @graph.vertices
    end

    # @param vertex [Object]
    # @return [Boolean] whether +vertex+ is in the indexed snapshot
    def has_vertex?(vertex)
      @graph.has_vertex?(vertex)
    end

    # @param source [Object]
    # @param target [Object]
    # @return [Boolean] whether +source -> target+ is an edge
    def has_edge?(source, target)
      @graph.has_edge?(source, target)
    end

    # @return [Array<RGL::Edge::DirectedEdge>] all edges in the snapshot
    def edges
      @graph.edges
    end

    # Commits adding a vertex.
    #
    # @param vertex [Object]
    # @return [Update]
    def add_vertex(vertex)
      return no_change_update(:add_vertex) if @graph.has_vertex?(vertex)

      @graph.add_vertex(vertex)
      @reachable[vertex] = Set.new([vertex])
      increment_version!

      build_update(
        action: :add_vertex,
        affected_sources: [vertex],
        affected_targets: [vertex],
        recomputed_sources: [vertex],
        scanned_vertices: [vertex],
        added_vertices: [vertex]
      )
    end

    # Commits adding the directed edge +source -> target+.
    #
    # Only sources that could already reach +source+ can gain reachability.
    # Their reachable sets are extended with the current reachable set of
    # +target+.
    #
    # @param source [Object]
    # @param target [Object]
    # @return [Update]
    def add_edge(source, target)
      return no_change_update(:add_edge) if @graph.has_edge?(source, target)

      added_vertices = []
      unless @graph.has_vertex?(source)
        @graph.add_vertex(source)
        @reachable[source] = Set.new([source])
        added_vertices << source
      end
      unless @graph.has_vertex?(target)
        @graph.add_vertex(target)
        @reachable[target] = Set.new([target])
        added_vertices << target
      end

      affected_sources = sources_reaching(source)
      affected_targets = @reachable[target].dup

      @graph.add_edge(source, target)
      affected_sources.each do |affected_source|
        @reachable[affected_source].merge(affected_targets)
      end
      increment_version!

      build_update(
        action: :add_edge,
        affected_sources: affected_sources,
        affected_targets: affected_targets,
        recomputed_sources: affected_sources,
        scanned_vertices: affected_targets,
        added_vertices: added_vertices
      )
    end

    # Commits removing the directed edge +source -> target+.
    #
    # Reachability is recomputed only for vertices that reached +source+ while
    # the edge was present. Vertices outside that prefix cannot have used the
    # removed edge.
    #
    # @param source [Object]
    # @param target [Object]
    # @return [Update]
    def remove_edge(source, target)
      return no_change_update(:remove_edge) unless @graph.has_edge?(source, target)

      affected_sources = sources_reaching(source)
      @graph.remove_edge(source, target)
      scanned_vertices = recompute_sources(affected_sources)
      increment_version!

      build_update(
        action: :remove_edge,
        affected_sources: affected_sources,
        affected_targets: [],
        recomputed_sources: affected_sources,
        scanned_vertices: scanned_vertices
      )
    end

    # Commits removing a vertex and all of its incident edges.
    #
    # Other vertices are recomputed only when they reached the removed vertex
    # before the change.
    #
    # @param vertex [Object]
    # @return [Update]
    def remove_vertex(vertex)
      return no_change_update(:remove_vertex) unless @graph.has_vertex?(vertex)

      affected_sources = sources_reaching(vertex)
      recomputed_sources = affected_sources.dup
      recomputed_sources.delete(vertex)

      @graph.remove_vertex(vertex)
      @reachable.delete(vertex)
      scanned_vertices = recompute_sources(recomputed_sources)
      increment_version!

      build_update(
        action: :remove_vertex,
        affected_sources: affected_sources,
        affected_targets: [],
        recomputed_sources: recomputed_sources,
        scanned_vertices: scanned_vertices,
        removed_vertices: [vertex]
      )
    end

    # Answers a reachability query against the current version.
    #
    # @param source [Object]
    # @param target [Object]
    # @return [Query]
    def query(source, target)
      Query.new(
        source: source,
        target: target,
        version: @version,
        reachable: reachable?(source, target)
      ).freeze
    end

    # @param source [Object]
    # @param target [Object]
    # @return [Boolean] whether +target+ is reachable from +source+
    def reachable?(source, target)
      return false unless @graph.has_vertex?(source) && @graph.has_vertex?(target)

      @reachable.fetch(source).include?(target)
    end

    private

    def rebuild_all_reachability!
      @reachable = {}
      @graph.each_vertex do |source|
        @reachable[source] = reachable_from(source)
      end
    end

    def reachable_from(source)
      visited = Set.new([source])
      pending = [source]

      while (current = pending.pop)
        @graph.each_adjacent(current) do |neighbor|
          next if visited.include?(neighbor)

          visited << neighbor
          pending << neighbor
        end
      end

      visited
    end

    def sources_reaching(vertex)
      @reachable.each_key.with_object(Set.new) do |source, sources|
        sources << source if @reachable.fetch(source).include?(vertex)
      end
    end

    def recompute_sources(sources)
      scanned = Set.new

      sources.each do |source|
        reachable = reachable_from(source)
        @reachable[source] = reachable
        scanned.merge(reachable)
      end

      scanned
    end

    def increment_version!
      @version += 1
    end

    def no_change_update(action)
      build_update(
        action: action,
        changed: false,
        affected_sources: [],
        affected_targets: [],
        recomputed_sources: [],
        scanned_vertices: []
      )
    end

    def build_update(options)
      update_options = {
        changed: true,
        version: @version,
        added_vertices: [],
        removed_vertices: []
      }.merge(options)

      range_fields = [
        :affected_sources,
        :affected_targets,
        :recomputed_sources,
        :scanned_vertices,
        :added_vertices,
        :removed_vertices
      ]

      range_fields.each do |field|
        value = update_options[field]
        update_options[field] = value.is_a?(Set) ? value.dup.freeze : Set.new(value).freeze
      end

      Update.new(**update_options).freeze
    end

  end
end
