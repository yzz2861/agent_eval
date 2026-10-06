# frozen_string_literal: true

require 'pairing_heap'

require 'rgl/edge_properties_map'

module RGL

  # Lazily enumerates loop-free paths from a source to a target in nondecreasing order of total weight.
  #
  # Yen's algorithm is used to generate candidates. Equal-cost paths are ordered by the deterministic discovery
  # order of vertices and edges supplied by the graph; vertices themselves do not need to be comparable.
  class SimplePathEnumerator

    include Enumerable

    QueueEntry = Struct.new(:distance, :sequence) do

      include Comparable

      def <=>(other)
        result = distance <=> other.distance
        result.zero? ? sequence <=> other.sequence : result
      end

    end

    def initialize(graph, edge_weights_map, source, target)
      @graph            = graph
      @edge_weights_map = NonNegativeEdgePropertiesMap.new(edge_weights_map, graph.directed?)
      @source           = source
      @target           = target
    end

    def each
      return enum_for(:each) unless block_given?

      return unless @graph.has_vertex?(@source) && @graph.has_vertex?(@target)
      require 'rgl/adjacency'

      first_path = shortest_path(@graph)
      return unless first_path

      yield first_path

      selected_paths = [first_path]
      candidates     = []
      seen_paths     = { first_path => true }

      while (previous_path = selected_paths.last)
        generate_candidates(previous_path, selected_paths, candidates, seen_paths)

        candidate_index = candidates.each_with_index.min_by { |(path, index)| [path_cost(path), index] }
        path, index     = candidate_index
        break unless path

        candidates.delete_at(index)
        seen_paths[path] = true
        selected_paths << path
        yield path
      end
    end

    private

    def generate_candidates(previous_path, selected_paths, candidates, seen_paths)
      require 'rgl/adjacency'

      (0...(previous_path.size - 1)).each do |i|
        candidate_graph = @graph.to_adjacency
        root_path       = previous_path[0, i]
        spur_node       = previous_path[i]

        selected_paths.each do |path|
          next unless path.length > i + 1 && path[i] == spur_node && path[0, i] == root_path

          candidate_graph.remove_edge(path[i], path[i + 1])
        end

        root_path.each { |vertex| candidate_graph.remove_vertex(vertex) }

        path = shortest_path(candidate_graph, spur_node)
        next unless path

        candidate = root_path + path
        next if seen_paths.key?(candidate)

        seen_paths[candidate] = true
        candidates << candidate
      end
    end

    def shortest_path(graph, source = @source)
      distances = { source => 0 }
      parents   = {}
      sequence  = 0
      queue     = PairingHeap::MinPriorityQueue.new
      settled   = {}
      queued    = { source => true }

      queue.push(source, QueueEntry.new(0, sequence))

      until queue.empty?
        vertex = queue.pop
        next if settled.key?(vertex)
        queued.delete(vertex)
        return restore_path(vertex, parents) if vertex == @target
        settled[vertex] = true

        graph.each_adjacent(vertex) do |neighbor|
          next if settled.key?(neighbor)

          new_distance = distances[vertex] + @edge_weights_map.edge_property(vertex, neighbor)
          old_distance = distances.fetch(neighbor, INFINITY)

          next unless new_distance < old_distance

          distances[neighbor] = new_distance
          parents[neighbor]   = vertex
          priority           = QueueEntry.new(new_distance, sequence)

          unless queued.key?(neighbor)
            queue.push(neighbor, priority)
            queued[neighbor] = true
          else
            queue.decrease_key(neighbor, priority)
          end

          sequence += 1
        end
      end

      nil
    end

    def restore_path(target, parents)
      path = []
      vertex = target

      while vertex
        path.unshift(vertex)
        vertex = parents[vertex]
      end

      path
    end

    def path_cost(path)
      path.each_cons(2).sum(0) { |u, v| @edge_weights_map.edge_property(u, v) }
    end

  end # class SimplePathEnumerator

  module Graph

    # Enumerates simple paths from the _source_ to the _target_ in nondecreasing order of total edge weight.
    #
    # Paths are generated lazily, so taking only the first three paths does not generate all remaining simple paths.
    # Zero-weight edges are supported. Equal-weight paths are emitted in deterministic graph traversal order, so vertex
    # objects do not need to implement comparison.
    #
    # If a block is provided, each path is yielded to it. Without a block, an Enumerator is returned. When _source_ and
    # _target_ are equal, the only path is the one-vertex trivial path. If no path exists, the enumerator is empty.
    #
    # Raises ArgumentError if edge weight is negative or undefined.
    #
    def dijkstra_simple_paths(edge_weights_map, source, target)
      path_enumerator = SimplePathEnumerator.new(self, edge_weights_map, source, target)
      return path_enumerator.each unless block_given?

      path_enumerator.each { |path| yield(path) }
    end

  end # module Graph

end # module RGL
