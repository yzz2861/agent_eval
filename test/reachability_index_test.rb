require 'test_helper'

require 'rgl/adjacency'
require 'rgl/reachability_index'

include RGL

class TestReachabilityIndex < Test::Unit::TestCase

  def test_fixed_change_sequence_matches_traversal
    reference = DirectedAdjacencyGraph.new
    @index = ReachabilityIndex.new

    changes = [
      [:add_vertex, 9],
      [:add_edge, 1, 2],
      [:add_edge, 2, 3],
      [:add_edge, 4, 5],
      [:add_edge, 2, 4],
      [:add_edge, 6, 1],
      [:add_edge, 3, 2],
      [:add_edge, 1, 1],
      [:remove_edge, 2, 4],
      [:remove_edge, 3, 2],
      [:add_edge, 3, 4],
      [:remove_vertex, 1],
      [:add_edge, 6, 3],
      [:remove_edge, 9, 9],
      [:add_vertex, 2],
      [:add_edge, 3, 4]
    ]

    no_op_change_indices = [13, 14, 15].to_set

    changes.each_with_index do |change, change_index|
      expected_changed = !no_op_change_indices.include?(change_index)
      expected_version = @index.version + (expected_changed ? 1 : 0)

      apply_reference_change(reference, change)
      update = apply_index_change(@index, change)

      assert_equal(expected_version, @index.version)
      assert_equal(expected_version, update.version)
      assert_equal(expected_changed, update.changed?)
      assert_reachability_matches_traversal(@index, reference)
    end

    assert_equal([2, 3, 4, 5, 6, 9], @index.vertices.sort)
  end

  def test_add_edge_reports_only_affected_prefix_and_suffix
    index = ReachabilityIndex.new(DirectedAdjacencyGraph[1, 2, 3, 4])

    update = index.add_edge(2, 3)

    assert_equal([1, 2].to_set, update.affected_sources)
    assert_equal([3, 4].to_set, update.affected_targets)
    assert_equal([1, 2].to_set, update.recomputed_sources)
    assert_equal([3, 4].to_set, update.scanned_vertices)
    assert(index.reachable?(1, 4))
    assert(!index.reachable?(3, 1))
  end

  def test_remove_edge_recomputes_only_old_sources_reaching_its_source
    graph = DirectedAdjacencyGraph[
      1, 2,
      2, 3,
      3, 4,
      5, 3,
      6, 7
    ]
    index = ReachabilityIndex.new(graph)

    update = index.remove_edge(3, 4)

    assert_equal([1, 2, 3, 5].to_set, update.affected_sources)
    assert_equal([1, 2, 3, 5].to_set, update.recomputed_sources)
    assert_equal([1, 2, 3, 5].to_set, update.scanned_vertices)

    assert(!index.reachable?(1, 4))
    assert(!index.reachable?(5, 4))
    assert(index.reachable?(6, 7))
  end

  def test_remove_vertex_recomputes_only_old_sources_reaching_it
    graph = DirectedAdjacencyGraph[
      1, 2,
      2, 3,
      4, 2,
      5, 6
    ]
    index = ReachabilityIndex.new(graph)

    update = index.remove_vertex(2)

    assert_equal([1, 2, 4].to_set, update.affected_sources)
    assert_equal([1, 4].to_set, update.recomputed_sources)
    assert_equal([1, 4].to_set, update.scanned_vertices)
    assert_equal([2].to_set, update.removed_vertices)

    assert(!index.has_vertex?(2))
    assert(!index.reachable?(1, 3))
    assert(!index.reachable?(4, 3))
    assert(index.reachable?(5, 6))
  end

  def test_query_carries_version_and_old_results_are_not_mutated
    graph = DirectedAdjacencyGraph[1, 2]
    index = ReachabilityIndex.new(graph)

    before = index.query(1, 3)
    assert_equal(0, before.version)
    assert(!before.reachable?)

    index.add_edge(2, 3)
    after = index.query(1, 3)

    assert_equal(1, after.version)
    assert(after.reachable?)
    assert_equal(0, before.version)
    assert(!before.reachable?)
    assert_raise(FrozenError) { before.version = 2 }
  end

  def test_index_does_not_observe_external_graph_mutations
    graph = DirectedAdjacencyGraph[1, 2]
    index = ReachabilityIndex.new(graph)

    graph.add_edge(2, 3)
    graph.remove_edge(1, 2)

    assert(index.has_edge?(1, 2))
    assert(!index.has_vertex?(3))
    assert(index.reachable?(1, 2))
  end

  def test_undirected_graph_is_rejected
    assert_raises(NotDirectedError) { ReachabilityIndex.new(AdjacencyGraph[1, 2]) }
  end

  private

  def apply_reference_change(graph, change)
    action, source, target = change
    case action
    when :add_edge
      graph.add_edge(source, target)
    when :remove_edge
      graph.remove_edge(source, target) if graph.has_vertex?(source)
    when :add_vertex
      graph.add_vertex(source)
    when :remove_vertex
      graph.remove_vertex(source) if graph.has_vertex?(source)
    end
  end

  def apply_index_change(index, change)
    action, source, target = change
    case action
    when :add_edge then index.add_edge(source, target)
    when :remove_edge then index.remove_edge(source, target)
    when :add_vertex then index.add_vertex(source)
    when :remove_vertex then index.remove_vertex(source)
    end
  end

  def assert_reachability_matches_traversal(index, graph)
    graph.vertices.each do |source|
      graph.vertices.each do |target|
        expected = traversal_reachable?(graph, source, target)
        assert_equal(expected, index.reachable?(source, target), "#{source} -> #{target}")

        query = index.query(source, target)
        assert_equal(index.version, query.version)
        assert_equal(expected, query.reachable?)
      end
    end
  end

  def traversal_reachable?(graph, source, target)
    visited = Set.new([source])
    pending = [source]

    while (current = pending.pop)
      return true if current == target

      graph.each_adjacent(current) do |neighbor|
        next if visited.include?(neighbor)

        visited << neighbor
        pending << neighbor
      end
    end

    false
  end

end
