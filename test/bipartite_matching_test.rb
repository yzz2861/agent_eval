# frozen_string_literal: true

require 'test_helper'

require 'rgl/bipartite'
require 'rgl/adjacency'

include RGL

class TestBipartiteMatching < Test::Unit::TestCase

  # Classic allocation example: tickets and the processors which can take them.
  def setup
    @graph = AdjacencyGraph[:t1, :h1, :t1, :h2, :t2, :h2, :t3, :h3]
    @tickets = %i[t1 t2 t3]
    @handlers = %i[h1 h2 h3]
  end

  def test_matching_pairs_connect_adjacent_vertices
    matching = @graph.maximum_bipartite_matching(@tickets, @handlers)

    assert_equal(3, matching.size)
    matching.pairs.each do |ticket, handler|
      assert(@graph.has_edge?(ticket, handler))
      assert(@tickets.include?(ticket))
      assert(@handlers.include?(handler))
    end
  end

  def test_pairs_use_declared_side_order
    matching = @graph.maximum_bipartite_matching(@tickets, @handlers)

    assert_equal([[:t1, :h1], [:t2, :h2], [:t3, :h3]], matching.pairs)
  end

  def test_matching_is_enumerable
    matching = @graph.maximum_bipartite_matching(@tickets, @handlers)

    collected = []
    matching.each { |u, v| collected << [u, v] }
    assert_equal(matching.pairs, collected)
    assert_equal(3, matching.map { |u, _v| u }.size)
  end

  def test_perfect_matching
    graph = AdjacencyGraph[1, 3, 1, 4, 2, 3]
    matching = graph.maximum_bipartite_matching([1, 2], [3, 4])

    assert_equal(2, matching.size)
    assert(matching.perfect?)
    assert(matching.first_side_complete?)
    assert_nil(matching.deficient_set)
    assert_nil(matching.neighbors_of_deficient_set)
    assert_equal([], matching.unmatched_first_side_vertices)
    assert_equal([], matching.unmatched_second_side_vertices)
  end

  def test_partner_lookups
    matching = @graph.maximum_bipartite_matching(@tickets, @handlers)

    assert_equal(:h1, matching.partner_of(:t1))
    assert_equal(:t1, matching.partner_of(:h1))
    assert_nil(matching.partner_of(:unknown))
    assert(matching.matched?(:t3))
    assert(!matching.matched?(:unknown))
  end

  def test_first_side_cannot_be_fully_matched
    graph = AdjacencyGraph[1, 4, 2, 5, 3, 5]
    matching = graph.maximum_bipartite_matching([1, 2, 3], [4, 5])

    assert_equal(2, matching.size)
    assert(!matching.first_side_complete?)
    assert(!matching.perfect?)
    assert_equal([3], matching.unmatched_first_side_vertices)
  end

  def test_deficient_set_is_a_hall_witness
    graph = AdjacencyGraph[1, 4, 2, 5, 3, 5]
    matching = graph.maximum_bipartite_matching([1, 2, 3], [4, 5])

    deficient = matching.deficient_set
    neighbors = matching.neighbors_of_deficient_set

    assert_not_nil(deficient)
    assert(deficient.include?(3))
    assert_equal(neighbors_of(graph, deficient), neighbors)
    assert_operator(neighbors.size, :<, deficient.size)
  end

  def test_deficient_set_for_two_vertices_sharing_one_neighbor
    graph = AdjacencyGraph[:a, :x, :b, :x, :c, :y, :d, :z]
    matching = graph.maximum_bipartite_matching(%i[a b c d], %i[x y z])

    deficient = matching.deficient_set
    neighbors = matching.neighbors_of_deficient_set

    assert_equal(3, matching.size)
    assert_equal([:a, :b], deficient)
    assert_equal([:x], neighbors)
    assert_operator(neighbors.size, :<, deficient.size)
  end

  def test_isolated_vertex_on_first_side_is_deficient
    graph = AdjacencyGraph[1, 4, 2, 5]
    graph.add_vertex(3) # isolated
    matching = graph.maximum_bipartite_matching([1, 2, 3], [4, 5])

    assert_equal(2, matching.size)
    assert_equal([3], matching.deficient_set)
    assert_equal([], matching.neighbors_of_deficient_set)
    assert_equal([3], matching.unmatched_first_side_vertices)
    assert(!matching.matched?(3))
  end

  def test_isolated_vertex_on_second_side_is_not_a_first_side_deficiency
    graph = AdjacencyGraph[1, 4]
    graph.add_vertex(5) # isolated
    matching = graph.maximum_bipartite_matching([1], [4, 5])

    assert_equal(1, matching.size)
    assert(matching.first_side_complete?)
    assert_nil(matching.deficient_set)
    assert(!matching.perfect?)
    assert_equal([5], matching.unmatched_second_side_vertices)
  end

  def test_empty_graph
    matching = AdjacencyGraph.new.maximum_bipartite_matching([], [])

    assert_equal(0, matching.size)
    assert_equal([], matching.pairs)
    assert(matching.perfect?)
    assert(matching.first_side_complete?)
    assert_nil(matching.deficient_set)
  end

  def test_only_isolated_vertices
    graph = AdjacencyGraph.new
    graph.add_vertex(1)
    graph.add_vertex(2)
    matching = graph.maximum_bipartite_matching([1], [2])

    assert_equal(0, matching.size)
    assert_equal([1], matching.deficient_set)
    assert_equal([], matching.neighbors_of_deficient_set)
  end

  def test_disconnected_components
    graph = AdjacencyGraph[1, 3, 2, 4]
    matching = graph.maximum_bipartite_matching([1, 2], [3, 4])

    assert_equal(2, matching.size)
    assert(matching.perfect?)
  end

  def test_vertices_need_not_be_comparable
    tickets = Array.new(3) { Object.new }
    handlers = Array.new(2) { Object.new }
    graph = AdjacencyGraph.new
    graph.add_edge(tickets[0], handlers[0])
    graph.add_edge(tickets[1], handlers[0])
    graph.add_edge(tickets[2], handlers[1])

    matching = graph.maximum_bipartite_matching(tickets, handlers)

    assert_equal(2, matching.size)
    assert(matching.pairs.all? { |u, v| graph.has_edge?(u, v) })
    assert_equal(2, matching.deficient_set.size)
    assert_operator(matching.neighbors_of_deficient_set.size, :<, matching.deficient_set.size)
  end

  def test_result_is_repeatable_under_stable_enumeration
    graph = AdjacencyGraph[:a, :x, :a, :y, :b, :x, :c, :z, :d, :z]
    sides = [%i[a b c d], %i[x y z]]

    first = graph.maximum_bipartite_matching(*sides)
    second = graph.maximum_bipartite_matching(*sides)

    assert_equal(first.pairs, second.pairs)
    assert_equal(first.deficient_set, second.deficient_set)
    assert_equal(first.neighbors_of_deficient_set, second.neighbors_of_deficient_set)
  end

  def test_sides_are_used_in_given_order_without_sorting
    graph = AdjacencyGraph[1, 3, 2, 4]
    matching = graph.maximum_bipartite_matching([2, 1], [4, 3])

    assert_equal([[2, 4], [1, 3]], matching.pairs)
  end

  def test_rejects_directed_graph
    assert_raise(NotUndirectedError) do
      DirectedAdjacencyGraph[1, 2].maximum_bipartite_matching([1], [2])
    end
  end

  def test_rejects_overlapping_sides
    graph = AdjacencyGraph[1, 2]
    assert_raise(ArgumentError) do
      graph.maximum_bipartite_matching([1, 2], [2])
    end
  end

  def test_rejects_same_side_edge
    graph = AdjacencyGraph[1, 2, 2, 3]
    assert_raise(ArgumentError) do
      graph.maximum_bipartite_matching([1, 2], [3])
    end
  end

  def test_rejects_vertex_declared_but_not_in_graph
    graph = AdjacencyGraph[1, 3]
    assert_raise(ArgumentError) do
      graph.maximum_bipartite_matching([1, 2], [3])
    end
  end

  def test_rejects_graph_vertex_missing_from_sides
    graph = AdjacencyGraph[1, 3, 2, 4]
    assert_raise(ArgumentError) do
      graph.maximum_bipartite_matching([1], [3, 4])
    end
  end

  def test_duplicate_vertices_within_a_side_are_ignored
    graph = AdjacencyGraph[1, 3, 2, 4]
    matching = graph.maximum_bipartite_matching([1, 2, 1], [3, 4, 3])

    assert_equal(2, matching.size)
    assert_equal([[1, 3], [2, 4]], matching.pairs)
  end

  def test_smaller_side_declared_first_can_be_fully_matched
    # Same graph which fails for the larger side; the smaller side saturates.
    graph = AdjacencyGraph[1, 4, 2, 5, 3, 5]
    matching = graph.maximum_bipartite_matching([4, 5], [1, 2, 3])

    assert_equal(2, matching.size)
    assert(matching.first_side_complete?)
    assert_nil(matching.deficient_set)
  end

  private

  def neighbors_of(graph, vertices)
    result = []
    seen = {}
    vertices.each do |u|
      graph.each_adjacent(u) do |v|
        unless seen.key?(v)
          seen[v] = true
          result << v
        end
      end
    end
    result
  end

end
