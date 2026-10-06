require 'test_helper'

require 'rgl/bipartite'
require 'rgl/adjacency'

include RGL

class TestBipartite < Test::Unit::TestCase

  def test_bipartite_sets
    assert_equal([[1, 2, 3], [4, 5, 6]], bipartite_sets(AdjacencyGraph[1,5, 1,6, 2,4, 2,5, 3,4, 3,5, 3,6]))
  end

  def test_bipartite_sets_for_non_bipartite_graph
    assert_equal(nil, bipartite_sets(AdjacencyGraph[1,4, 1,5, 2,3, 2,4, 2,5, 3,5]))
  end

  def test_bipartite_sets_for_directed_graph
    assert_raise(NotUndirectedError, 'bipartite sets can only be found for an undirected graph') do
      DirectedAdjacencyGraph.new.bipartite_sets
    end
  end

  def test_bipartite_sets_for_bipartite_disconnected_graph
    assert_equal([[1, 3], [2, 4]], bipartite_sets(AdjacencyGraph[1,2, 3,4]))
  end

  def test_bipartite_sets_for_non_bipartite_disconnected_graph
    assert_equal(nil, bipartite_sets(AdjacencyGraph[1,2, 3,4, 4,5, 5,3]))
  end

  def test_bipartite
    assert(AdjacencyGraph[1,2, 2,3].bipartite?)
  end

  def test_not_bipartite
    assert(!AdjacencyGraph[1,2, 2,3, 3,1].bipartite?)
  end

  private

  def bipartite_sets(graph)
    sets = graph.bipartite_sets
    sets && sets.map { |set| set.sort }.sort
  end

end

class TestBipartiteGraph < Test::Unit::TestCase

  def setup
    @graph = BipartiteGraph.new(%i[ticket1 ticket2 ticket3], %i[agent1 agent2])
    @graph.add_edge(:ticket1, :agent1)
    @graph.add_edge(:ticket2, :agent1)
    @graph.add_edge(:ticket2, :agent2)
    @graph.add_edge(:ticket3, :agent2)
  end

  def test_rejects_vertex_declared_in_both_sets
    assert_raise(NotBipartiteError) { BipartiteGraph.new([1, 2], [2, 3]) }
  end

  def test_rejects_edge_within_same_set
    assert_raise(NotBipartiteError) { @graph.add_edge(:ticket1, :ticket2) }
    assert_raise(NotBipartiteError) { @graph.add_edge(:agent1, :agent2) }
  end

  def test_rejects_edge_with_undeclared_vertex
    assert_raise(NotBipartiteError) { @graph.add_edge(:ticket1, :agent3) }
    assert_raise(NotBipartiteError) { @graph.add_edge(:ticket4, :agent1) }
  end

  def test_maximum_matching_pairs
    matching = @graph.maximum_matching
    assert_equal(2, matching.size)
    matching.each do |left, right|
      assert_include(%i[ticket1 ticket2 ticket3], left)
      assert_include(%i[agent1 agent2], right)
      assert(@graph.has_edge?(left, right))
    end
    assert_equal(matching.map(&:first).uniq, matching.map(&:first))
    assert_equal(matching.map(&:last).uniq, matching.map(&:last))
  end

  def test_maximum_matching_is_reproducible
    first = @graph.maximum_matching
    second = BipartiteGraph.new(%i[ticket1 ticket2 ticket3], %i[agent1 agent2])
    second.add_edge(:ticket1, :agent1)
    second.add_edge(:ticket2, :agent1)
    second.add_edge(:ticket2, :agent2)
    second.add_edge(:ticket3, :agent2)
    assert_equal(first, second.maximum_matching)
  end

  def test_maximum_matching_does_not_require_comparable_vertices
    vertices = [Object.new, Object.new, Object.new, Object.new]
    graph = BipartiteGraph.new(vertices[0, 2], vertices[2, 2])
    graph.add_edge(vertices[0], vertices[2])
    graph.add_edge(vertices[1], vertices[3])
    assert_equal(2, graph.maximum_matching.size)
    assert_empty(graph.deficient_set(:left))
  end

  def test_deficient_set_of_unmatchable_side
    deficient = @graph.deficient_set(:left)
    assert_equal(3, deficient.size)
    neighbors = deficient.flat_map { |v| @graph.each_adjacent(v).to_a }.uniq
    assert_operator(neighbors.size, :<, deficient.size)
  end

  def test_deficient_set_of_matchable_side_is_empty
    assert_empty(@graph.deficient_set(:right))
  end

  def test_deficient_set_rejects_unknown_side
    assert_raise(ArgumentError) { @graph.deficient_set(:middle) }
  end

  def test_deficient_set_with_isolated_vertex
    graph = BipartiteGraph.new(%i[a b], %i[c])
    graph.add_edge(:a, :c)
    deficient = graph.deficient_set(:left)
    assert_include(deficient, :b)
    neighbors = deficient.flat_map { |v| graph.each_adjacent(v).to_a }.uniq
    assert_operator(neighbors.size, :<, deficient.size)
  end

  def test_empty_graph
    graph = BipartiteGraph.new([], [])
    assert_empty(graph.maximum_matching)
    assert_empty(graph.deficient_set(:left))
    assert_empty(graph.deficient_set(:right))
  end

  def test_graph_interface
    assert(@graph.bipartite?)
    assert_equal(5, @graph.size)
    assert_equal(4, @graph.num_edges)
    assert_equal(%i[ticket1 ticket2 ticket3 agent1 agent2], @graph.vertices)
  end

end
