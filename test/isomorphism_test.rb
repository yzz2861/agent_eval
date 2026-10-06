require 'test_helper'

require 'rgl/isomorphism'
require 'rgl/adjacency'

include RGL

class TestIsomorphism < Test::Unit::TestCase

  def test_isomorphic_directed_graphs_with_different_ids
    g1 = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 1]
    g2 = DirectedAdjacencyGraph['x', 'y', 'y', 'z', 'z', 'x']

    mapping = g1.isomorphism_mapping(g2)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping)
    assert(g1.isomorphic?(g2))
  end

  def test_isomorphic_undirected_graphs_with_different_ids
    g1 = AdjacencyGraph[1, 2, 2, 3, 3, 4, 4, 1]
    g2 = AdjacencyGraph[:a, :b, :b, :c, :c, :d, :d, :a]

    mapping = g1.isomorphism_mapping(g2)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping)
  end

  def test_not_isomorphic_when_direction_differs
    g1 = DirectedAdjacencyGraph[1, 2, 2, 3]
    g2 = AdjacencyGraph[1, 2, 2, 3]

    assert_nil(g1.isomorphism_mapping(g2))
    assert(!g1.isomorphic?(g2))
  end

  def test_not_isomorphic_when_vertex_count_differs
    g1 = AdjacencyGraph[1, 2, 2, 3]
    g2 = AdjacencyGraph[1, 2]

    assert_nil(g1.isomorphism_mapping(g2))
  end

  # Two 8-vertex 2-regular graphs: a single 8-cycle and the disjoint union
  # of a 3-cycle and a 5-cycle. The degree sequences are identical
  # ([2] * 8), but the graphs are not isomorphic.
  def test_same_degree_sequence_but_not_isomorphic
    cycle8 = AdjacencyGraph[1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 1]
    two_cycles = AdjacencyGraph[1, 2, 2, 3, 3, 1, 4, 5, 5, 6, 6, 7, 7, 8, 8, 4]

    assert_equal(cycle8.vertices.map { |v| cycle8.out_degree(v) }.sort,
                 two_cycles.vertices.map { |v| two_cycles.out_degree(v) }.sort)
    assert_nil(cycle8.isomorphism_mapping(two_cycles))
    assert(!cycle8.isomorphic?(two_cycles))
  end

  def test_vertex_labels_restrict_mapping
    g1 = AdjacencyGraph[1, 2, 2, 3]
    g2 = AdjacencyGraph[:a, :b, :b, :c]

    labels1 = { 1 => 'leaf', 2 => 'inner', 3 => 'leaf' }
    labels2 = { a: 'leaf', b: 'inner', c: 'root' }
    vertex_label = [->(v) { labels1[v] }, ->(v) { labels2[v] }]

    assert_nil(g1.isomorphism_mapping(g2, vertex_label: vertex_label))

    labels2[:c] = 'leaf'
    mapping = g1.isomorphism_mapping(g2, vertex_label: vertex_label)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping, vertex_label: vertex_label)
  end

  def test_single_vertex_label_callable_applies_to_both_graphs
    g1 = DirectedAdjacencyGraph[1, 2]
    g2 = DirectedAdjacencyGraph[10, 20]
    vertex_label = ->(v) { v.to_s.length }

    assert_nil(g1.isomorphism_mapping(g2, vertex_label: vertex_label))

    g2 = DirectedAdjacencyGraph[7, 9]
    mapping = g1.isomorphism_mapping(g2, vertex_label: vertex_label)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping, vertex_label: vertex_label)
  end

  def test_edge_labels_restrict_mapping
    g1 = DirectedAdjacencyGraph[1, 2, 2, 3]
    g2 = DirectedAdjacencyGraph[:a, :b, :b, :c]

    edge_labels1 = { [1, 2] => 'depends', [2, 3] => 'depends' }
    edge_labels2 = { [:a, :b] => 'depends', [:b, :c] => 'imports' }
    edge_label = [->(u, v) { edge_labels1[[u, v]] }, ->(u, v) { edge_labels2[[u, v]] }]

    assert_nil(g1.isomorphism_mapping(g2, edge_label: edge_label))

    edge_labels2[[:b, :c]] = 'depends'
    mapping = g1.isomorphism_mapping(g2, edge_label: edge_label)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping, edge_label: edge_label)
  end

  def test_self_loops
    g1 = DirectedAdjacencyGraph[1, 1, 1, 2]
    g2 = DirectedAdjacencyGraph[:a, :a, :a, :b]

    mapping = g1.isomorphism_mapping(g2)

    assert_not_nil(mapping)
    assert_equal(:a, mapping[1])
    assert_valid_isomorphism(g1, g2, mapping)

    # Loop on the other endpoint is a different structure.
    g3 = DirectedAdjacencyGraph[:a, :b, :b, :b]

    assert_nil(g1.isomorphism_mapping(g3))
  end

  def test_undirected_self_loops
    g1 = AdjacencyGraph[1, 1, 1, 2]
    g2 = AdjacencyGraph[:x, :x, :x, :y]

    mapping = g1.isomorphism_mapping(g2)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping)
  end

  # Parallel edges are supported and matched by multiplicity.
  def test_parallel_edges_matched_by_multiplicity
    g1 = DirectedAdjacencyGraph.new(Array)
    g1.add_edge(1, 2)
    g1.add_edge(1, 2)
    g1.add_edge(2, 3)

    g2 = DirectedAdjacencyGraph.new(Array)
    g2.add_edge(:a, :b)
    g2.add_edge(:a, :b)
    g2.add_edge(:b, :c)

    mapping = g1.isomorphism_mapping(g2)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping)

    # Same degree sequence, but the parallel edges sit between different
    # vertex pairs.
    g3 = DirectedAdjacencyGraph.new(Array)
    g3.add_edge(:a, :b)
    g3.add_edge(:b, :c)
    g3.add_edge(:b, :c)

    assert_nil(g1.isomorphism_mapping(g3))
  end

  # The path on three vertices has two automorphisms, so both mappings into
  # the isomorphic path are legal. Whichever is returned must be verified
  # edge by edge.
  def test_multiple_valid_mappings
    g1 = AdjacencyGraph[1, 2, 2, 3]
    g2 = AdjacencyGraph[:a, :b, :b, :c]

    valid_mappings = [
      { 1 => :a, 2 => :b, 3 => :c },
      { 1 => :c, 2 => :b, 3 => :a }
    ]

    mapping = g1.isomorphism_mapping(g2)

    assert_not_nil(mapping)
    assert_include(valid_mappings, mapping)
    assert_valid_isomorphism(g1, g2, mapping)
  end

  def test_empty_graphs_are_isomorphic
    g1 = DirectedAdjacencyGraph.new
    g2 = DirectedAdjacencyGraph.new

    assert_equal({}, g1.isomorphism_mapping(g2))
    assert(g1.isomorphic?(g2))
  end

  def test_isolated_vertices
    g1 = AdjacencyGraph.new
    g1.add_vertex(1)
    g1.add_vertex(2)
    g2 = AdjacencyGraph[:a, :b]

    assert_nil(g1.isomorphism_mapping(g2))

    g2 = AdjacencyGraph.new
    g2.add_vertex(:a)
    g2.add_vertex(:b)

    mapping = g1.isomorphism_mapping(g2)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping)
  end

  # Exhausting the search limit must not be reported as "not isomorphic".
  def test_max_states_exceeded_raises
    cycle8 = AdjacencyGraph[1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 1]
    two_cycles = AdjacencyGraph[1, 2, 2, 3, 3, 1, 4, 5, 5, 6, 6, 7, 7, 8, 8, 4]

    assert_raise(IsomorphismSearchLimitExceeded) do
      cycle8.isomorphism_mapping(two_cycles, max_states: 1)
    end
    assert_raise(IsomorphismSearchLimitExceeded) do
      cycle8.isomorphic?(two_cycles, max_states: 1)
    end
  end

  def test_max_states_sufficient_for_success
    g1 = AdjacencyGraph[1, 2, 2, 3, 3, 4, 4, 1]
    g2 = AdjacencyGraph[:a, :b, :b, :c, :c, :d, :d, :a]

    mapping = g1.isomorphism_mapping(g2, max_states: 100)

    assert_not_nil(mapping)
    assert_valid_isomorphism(g1, g2, mapping)
  end

  def test_invalid_max_states
    g1 = AdjacencyGraph[1, 2]
    g2 = AdjacencyGraph[:a, :b]

    assert_raise(ArgumentError) { g1.isomorphism_mapping(g2, max_states: -1) }
    assert_raise(ArgumentError) { g1.isomorphism_mapping(g2, max_states: 1.5) }
  end

  private

  # Verifies a returned mapping edge by edge: it must be a bijection between
  # the vertex sets that preserves edge multiplicities (and labels, when
  # label callables are given) in both directions.
  def assert_valid_isomorphism(g1, g2, mapping, vertex_label: nil, edge_label: nil)
    assert_equal(g1.num_vertices, mapping.size)
    g1.each_vertex { |v| assert(mapping.key?(v), "no image for vertex #{v.inspect}") }
    assert_equal(mapping.values.uniq.size, mapping.values.size, 'mapping is not injective')
    g2.each_vertex { |v| assert(mapping.value?(v), "vertex #{v.inspect} not covered") }

    counts1 = adjacency_counts(g1)
    counts2 = adjacency_counts(g2)
    g1.each_vertex do |u|
      g1.each_vertex do |v|
        assert_equal(counts1[[u, v]], counts2[[mapping[u], mapping[v]]],
                     "edge multiplicity mismatch for (#{u.inspect}, #{v.inspect})")
      end
    end

    if vertex_label
      label1, label2 = normalize_labeler(vertex_label)
      g1.each_vertex do |v|
        assert_equal(label1.call(v), label2.call(mapping[v]), "vertex label mismatch for #{v.inspect}")
      end
    end

    if edge_label
      label1, label2 = normalize_labeler(edge_label)
      g1.each_edge do |u, v|
        assert_equal(label1.call(u, v), label2.call(mapping[u], mapping[v]),
                     "edge label mismatch for (#{u.inspect}, #{v.inspect})")
      end
    end
  end

  def adjacency_counts(graph)
    counts = Hash.new(0)
    graph.each_vertex do |u|
      graph.each_adjacent(u) { |v| counts[[u, v]] += 1 }
    end
    counts
  end

  def normalize_labeler(labeler)
    labeler.is_a?(Array) ? labeler : [labeler, labeler]
  end

end
