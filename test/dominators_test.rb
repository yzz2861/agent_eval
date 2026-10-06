require 'test_helper'

require 'rgl/dominators'
require 'rgl/adjacency'

include RGL

class TestDominators < Test::Unit::TestCase

  def setup
    @graph = DirectedAdjacencyGraph.new
    edges = [
      [:a, :b], [:a, :c], [:b, :d], [:c, :d],
      [:d, :e], [:e, :d], [:e, :b], [:b, :b]
    ]
    edges.each { |from, to| @graph.add_edge(from, to) }
    @graph.add_vertex(:unreachable)

    @analysis = @graph.dominator_analysis(:a)
  end

  def test_immediate_dominators_for_branch_merge_with_back_edges
    assert_equal(
      {
        a: nil,
        b: :a,
        c: :a,
        d: :a,
        e: :d
      },
      @analysis.idoms
    )

    assert_nil(@analysis.idom(:a))
    assert_equal(:d, @analysis.idom(:e))
  end

  def test_dominance_queries_match_all_simple_paths
    assert(@analysis.dominates?(:a, :e))
    assert(@analysis.dominates?(:d, :e))
    assert(@analysis.dominates?(:b, :b))
    refute(@analysis.dominates?(:b, :d))
    refute(@analysis.dominates?(:c, :e))
    refute(@analysis.dominates?(:e, :d))
    refute(@analysis.dominates?(:unreachable, :b))
    refute(@analysis.dominates?(:b, :unreachable))

    assert_equal([:d, :a], @analysis.dominators(:e))
    assert_equal([], @analysis.dominators(:a))

    reachable = @analysis.reachable_vertices
    expected_idoms = {}
    reachable.each do |vertex|
      expected_dominators = reachable.select do |candidate|
        all_simple_paths_include?(@graph, :a, vertex, candidate)
      end - [vertex]
      expected_idom = expected_dominators.find do |candidate|
        expected_dominators.reject { |other| other == candidate }.all? do |other|
          all_simple_paths_include?(@graph, :a, candidate, other)
        end
      end
      expected_idoms[vertex] = expected_idom

      expected_dominators.each do |dominator|
        assert(@analysis.dominates?(dominator, vertex))
      end
      (reachable - expected_dominators - [vertex]).each do |non_dominator|
        refute(@analysis.dominates?(non_dominator, vertex))
      end
    end

    assert_equal(expected_idoms, @analysis.idoms)
  end

  def test_dominance_frontiers_for_back_edges_and_loops
    assert_equal(oracle_dominance_frontiers, @analysis.dominance_frontiers)

    assert_equal(Set[:b, :d], @analysis.dominance_frontier(:b))
    assert_equal(Set[:d], @analysis.dominance_frontier(:c))
    assert_equal(Set[:b, :d], @analysis.dominance_frontier(:d))
    assert_equal(Set[:b, :d], @analysis.dominance_frontier(:e))
    assert_equal(Set[], @analysis.dominance_frontier(:a))
  end

  def test_entry_self_loop_is_in_entry_dominance_frontier
    graph = DirectedAdjacencyGraph.new
    graph.add_edge(:a, :a)
    graph.add_edge(:a, :b)
    graph.add_edge(:b, :a)

    analysis = graph.dominator_analysis(:a)

    assert_nil(analysis.idom(:a))
    assert_equal(:a, analysis.idom(:b))
    assert_equal(Set[:a], analysis.dominance_frontier(:a))
    assert_equal(Set[:a], analysis.dominance_frontier(:b))
  end

  def test_back_edge_to_entry_is_in_entry_dominance_frontier
    graph = DirectedAdjacencyGraph[:a, :b, :b, :c, :c, :a]
    analysis = graph.dominator_analysis(:a)

    assert_equal(Set[:a], analysis.dominance_frontier(:a))
    assert_equal(Set[:a], analysis.dominance_frontier(:b))
    assert_equal(Set[:a], analysis.dominance_frontier(:c))
  end

  def test_unreachable_vertices_are_not_attached_to_entry
    refute(@analysis.reachable?(:unreachable))
    refute(@analysis.idoms.key?(:unreachable))
    assert_equal(Set[:a, :b, :c, :d, :e], @analysis.reachable_vertices)

    assert_raises(ArgumentError) { @analysis.idom(:unreachable) }
    assert_raises(ArgumentError) { @analysis.dominators(:unreachable) }
    assert_raises(ArgumentError) { @analysis.dominance_frontier(:unreachable) }
  end

  def test_missing_and_invalid_entry_vertices
    assert_raises(NoVertexError) { @graph.dominator_analysis(:missing) }
    assert_raises(NotDirectedError) { AdjacencyGraph[:a, :b].dominator_analysis(:a) }
  end

  def test_dominator_tree_contains_only_reachable_vertices
    tree = @analysis.dominator_tree

    assert_equal(Set[:a, :b, :c, :d, :e], tree.vertices.to_set)
    assert_equal(
      [
        [:a, :b], [:a, :c], [:a, :d], [:d, :e]
      ].map { |edge| RGL::Edge::DirectedEdge.new(*edge) }.to_set,
      tree.edges.to_set
    )
  end

  def test_result_is_independent_of_vertex_and_edge_insertion_order
    reordered = DirectedAdjacencyGraph.new(Array)
    [
      [:e, :b], [:e, :d], [:d, :e], [:c, :d], [:b, :b],
      [:b, :d], [:a, :c], [:a, :b]
    ].each { |from, to| reordered.add_edge(from, to) }
    reordered.add_vertex(:unreachable)

    analysis = reordered.dominator_analysis(:a)

    assert_equal(@analysis.idoms, analysis.idoms)
    assert_equal(@analysis.dominance_frontiers, analysis.dominance_frontiers)
  end

  def test_analysis_does_not_modify_graph
    vertices = @graph.vertices
    edges = @graph.edges

    @graph.dominator_analysis(:a)

    assert_equal(vertices, @graph.vertices)
    assert_equal(edges, @graph.edges)
  end

  def test_nil_can_be_an_entry_vertex
    graph = DirectedAdjacencyGraph[nil, :b, :b, nil]
    analysis = graph.dominator_analysis(nil)

    assert_nil(analysis.idom(nil))
    assert_nil(analysis.idom(:b))
    assert_equal([nil], analysis.dominators(:b))
    assert(analysis.dominates?(nil, :b))
  end

  private

  def all_simple_paths_include?(graph, source, target, vertex)
    paths = simple_paths(graph, source, target)
    raise "expected at least one path to #{target}" if paths.empty?

    paths.all? { |path| path.include?(vertex) }
  end

  def oracle_dominance_frontiers
    vertices = @analysis.reachable_vertices
    frontiers = vertices.to_h { |vertex| [vertex, Set.new] }

    vertices.each do |target|
      predecessors = Set.new
      vertices.each do |source|
        @graph.each_adjacent(source) do |neighbor|
          predecessors.add(source) if neighbor == target
        end
      end

      predecessors.each do |predecessor|
        vertices.each do |dominator|
          dominates_predecessor =
            all_simple_paths_include?(@graph, :a, predecessor, dominator)
          strictly_dominates_target =
            dominator != target &&
              all_simple_paths_include?(@graph, :a, target, dominator)

          frontiers[dominator].add(target) if
            dominates_predecessor && !strictly_dominates_target
        end
      end
    end

    frontiers
  end

  def simple_paths(graph, source, target, path = [source])
    return [path] if source == target

    graph.adjacent_vertices(source).each_with_object([]) do |neighbor, paths|
      next if path.include?(neighbor)

      paths.concat(simple_paths(graph, neighbor, target, path + [neighbor]))
    end
  end

end
