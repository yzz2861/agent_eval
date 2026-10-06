# frozen_string_literal: true

require 'test_helper'

require 'rgl/adjacency'
require 'rgl/dominators'

class TestDominators < Test::Unit::TestCase
  def setup
    @graph = RGL::DirectedAdjacencyGraph[
      :entry, :branch_a,
      :entry, :branch_b,
      :branch_a, :merge,
      :branch_b, :merge,
      :merge, :loop,
      :loop, :merge,
      :loop, :exit,
      :unreachable, :other_unreachable,
      :unreachable, :unreachable
    ]
    @analysis = @graph.dominator_analysis(:entry)
  end

  def test_immediate_dominators_for_reachable_vertices
    assert_equal(
      {
        entry: nil,
        branch_a: :entry,
        branch_b: :entry,
        merge: :entry,
        loop: :merge,
        exit: :loop
      },
      @analysis.immediate_dominators
    )
  end

  def test_only_reachable_vertices_are_included
    assert_equal(
      %i[entry branch_a branch_b merge loop exit].to_set,
      @analysis.reachable_vertices
    )
    assert_not_equal(@graph.vertices.to_set, @analysis.reachable_vertices)
    assert_nil(@analysis.immediate_dominators[:unreachable])
    assert_raises(ArgumentError) { @analysis.immediate_dominator(:unreachable) }
  end

  def test_dominance_queries_match_all_simple_paths
    strict_dominators = expected_strict_dominators(@graph, :entry, @analysis.reachable_vertices)

    @analysis.reachable_vertices.each do |vertex|
      assert_equal(strict_dominators[vertex] | [vertex], @analysis.dominators(vertex))
      assert_equal(strict_dominators[vertex], @analysis.dominators(vertex, include_self: false))

      @analysis.reachable_vertices.each do |dominator|
        expected = strict_dominators[vertex].include?(dominator)
        assert_equal(expected, @analysis.strictly_dominates?(dominator, vertex))
        assert_equal(expected || dominator == vertex,
                     @analysis.dominates?(dominator, vertex))
      end
    end

    assert_equal(:merge, @analysis.idom(:loop))
    assert(@analysis.dominates?(:merge, :exit))
    assert(!@analysis.dominates?(:branch_a, :exit))
  end

  def test_immediate_dominator_is_closest_strict_dominator
    strict_dominators = expected_strict_dominators(@graph, :entry, @analysis.reachable_vertices)

    @analysis.reachable_vertices.each do |vertex|
      next if vertex == :entry

      idom = @analysis.immediate_dominator(vertex)

      assert(strict_dominators[vertex].include?(idom))
      strict_dominators[vertex].each do |dominator|
        next if dominator == idom

        assert(@analysis.strictly_dominates?(dominator, idom))
      end
    end
  end

  def test_dominance_frontiers_match_predecessor_definition
    expected = Hash.new { |hash, key| hash[key] = Set.new }
    @analysis.reachable_vertices.each { |vertex| expected[vertex] }

    @analysis.reachable_vertices.each do |predecessor|
      @graph.each_adjacent(predecessor) do |vertex|
        next unless @analysis.reachable?(vertex)

        @analysis.reachable_vertices.each do |dominator|
          if @analysis.dominates?(dominator, predecessor) &&
             !@analysis.strictly_dominates?(dominator, vertex)
            expected[dominator] << vertex
          end
        end
      end
    end

    assert_equal(
      {
        entry: Set.new,
        branch_a: [:merge].to_set,
        branch_b: [:merge].to_set,
        merge: [:merge].to_set,
        loop: [:merge].to_set,
        exit: Set.new
      },
      @analysis.dominance_frontiers
    )
    assert_equal(expected, @analysis.dominance_frontiers)
    assert_equal([:merge].to_set, @analysis.dominance_frontier(:merge))
  end

  def test_self_loops_are_in_the_dominance_frontier
    graph = RGL::DirectedAdjacencyGraph[:entry, :entry, :entry, :body]
    analysis = graph.dominator_analysis(:entry)

    assert_nil(analysis.immediate_dominator(:entry))
    assert_equal(:entry, analysis.immediate_dominator(:body))
    assert_equal([:entry].to_set, analysis.dominance_frontier(:entry))
    assert_equal(Set.new, analysis.dominance_frontier(:body))

    graph = RGL::DirectedAdjacencyGraph[:entry, :body, :body, :body, :body, :exit]
    analysis = graph.dominator_analysis(:entry)

    assert_equal([:body].to_set, analysis.dominance_frontier(:body))
  end

  def test_back_edge_to_entry_puts_entry_in_its_own_frontier
    graph = RGL::DirectedAdjacencyGraph[
      :entry, :loop,
      :loop, :entry,
      :entry, :exit
    ]
    analysis = graph.dominator_analysis(:entry)

    assert_nil(analysis.immediate_dominator(:entry))
    assert_equal(:entry, analysis.immediate_dominator(:loop))
    assert_equal(:entry, analysis.immediate_dominator(:exit))
    assert_equal([:entry].to_set, analysis.dominance_frontier(:entry))
    assert_equal([:entry].to_set, analysis.dominance_frontier(:loop))
    assert_equal(Set.new, analysis.dominance_frontier(:exit))
  end

  def test_results_are_independent_of_insertion_order
    edges = [
      [:entry, :branch_a], [:entry, :branch_b], [:branch_a, :merge],
      [:branch_b, :merge], [:merge, :loop], [:loop, :merge], [:loop, :exit]
    ]

    first = build_graph(edges, %i[exit loop merge branch_b branch_a entry])
    second = build_graph(edges.reverse, %i[entry branch_a branch_b merge loop exit])

    first_analysis = first.dominator_analysis(:entry)
    second_analysis = second.dominator_analysis(:entry)

    assert_equal(first_analysis.immediate_dominators, second_analysis.immediate_dominators)
    assert_equal(first_analysis.dominance_frontiers, second_analysis.dominance_frontiers)
  end

  def test_analysis_does_not_modify_the_graph
    vertices = @graph.vertices.to_set
    edges = @graph.edges.to_set

    @graph.dominator_analysis(:entry)

    assert_equal(vertices, @graph.vertices.to_set)
    assert_equal(edges, @graph.edges.to_set)
  end

  def test_invalid_inputs
    assert_raises(RGL::NotDirectedError) do
      RGL::AdjacencyGraph[1, 2].dominator_analysis(1)
    end
    assert_raises(RGL::NoVertexError) { @graph.dominator_analysis(:missing) }
    assert_raises(RGL::NoVertexError) { @analysis.dominates?(:missing, :entry) }
  end

  private

  def build_graph(edges, vertex_order)
    graph = RGL::DirectedAdjacencyGraph.new
    vertex_order.each { |vertex| graph.add_vertex(vertex) }
    edges.each { |from, to| graph.add_edge(from, to) }
    graph
  end

  def expected_strict_dominators(graph, start, vertices)
    paths = simple_paths(graph, start, vertices)

    vertices.each_with_object({}) do |vertex, result|
      vertex_paths = paths[vertex]
      result[vertex] = if vertex == start
                         Set.new
                       else
                         vertex_paths.map { |path| Set.new(path - [vertex]) }.reduce(:intersection)
                       end
    end
  end

  def simple_paths(graph, start, vertices)
    paths = vertices.each_with_object({}) { |vertex, result| result[vertex] = [] }

    extend_path = lambda do |path, vertex|
      paths[vertex] << path.dup

      graph.each_adjacent(vertex) do |successor|
        next unless vertices.include?(successor)
        next if path.include?(successor)

        path << successor
        extend_path.call(path, successor)
        path.pop
      end
    end

    extend_path.call([start], start)
    paths
  end
end
