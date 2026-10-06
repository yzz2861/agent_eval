require 'test_helper'

require 'rgl/dijkstra'
require 'rgl/adjacency'

include RGL

class SimplePathTestVertex

  attr_reader :name

  def initialize(name)
    @name = name
  end

  def eql?(other)
    other.is_a?(SimplePathTestVertex) && name == other.name
  end

  alias == eql?

  def hash
    name.hash
  end

end

class TestDijkstra < Test::Unit::TestCase

  def setup
    @graph = AdjacencyGraph[1,2, 1,3, 2,3, 2,4, 3,4]

    @edge_weights = {
        [1, 2] => 10,
        [1, 3] => 1,
        [2, 3] => 1,
        [2, 4] => 1,
        [3, 4] => 10
    }

    @edge_weights_lambda = lambda { |edge| @edge_weights[edge] }
  end

  def test_shortest_path_search
    assert_equal([1, 3, 2, 4], shortest_path(1, 4))
  end

  def test_shortest_path_search_with_lambda
    assert_equal([1, 3, 2, 4], shortest_path(1, 4, @edge_weights_lambda))
  end

  def test_shortest_path_to_the_source
    assert_equal([1], shortest_path(1, 1))
  end

  def test_simple_paths_are_lazily_enumerated_by_increasing_cost
    enumerator = @graph.dijkstra_simple_paths(@edge_weights, 1, 4)

    assert_equal([1, 3, 2, 4], enumerator.next)
    assert_equal([1, 2, 4], enumerator.next)
    assert_equal([1, 3, 4], enumerator.next)
  end

  def test_simple_paths_accept_lambda_edge_weights
    assert_equal([[1, 3, 2, 4], [1, 2, 4], [1, 3, 4], [1, 2, 3, 4]],
                 @graph.dijkstra_simple_paths(@edge_weights_lambda, 1, 4).to_a)
  end

  def test_simple_paths_match_all_simple_paths_in_small_graph
    paths = @graph.dijkstra_simple_paths(@edge_weights, 1, 4).to_a

    assert_equal(all_simple_paths(@graph, 1, 4).sort, paths.sort)
    assert_equal([[1, 3, 2, 4], [1, 2, 4], [1, 3, 4], [1, 2, 3, 4]], paths)
    assert_equal([3, 11, 11, 21], paths.map { |path| path_cost(path) })
  end

  def test_simple_paths_keep_alternatives_after_a_shorter_spur_path
    graph = AdjacencyGraph.new
    [[0, 3], [0, 4], [0, 2], [1, 2], [1, 4], [2, 3], [3, 4]].each do |u, v|
      graph.add_edge(u, v)
    end
    weights = {
      [0, 2] => 1,
      [0, 3] => 2,
      [0, 4] => 0,
      [1, 2] => 2,
      [1, 4] => 0,
      [2, 3] => 1,
      [3, 4] => 1
    }

    assert_equal([[4, 0, 2], [4, 1, 2], [4, 3, 2], [4, 0, 3, 2], [4, 3, 0, 2]],
                 graph.dijkstra_simple_paths(weights, 4, 2).to_a)
  end

  def test_simple_paths_are_not_found_by_deleting_one_shortest_path_edge
    source       = SimplePathTestVertex.new('source')
    first_shared = SimplePathTestVertex.new('shared')
    shortest     = SimplePathTestVertex.new('shortest')
    alternative  = SimplePathTestVertex.new('alternative')
    target       = SimplePathTestVertex.new('target')
    other        = SimplePathTestVertex.new('other')

    graph = DirectedAdjacencyGraph[
      source, first_shared,
      first_shared, shortest,
      shortest, target,
      first_shared, alternative,
      alternative, target,
      source, other,
      other, target
    ]

    weights = {
      [source, first_shared]      => 1,
      [first_shared, shortest]   => 1,
      [shortest, target]         => 100,
      [first_shared, alternative] => 8,
      [alternative, target]       => 100,
      [source, other]             => 20,
      [other, target]             => 100
    }

    graph_without_shared_edge = graph.dup
    graph_without_shared_edge.remove_edge(source, first_shared)

    assert_equal([source, first_shared, alternative, target],
                 graph.dijkstra_simple_paths(weights, source, target).to_a[1])
    assert_equal([source, other, target],
                 graph_without_shared_edge.dijkstra_shortest_path(weights, source, target))
  end

  def test_zero_weight_equal_cost_paths_have_deterministic_traversal_order
    source      = SimplePathTestVertex.new('source')
    first       = SimplePathTestVertex.new('first')
    second      = SimplePathTestVertex.new('second')
    target      = SimplePathTestVertex.new('target')
    graph       = DirectedAdjacencyGraph[source, first, source, second, first, target, second, target]
    weights     = {
      [source, first]  => 0,
      [source, second] => 0,
      [first, target]  => 1,
      [second, target] => 1
    }

    assert_equal([[source, first, target], [source, second, target]],
                 graph.dijkstra_simple_paths(weights, source, target).to_a)
  end

  def test_zero_weight_cycles_do_not_create_repeated_vertices
    graph = DirectedAdjacencyGraph[1, 2, 2, 3, 3, 2, 3, 4, 1, 4]
    weights = Hash.new(0)
    weights[[1, 4]] = 1

    assert_equal([[1, 2, 3, 4], [1, 4]],
                 graph.dijkstra_simple_paths(weights, 1, 4).to_a)
  end

  def test_simple_paths_from_source_to_source
    assert_equal([[1]], @graph.dijkstra_simple_paths(@edge_weights, 1, 1).to_a)
  end

  def test_simple_paths_when_target_is_unreachable
    graph = DirectedAdjacencyGraph[1, 2, 3, 4]

    assert_equal([], graph.dijkstra_simple_paths(Hash.new(1), 1, 4).to_a)
  end

  def test_simple_paths_when_endpoint_is_not_in_graph
    @graph.add_vertex(5)

    assert_equal([], @graph.dijkstra_simple_paths(@edge_weights, 1, 5).to_a)
    assert_equal([], @graph.dijkstra_simple_paths(@edge_weights, 5, 1).to_a)
  end

  def test_simple_paths_when_fewer_alternatives_than_requested
    graph   = DirectedAdjacencyGraph[1, 2, 1, 3, 2, 4, 3, 4]
    weights = { [1, 2] => 1, [1, 3] => 2, [2, 4] => 1, [3, 4] => 1 }

    assert_equal([[1, 2, 4], [1, 3, 4]],
                 graph.dijkstra_simple_paths(weights, 1, 4).take(3))
  end

  def test_simple_paths_reject_negative_edge_weight
    @edge_weights[[2, 3]] = -1

    assert_raises(ArgumentError) { @graph.dijkstra_simple_paths(@edge_weights, 1, 4).to_a }
  end

  def test_path_for_unreachable_vertex
    @graph.add_vertex(5)
    assert_equal(nil, shortest_path(1, 5))
  end

  def test_shortest_paths_search
    assert_equal(
        {
            1 => [1],
            2 => [1, 3, 2],
            3 => [1, 3],
            4 => [1, 3, 2, 4]
        },
        shortest_paths(1)
    )
  end

  def test_shortest_paths_search_with_lambda
    assert_equal(
        {
            1 => [1],
            2 => [1, 3, 2],
            3 => [1, 3],
            4 => [1, 3, 2, 4]
        },
        shortest_paths(1, @edge_weights_lambda)
    )
  end

  def test_shortest_paths_search_with_unreachable_vertex
    @graph.add_vertex(5)

    assert_equal(
        {
            1 => [1],
            2 => [1, 3, 2],
            3 => [1, 3],
            4 => [1, 3, 2, 4],
            5 => nil
        },
        shortest_paths(1)
    )
  end

  def test_visitor
    visitor = DijkstraVisitor.new(@graph)

    events = []

    %w[examine_vertex examine_edge edge_relaxed edge_not_relaxed finish_vertex].each do |event|
      visitor.send("set_#{event}_event_handler") { |*args| events << { event.to_sym => args } }
    end

    @graph.dijkstra_shortest_paths(@edge_weights, 1, visitor)

    assert_equal(
        [
            { :examine_vertex => [1] },
            { :examine_edge   => [1, 2] },
            { :edge_relaxed   => [1, 2] },
            { :examine_edge   => [1, 3] },
            { :edge_relaxed   => [1, 3] },
            { :finish_vertex  => [1] },
            { :examine_vertex => [3] },
            { :examine_edge   => [3, 2] },
            { :edge_relaxed   => [3, 2] },
            { :examine_edge   => [3, 4] },
            { :edge_relaxed   => [3, 4] },
            { :finish_vertex  => [3] },
            { :examine_vertex => [2] },
            { :examine_edge   => [2, 4] },
            { :edge_relaxed   => [2, 4] },
            { :finish_vertex  => [2] },
            { :examine_vertex => [4] },
            { :finish_vertex  => [4] },
        ],
        events
    )
  end

  def test_negative_edge_weight
    @edge_weights[[2, 3]] = -7
    assert_raises(ArgumentError, 'weight of edge (2, 3) is negative') { shortest_path(1, 5) }
  end

  def test_negative_edge_weight_with_lambda
    @edge_weights[[2, 3]] = -7
    assert_raises(ArgumentError, 'weight of edge (2, 3) is negative') { shortest_path(1, 5, @edge_weights_lambda) }
  end

  def test_missing_edge_weight
    @edge_weights.delete([2, 3])
    assert_raises(ArgumentError, 'weight of edge (2, 3) is not defined') { shortest_path(1, 5) }
  end

  def test_edge_weights_map_object_in_argument
    weights_map = EdgePropertiesMap.new(@edge_weights, @graph.directed?)
    dijkstra    = DijkstraAlgorithm.new(@graph, weights_map, DijkstraVisitor.new(@graph))

    assert_equal([1, 3, 2, 4], dijkstra.shortest_path(1, 4))
  end

  private

  def shortest_path(source, target, edge_weights = @edge_weights)
    @graph.dijkstra_shortest_path(edge_weights, source, target)
  end

  def shortest_paths(source, edge_weights = @edge_weights)
    @graph.dijkstra_shortest_paths(edge_weights, source)
  end

  def all_simple_paths(graph, source, target, path = [source])
    return [path] if source == target

    graph.adjacent_vertices(source).flat_map do |neighbor|
      next [] if path.include?(neighbor)

      all_simple_paths(graph, neighbor, target, path + [neighbor])
    end
  end

  def path_cost(path)
    path.each_cons(2).sum(0) { |u, v| @edge_weights[[u, v]] || @edge_weights[[v, u]] }
  end

end
