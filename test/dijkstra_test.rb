require 'test_helper'

require 'rgl/dijkstra'
require 'rgl/adjacency'

include RGL

class TestDijkstra < Test::Unit::TestCase

  def setup
    @graph = AdjacencyGraph[1,2, 1,3, 2,3, 2,4, 3,4]

    @edge_weights = {
        [1, 2] => 10,
        [1, 3] => 1,
        [2, 3] => 1,
        [2, 4] => 1,
        [3, 4] => 5
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

  def test_each_shortest_path_returns_all_simple_paths_in_cost_order
    all_simple_paths = simple_paths(@graph, 1, 4)

    expected = [
        [1, 3, 2, 4],
        [1, 3, 4],
        [1, 2, 4],
        [1, 2, 3, 4]
    ]

    paths = @graph.each_dijkstra_shortest_path(@edge_weights, 1, 4).to_a

    assert_equal(expected, paths)
    assert_equal(expected.sort, all_simple_paths.sort)
    assert_equal(expected.map { |path| path_cost(path) }.sort, paths.map { |path| path_cost(path) })

    graph_without_first_shortest_edge = @graph.dup
    graph_without_first_shortest_edge.remove_edge(1, 3)
    path_after_deleting_first_edge =
        graph_without_first_shortest_edge.dijkstra_shortest_path(@edge_weights, 1, 4)

    assert_equal([1, 2, 4], path_after_deleting_first_edge)
    refute_equal(path_after_deleting_first_edge, paths[1])
    assert_operator(path_cost(paths[1]), :<, path_cost(path_after_deleting_first_edge))
  end

  def test_each_shortest_path_can_stop_after_requested_alternatives
    enumerator = @graph.each_dijkstra_shortest_path(@edge_weights, 1, 4)

    assert_equal(
        [
            [1, 3, 2, 4],
            [1, 3, 4],
            [1, 2, 4]
        ],
        enumerator.first(3)
    )
  end

  def test_each_shortest_path_with_lambda_weights
    paths = @graph
              .each_dijkstra_shortest_path(@edge_weights_lambda, 1, 4)
              .first(2)

    assert_equal(
        [
            [1, 3, 2, 4],
            [1, 3, 4]
        ],
        paths
    )
  end

  def test_each_shortest_path_accepts_a_block
    paths = []

    @graph.each_dijkstra_shortest_path(@edge_weights, 1, 4) do |path|
      paths << path
    end

    assert_equal([1, 3, 2, 4], paths.first)
    assert_equal(4, paths.size)
  end

  def test_each_shortest_path_for_equal_source_and_target
    paths = @graph.each_dijkstra_shortest_path(@edge_weights, 1, 1).to_a

    assert_equal([[1]], paths)
  end

  def test_each_shortest_path_without_a_route
    @graph.add_vertex(5)

    assert_equal([], @graph.each_dijkstra_shortest_path(@edge_weights, 1, 5).to_a)
  end

  def test_each_shortest_path_when_fewer_alternatives_are_requested
    paths = @graph.each_dijkstra_shortest_path(@edge_weights, 1, 4).first(10)

    assert_equal(4, paths.size)
  end

  def test_each_shortest_path_has_deterministic_order_for_zero_weight_ties
    vertex_class = Class.new do

      attr_reader :name

      def initialize(name)
        @name = name
      end

      def ==(other)
        other.is_a?(self.class) && name == other.name
      end

      alias eql? ==

      def hash
        name.hash
      end

    end

    source = vertex_class.new(:source)
    first  = vertex_class.new(:first)
    second = vertex_class.new(:second)
    target = vertex_class.new(:target)
    graph  = DirectedAdjacencyGraph.new
    graph.add_edges(
        [source, first],
        [source, second],
        [first, target],
        [second, target]
    )

    weights = {
        [source, first]  => 0,
        [source, second] => 0,
        [first, target]  => 0,
        [second, target] => 0
    }

    assert_equal(
        [
            [source, first, target],
            [source, second, target]
        ],
        graph.each_dijkstra_shortest_path(weights, source, target).to_a
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

  def path_cost(path)
    path.each_cons(2).sum(0) { |u, v| @edge_weights[[u, v]] || @edge_weights[[v, u]] }
  end

  def simple_paths(graph, source, target)
    search = lambda do |vertex, path, visited|
      return [path] if vertex == target

      graph.adjacent_vertices(vertex).each_with_object([]) do |neighbor, paths|
        next if visited.include?(neighbor)

        visited[neighbor] = true
        paths.concat(search.call(neighbor, path + [neighbor], visited))
        visited.delete(neighbor)
      end
    end

    search.call(source, [source], { source => true })
  end

end
