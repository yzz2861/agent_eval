require 'test_helper'

require 'rgl/adjacency'
require 'rgl/isomorphism'

include RGL

class TestIsomorphism < Test::Unit::TestCase

  def test_finds_directed_graph_isomorphism
    graph1 = DirectedAdjacencyGraph[:a, :b, :b, :c, :b, :d, :d, :d]
    graph2 = DirectedAdjacencyGraph['x', 'y', 'y', 'z', 'y', 'q', 'q', 'q']

    result = graph1.find_isomorphism(graph2)

    assert(result.isomorphic?)
    assert_equal(4, result.mapping.size)
    assert_valid_isomorphism(graph1, graph2, result.mapping)
  end

  def test_finds_undirected_graph_isomorphism_without_using_ids
    graph1 = AdjacencyGraph[:a, :b, :b, :c, :c, :d, :c, :e]
    graph2 = AdjacencyGraph[10, 20, 20, 30, 30, 40, 30, 50]

    result = RGL::Isomorphism.find(graph1, graph2)

    assert(result.isomorphic?)
    assert_equal(Set.new(graph1.vertices), Set.new(result.mapping.keys))
    assert_equal(Set.new(graph2.vertices), Set.new(result.mapping.values))
    assert_valid_isomorphism(graph1, graph2, result.mapping)
  end

  def test_uses_node_and_edge_label_readers
    node_labels = {
      person: :person, home: :place, work: :place, car: :vehicle,
      alice: :person, house: :place, office: :place, truck: :vehicle
    }
    edge_labels = {
      %i[home person].sort => :lives,
      %i[person work].sort => :works,
      %i[car person].sort => :owns,
      %i[alice house].sort => :lives,
      %i[alice office].sort => :works,
      %i[alice truck].sort => :owns
    }
    graph1 = AdjacencyGraph[:person, :home, :person, :work, :person, :car]
    graph2 = AdjacencyGraph[:alice, :house, :alice, :office, :alice, :truck]

    result = graph1.find_isomorphism(
      graph2,
      node_label: ->(_graph, vertex) { node_labels[vertex] },
      edge_label: ->(source, target) { edge_labels[[source, target].sort] }
    )

    assert(result.isomorphic?)
    assert_valid_isomorphism(
      graph1,
      graph2,
      result.mapping,
      node_label: ->(vertex) { node_labels[vertex] },
      edge_label: ->(source, target) { edge_labels[[source, target].sort] }
    )
  end

  def test_node_labels_can_prevent_an_isomorphism
    graph1 = AdjacencyGraph[:a, :b, :b, :c]
    graph2 = AdjacencyGraph[:x, :y, :y, :z]
    labels1 = { a: :red, b: :green, c: :blue }
    labels2 = { x: :red, y: :green, z: :blue }
    incompatible_labels2 = { x: :green, y: :red, z: :blue }

    result = graph1.find_isomorphism(
      graph2,
      node_label: ->(_graph, vertex) { labels1.fetch(vertex) { labels2.fetch(vertex) } }
    )
    assert(result.isomorphic?)

    result = graph1.find_isomorphism(
      graph2,
      node_label: ->(graph, vertex) do
        graph.equal?(graph1) ? labels1[vertex] : incompatible_labels2[vertex]
      end
    )
    assert(result.not_isomorphic?)
  end

  def test_edge_labels_can_prevent_an_isomorphism
    graph1 = AdjacencyGraph[:a, :b, :b, :c]
    graph2 = AdjacencyGraph[:x, :y, :y, :z]
    labels1 = { %i[a b] => :road, %i[b c] => :path }
    labels2 = { %i[x y] => :road, %i[y z] => :road }

    result = graph1.find_isomorphism(
      graph2,
      edge_label: lambda do |source, target|
        labels1[[source, target].sort] || labels2[[source, target].sort]
      end
    )

    assert(result.not_isomorphic?)
  end

  def test_supports_self_loops
    directed1 = DirectedAdjacencyGraph[:a, :a, :a, :b]
    directed2 = DirectedAdjacencyGraph[:x, :x, :x, :y]
    result = directed1.find_isomorphism(directed2)

    assert(result.isomorphic?)
    assert_valid_isomorphism(directed1, directed2, result.mapping)

    undirected1 = AdjacencyGraph[:a, :a, :a, :b]
    undirected2 = AdjacencyGraph[:x, :x, :x, :y]
    result = undirected1.find_isomorphism(undirected2)

    assert(result.isomorphic?)
    assert_valid_isomorphism(undirected1, undirected2, result.mapping)

    parallel_directed1 = DirectedAdjacencyGraph.new(Array)
    parallel_directed1.add_edge(:a, :a)
    parallel_directed1.add_edge(:a, :a)
    parallel_directed1.add_vertex(:b)
    parallel_directed2 = DirectedAdjacencyGraph.new(Array)
    parallel_directed2.add_edge(:x, :x)
    parallel_directed2.add_edge(:x, :x)
    parallel_directed2.add_vertex(:y)
    result = parallel_directed1.find_isomorphism(parallel_directed2)
    assert(result.isomorphic?)
    assert_valid_isomorphism(parallel_directed1, parallel_directed2, result.mapping)

    parallel_undirected1 = AdjacencyGraph.new(Array)
    parallel_undirected1.add_edge(:a, :a)
    parallel_undirected1.add_edge(:a, :a)
    parallel_undirected1.add_vertex(:b)
    parallel_undirected2 = AdjacencyGraph.new(Array)
    parallel_undirected2.add_edge(:x, :x)
    parallel_undirected2.add_edge(:x, :x)
    parallel_undirected2.add_vertex(:y)
    result = parallel_undirected1.find_isomorphism(parallel_undirected2)
    assert(result.isomorphic?)
    assert_valid_isomorphism(parallel_undirected1, parallel_undirected2, result.mapping)
  end

  def test_supports_parallel_edges_and_compares_their_multiplicity
    directed1 = DirectedAdjacencyGraph.new(Array)
    directed1.add_edge(:a, :b)
    directed1.add_edge(:a, :b)
    directed2 = DirectedAdjacencyGraph.new(Array)
    directed2.add_edge(:x, :y)
    directed2.add_edge(:x, :y)

    result = directed1.find_isomorphism(directed2)
    assert(result.isomorphic?)
    assert_valid_isomorphism(directed1, directed2, result.mapping)

    directed2.remove_edge(:x, :y)
    directed2.remove_edge(:x, :y)
    result = directed1.find_isomorphism(directed2)
    assert(result.not_isomorphic?)

    undirected1 = AdjacencyGraph.new(Array)
    undirected1.add_edge(:a, :b)
    undirected1.add_edge(:a, :b)
    undirected2 = AdjacencyGraph.new(Array)
    undirected2.add_edge(:x, :y)
    undirected2.add_edge(:x, :y)

    result = undirected1.find_isomorphism(undirected2)
    assert(result.isomorphic?)
    assert_valid_isomorphism(undirected1, undirected2, result.mapping)

    undirected2.remove_edge(:x, :y)
    undirected2.remove_edge(:x, :y)
    result = undirected1.find_isomorphism(undirected2)
    assert(result.not_isomorphic?)
  end

  def test_distinguishes_graphs_with_identical_degree_sequences
    adjacent_centers = AdjacencyGraph[
      :a, :d, :a, :u, :u, :a1, :a, :a2,
      :d, :v, :v, :d1, :d, :d2
    ]
    separated_centers = AdjacencyGraph[
      :a, :u, :u, :v, :v, :d,
      :a, :a1, :a, :a2, :d, :d1, :d, :d2
    ]

    assert_equal(degree_sequence(adjacent_centers), degree_sequence(separated_centers))
    result = adjacent_centers.find_isomorphism(separated_centers)

    assert(result.not_isomorphic?)
  end

  def test_accepts_every_legal_mapping_for_a_symmetric_graph
    graph1 = AdjacencyGraph[:center, :left, :center, :right]
    graph2 = AdjacencyGraph[:hub, :one, :hub, :two]
    result = graph1.find_isomorphism(graph2)

    assert(result.isomorphic?)
    assert_valid_isomorphism(graph1, graph2, result.mapping)

    alternative_mapping = { center: :hub, left: :two, right: :one }
    assert_valid_isomorphism(graph1, graph2, alternative_mapping)
    assert_include(
      [
        { center: :hub, left: :one, right: :two },
        alternative_mapping
      ],
      result.mapping
    )
  end

  def test_search_limit_is_not_reported_as_non_isomorphic
    leaves = (1..12).map { |index| [:"leaf#{index}", :"other#{index}"] }
    graph = AdjacencyGraph[*leaves.flat_map { |leaf, _other| [:center, leaf] }]
    other = AdjacencyGraph[*leaves.flat_map { |_leaf, mapped| [:hub, mapped] }]

    unlimited = graph.find_isomorphism(other)
    assert(unlimited.isomorphic?)
    assert_valid_isomorphism(graph, other, unlimited.mapping)

    limited = graph.find_isomorphism(other, search_limit: 5)
    assert(limited.limit_reached?)
    assert(!limited.isomorphic?)
    assert(!limited.not_isomorphic?)
    assert_nil(limited.mapping)
  end

  def test_search_limit_does_not_replace_a_provable_negative
    graph1 = AdjacencyGraph[:a, :b, :b, :c]
    graph2 = AdjacencyGraph[:x, :y]

    result = graph1.find_isomorphism(graph2, search_limit: 0)

    assert(result.not_isomorphic?)
    assert(!result.limit_reached?)
  end

  def test_empty_graphs_are_isomorphic
    result = AdjacencyGraph.new.find_isomorphism(AdjacencyGraph.new)

    assert(result.isomorphic?)
    assert_equal({}, result.mapping)
  end

  def test_directedness_and_arc_direction_matter
    directed = DirectedAdjacencyGraph[:a, :b, :b, :c]
    undirected = AdjacencyGraph[:x, :y, :y, :z]
    assert(directed.find_isomorphism(undirected).not_isomorphic?)

    forward = DirectedAdjacencyGraph[:a, :b, :b, :c]
    reverse_arcs = DirectedAdjacencyGraph[:x, :y, :z, :y]
    assert(forward.find_isomorphism(reverse_arcs).not_isomorphic?)
  end

  def test_validates_arguments
    graph = AdjacencyGraph[:a, :b]
    assert_raise(ArgumentError) { graph.find_isomorphism(graph, node_label: :not_callable) }
    assert_raise(ArgumentError) { graph.find_isomorphism(graph, edge_label: :not_callable) }
    assert_raise(ArgumentError) { graph.find_isomorphism(graph, search_limit: -1) }
  end

  private

  def degree_sequence(graph)
    graph.vertices.map { |vertex| graph.adjacent_vertices(vertex).size }.sort
  end

  def assert_valid_isomorphism(graph1, graph2, mapping, node_label: nil, edge_label: nil)
    assert_equal(Set.new(graph1.vertices), Set.new(mapping.keys))
    assert_equal(Set.new(graph2.vertices), Set.new(mapping.values))
    assert_equal(mapping.values.uniq.size, mapping.size)

    graph1.vertices.each do |vertex|
      mapped_vertex = mapping[vertex]
      if node_label
        assert_equal(node_label.call(vertex), node_label.call(mapped_vertex))
      end
    end

    expected_incidences = incidence_counts(graph1).each_with_object(Hash.new(0)) do |((source, target), count), counts|
      mapped_pair = [mapping[source], mapping[target]]
      counts[mapped_pair] += count
      if edge_label
        count.times do
          assert_equal(
            edge_label.call(source, target),
            edge_label.call(*mapped_pair)
          )
        end
      end
    end

    assert_equal(incidence_counts(graph2), expected_incidences)
  end

  def incidence_counts(graph)
    counts = Hash.new(0)
    graph.each_vertex do |source|
      graph.each_adjacent(source) do |target|
        counts[[source, target]] += 1
      end
    end
    counts
  end
end
