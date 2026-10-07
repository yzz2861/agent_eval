# frozen_string_literal: true

require_relative 'test_helper'

class JSONJSONPathTest < Test::Unit::TestCase
  STORE = JSON.parse(<<~JSON)
    {
      "store": {
        "book": [
          { "category": "reference", "author": "Nigel Rees", "title": "Sayings of the Century", "price": 8.95 },
          { "category": "fiction", "author": "Evelyn Waugh", "title": "Sword of Honour", "price": 12.99 },
          { "category": "fiction", "author": "Herman Melville", "title": "Moby Dick", "isbn": "0-553-21311-3", "price": 8.99 },
          { "category": "fiction", "author": "J. R. R. Tolkien", "title": "The Lord of the Rings", "isbn": "0-395-19395-8", "price": 22.99 }
        ],
        "bicycle": { "color": "red", "price": 19.95 }
      }
    }
  JSON

  def query(expression, document)
    JSON::JSONPath.query(expression, document)
  end

  def values(expression, document)
    query(expression, document).map(&:value)
  end

  def paths(expression, document)
    query(expression, document).map(&:path)
  end

  def test_root_only
    document = { "a" => 1 }
    matches = query("$", document)
    assert_equal 1, matches.size
    assert_equal document, matches[0].value
    assert_equal "$", matches[0].path
  end

  def test_member_shorthand_and_bracket
    assert_equal ["red"], values("$.store.bicycle.color", STORE)
    assert_equal ["red"], values("$['store']['bicycle']['color']", STORE)
    assert_equal ["red"], values(%q($["store"]["bicycle"]["color"]), STORE)
  end

  def test_array_index
    assert_equal ["Sayings of the Century"], values("$.store.book[0].title", STORE)
    assert_equal [], values("$.store.book[10]", STORE)
  end

  def test_negative_array_index
    assert_equal ["The Lord of the Rings"], values("$.store.book[-1].title", STORE)
    assert_equal ["Moby Dick"], values("$.store.book[-2].title", STORE)
    assert_equal [], values("$.store.book[-5]", STORE)
  end

  def test_wildcard_on_object_and_array
    assert_equal ["red", 19.95], values("$.store.bicycle.*", STORE)
    assert_equal %w[reference fiction fiction fiction], values("$.store.book[*].category", STORE)
    assert_equal 4, query("$.store.book[*]", STORE).size
  end

  def test_recursive_descent
    assert_equal [8.95, 12.99, 8.99, 22.99, 19.95], values("$..price", STORE)
    assert_equal ["0-553-21311-3", "0-395-19395-8"], values("$..isbn", STORE)
    assert_equal "Sayings of the Century", values("$..book[0].title", STORE).first
    assert_equal STORE["store"]["book"], values("$..book", STORE).first
  end

  def test_recursive_descent_wildcard
    document = { "a" => { "b" => [1, 2] } }
    assert_equal [{ "b" => [1, 2] }, [1, 2], 1, 2], values("$..*", document)
    assert_equal ["$['a']", "$['a']['b']", "$['a']['b'][0]", "$['a']['b'][1]"], paths("$..*", document)
  end

  def test_slices
    array = { "a" => [0, 1, 2, 3, 4, 5] }
    assert_equal [1, 2], values("$.a[1:3]", array)
    assert_equal [0, 1], values("$.a[:2]", array)
    assert_equal [4, 5], values("$.a[4:]", array)
    assert_equal [0, 2, 4], values("$.a[0:5:2]", array)
    assert_equal [3, 4], values("$.a[-3:-1]", array)
    assert_equal [5, 4, 3, 2, 1, 0], values("$.a[::-1]", array)
    assert_equal [5, 3, 1], values("$.a[::-2]", array)
    assert_equal [0, 1, 2, 3, 4, 5], values("$.a[::]", array)
    assert_equal [], values("$.a[10:20]", array)
  end

  def test_normalized_paths
    assert_equal ["$['store']['book'][0]['title']"], paths("$.store.book[0].title", STORE)
    assert_equal ["$['store']['book'][3]"], paths("$.store.book[-1]", STORE)
    assert_equal ["$['store']['bicycle']['color']"], paths(%q($["store"].bicycle['color']), STORE)
  end

  def test_missing_member_vs_null_value
    document = { "present_null" => nil, "present_false" => false }
    assert_equal [], query("$.missing", document)

    null_match = query("$.present_null", document)
    assert_equal 1, null_match.size
    assert_nil null_match[0].value
    assert_equal "$['present_null']", null_match[0].path

    assert_equal [false], values("$.present_false", document)
  end

  def test_match_equality_and_helpers
    compiled = JSON::JSONPath.new("$.store.bicycle.color")
    assert_equal "$.store.bicycle.color", compiled.expression
    assert_equal ["red"], compiled.values(STORE)
    assert_equal ["$['store']['bicycle']['color']"], compiled.paths(STORE)
    match = compiled.query(STORE).first
    assert_equal JSON::JSONPath::Match.new("red", "$['store']['bicycle']['color']"), match
    assert_match(/\A#<JSON::JSONPath::Match /, match.inspect)
  end

  def test_compile_once_evaluate_many_documents
    compiled = JSON::JSONPath.new("$.items[?(@.price < 10)].name")
    cheap = { "items" => [{ "name" => "pen", "price" => 1 }, { "name" => "car", "price" => 30_000 }] }
    empty = { "items" => [] }
    assert_equal ["pen"], compiled.values(cheap)
    assert_equal [], compiled.values(empty)
    # Evaluating against one document must not leak state into the next.
    assert_equal ["pen"], compiled.values(cheap)
  end

  def test_query_does_not_mutate_document
    document = JSON.parse(JSON.dump(STORE))
    before = JSON.dump(document)
    JSON::JSONPath.new("$..*[?(@.price)].title").query(document)
    assert_equal before, JSON.dump(document)
  end

  def test_non_string_expression
    assert_raise(TypeError) { JSON::JSONPath.new(:"$.a") }
  end

  def test_filter_numeric_comparison
    assert_equal ["Sayings of the Century", "Moby Dick"],
      values("$.store.book[?(@.price < 10)].title", STORE)
    assert_equal ["The Lord of the Rings"],
      values("$.store.book[?(@.price > 20)].title", STORE)
    assert_equal ["Sword of Honour"],
      values("$.store.book[?(@.price == 12.99)].title", STORE)
    assert_equal ["Sayings of the Century", "Sword of Honour", "Moby Dick"],
      values("$.store.book[?(@.price <= 12.99)].title", STORE)
    assert_equal ["Sword of Honour", "The Lord of the Rings"],
      values("$.store.book[?(@.price != 8.95 && @.price > 10)].title", STORE)
  end

  def test_filter_string_and_boolean_literals
    assert_equal ["red"], values("$.store[?(@.color == 'red')].color", STORE)
    assert_equal ["Nigel Rees"],
      values("$.store.book[?(@.category == 'reference')].author", STORE)
    document = { "a" => [{ "ok" => true }, { "ok" => false }, {}] }
    assert_equal [true], values("$.a[?(@.ok == true)].ok", document)
    assert_equal [false], values("$.a[?(@.ok == false)].ok", document)
  end

  def test_filter_existence_is_structural_not_truthy
    document = {
      "items" => [
        { "name" => "a", "flag" => nil },
        { "name" => "b", "flag" => false },
        { "name" => "c" },
      ],
    }
    # null and false values still count as existing.
    assert_equal %w[a b], values("$.items[?(@.flag)].name", document)
    assert_equal %w[c], values("$.items[?(!@.flag)].name", document)
    assert_equal ["0-553-21311-3", "0-395-19395-8"],
      values("$.store.book[?(@.isbn)].isbn", STORE)
  end

  def test_filter_null_comparison
    document = { "items" => [{ "v" => nil }, { "v" => 1 }, {}] }
    assert_equal [nil], values("$.items[?(@.v == null)].v", document)
    assert_equal [1], values("$.items[?(@.v != null)].v", document)
  end

  def test_filter_boolean_combinations_and_parentheses
    expr = "$.store.book[?(@.category == 'reference' || (@.category == 'fiction' && @.price < 10))].title"
    assert_equal ["Sayings of the Century", "Moby Dick"], values(expr, STORE)
    expr = "$.store.book[?(!(@.category == 'fiction'))].title"
    assert_equal ["Sayings of the Century"], values(expr, STORE)
  end

  def test_filter_current_node_scalar
    document = { "nums" => [1, 5, 10, 20], "words" => %w[a bb ccc] }
    assert_equal [5, 10], values("$.nums[?(@ >= 5 && @ <= 10)]", document)
    assert_equal ["bb"], values(%q($.words[?(@ == 'bb')]), document)
  end

  def test_filter_root_reference
    document = {
      "threshold" => 10,
      "items" => [{ "v" => 5 }, { "v" => 15 }],
    }
    assert_equal [15], values("$.items[?(@.v > $.threshold)].v", document)
  end

  def test_filter_nested_path_and_index
    document = {
      "rows" => [
        { "cells" => [{ "v" => 1 }] },
        { "cells" => [{ "v" => 9 }] },
        { "cells" => [] },
      ],
    }
    assert_equal [9], values("$.rows[?(@.cells[0].v > 5)].cells[0].v", document)
    assert_equal [{ "v" => 1 }, { "v" => 9 }], values("$.rows[?(@.cells[0])].cells[0]", document)
  end

  def test_filter_on_object_members
    document = { "a" => { "n" => 1 }, "b" => { "n" => 5 }, "c" => 3 }
    assert_equal [{ "n" => 5 }], values("$[?(@.n > 2)]", document)
    assert_equal ["$['b']"], paths("$[?(@.n > 2)]", document)
  end

  def test_multibyte_member_names
    document = JSON.parse('{"日本語": {"键": "值"}, "café": 1}')
    assert_equal ["值"], values("$.日本語.键", document)
    assert_equal ["值"], values("$['日本語']['键']", document)
    assert_equal [1], values("$.café", document)
    assert_equal ["$['日本語']['键']"], paths("$.日本語.键", document)
    assert_equal ["值"], values("$.日本語[?(@ == '值')]", document).first(1)
  end

  def test_multibyte_via_unicode_escape
    document = { "键" => "值" }
    assert_equal ["值"], values(%q($['\u952e']), document)
    assert_equal ["值"], values(%q($["\u952e"]), document)
  end

  def test_escaped_member_names
    document = {
      "it's" => 1,
      'say "hi"' => 2,
      "back\\slash" => 3,
      "tab\there" => 4,
    }
    assert_equal [1], values(%q($['it\'s']), document)
    assert_equal [2], values(%q($["say \"hi\""]), document)
    assert_equal [3], values(%q($['back\\\\slash']), document)
    assert_equal [4], values(%q($['tab\there']), document)
    # Normalized paths re-escape special characters and can be recompiled.
    path = paths(%q($['it\'s']), document).first
    assert_equal "$['it\\'s']", path
    assert_equal [1], values(path, document)
    path = paths(%q($['back\\\\slash']), document).first
    assert_equal [3], values(path, document)
  end

  def test_unsupported_syntax_raises_syntax_error
    error_class = JSON::JSONPath::SyntaxError
    assert_raise(error_class) { JSON::JSONPath.new("") }
    assert_raise(error_class) { JSON::JSONPath.new("store.book") }
    assert_raise(error_class) { JSON::JSONPath.new("$.a b") }
    assert_raise(error_class) { JSON::JSONPath.new("$[0,1]") }
    assert_raise(error_class) { JSON::JSONPath.new("$['a','b']") }
    assert_raise(error_class) { JSON::JSONPath.new("$[(@.length-1)]") }
    assert_raise(error_class) { JSON::JSONPath.new("$[?(@.a.length() > 1)]") }
    assert_raise(error_class) { JSON::JSONPath.new("$.a[1:2:0]") }
    assert_raise(error_class) { JSON::JSONPath.new("$.a[") }
    assert_raise(error_class) { JSON::JSONPath.new("$['a") }
    assert_raise(error_class) { JSON::JSONPath.new("$.a[?(@.b == )]") }
    assert_raise(error_class) { JSON::JSONPath.new("$.a[?(@.b ~ 1)]") }
    assert_raise(error_class) { JSON::JSONPath.new("$.a[?(1)]") }
    assert_raise(error_class) { JSON::JSONPath.new("$..[?(@..b)]") }
    assert_raise(error_class) { JSON::JSONPath.new(%q($['\q'])) }
  end

  def test_syntax_error_is_a_json_error
    assert_kind_of JSON::JSONError, JSON::JSONPath::SyntaxError.new("x")
    error = assert_raise(JSON::JSONPath::SyntaxError) { JSON::JSONPath.new("$[0,1]") }
    assert_match(/union/, error.message)
  end
end
