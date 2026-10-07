# frozen_string_literal: true

require_relative 'test_helper'

class JSONPathTest < Test::Unit::TestCase
  def test_root_members_arrays_and_unions
    data = {
      'store' => {
        'book' => [
          { 'title' => 'A' },
          { 'title' => 'B' }
        ]
      }
    }

    assert_equal [data], JSON.query_json_path(data, '$').map(&:value)
    assert_equal '$', JSON.query_json_path(data, '$').first.path
    assert_equal ['B'], JSON.query_json_path(data, '$.store.book[1].title').map(&:value)
    assert_equal "$['store']['book'][1]['title']",
                 JSON.query_json_path(data, '$.store.book[1].title').first.path
    assert_equal ['A', 'B'], JSON.query_json_path(data, "$.store.book[*]['title']").map(&:value)
    assert_equal [
      { 'title' => 'A' },
      { 'title' => 'B' }
    ], JSON.query_json_path(data, '$.store.book[0,1]').map(&:value)
  end

  def test_recursive_descent_and_wildcard
    data = {
      'items' => [
        { 'id' => 1, 'child' => { 'id' => 2 } },
        { 'child' => { 'items' => [{ 'id' => 3 }] } }
      ]
    }

    assert_equal [1, 2, 3], JSON.query_json_path(data, '$..id').map(&:value)
    assert_equal ["$['items'][0]", "$['items'][1]", "$['items'][0]['id']"],
                 JSON.query_json_path(data, '$..*').first(3).map(&:path)
  end

  def test_slices_and_negative_indexes
    data = { 'values' => [0, 1, 2, 3, 4] }

    assert_equal [1, 3], JSON.query_json_path(data, '$.values[1:4:2]').map(&:value)
    assert_equal [4, 2], JSON.query_json_path(data, '$.values[-1:1:-2]').map(&:value)
    assert_equal [4], JSON.query_json_path(data, '$.values[-1]').map(&:value)
    assert_equal "$['values'][4]", JSON.query_json_path(data, '$.values[-1]').first.path
    assert_equal [], JSON.query_json_path(data, '$.values[-9]').map(&:value)
    assert_equal [], JSON.query_json_path(data, '$.values[9]').map(&:value)
  end

  def test_filter_boolean_comparisons_and_missing_vs_null
    data = {
      'users' => [
        { 'name' => 'Ada', 'age' => 36, 'active' => true },
        { 'name' => 'Grace', 'age' => 85, 'active' => false },
        { 'name' => nil, 'age' => 0 },
        { 'age' => 0 }
      ]
    }

    assert_equal ['Ada'],
                 JSON.query_json_path(data, '$.users[?@.active == true]').map(&:value).map { |u| u['name'] }
    assert_equal ['Ada', 'Grace'],
                 JSON.query_json_path(data, '$.users[?@.age >= 18]').map(&:value).map { |u| u['name'] }
    assert_equal ['Ada', 'Grace', nil],
                 JSON.query_json_path(data, '$.users[?@.name]').map(&:value).map { |u| u['name'] }
    assert_equal ['Ada', 'Grace'],
                 JSON.query_json_path(data, '$.users[?@.name && @.name != null]').map(&:value).map { |u| u['name'] }
    null_results = JSON.query_json_path(data, '$.users[?@.name == null]')
    assert_equal [nil], null_results.map { |result| result.value['name'] }
    assert_equal [2], null_results.map { |result| result.path[/\[(\d+)\]$/, 1].to_i }
    assert_equal [36, 85, 0, 0],
                 JSON.query_json_path(data, '$.users[?@.age]').map(&:value).map { |u| u['age'] }
    assert_equal [true, false],
                 JSON.query_json_path(data, '$.users[?@.active]').map(&:value).map { |u| u['active'] }
  end

  def test_filter_boolean_combinations_and_root_query
    data = {
      'limit' => 10,
      'items' => [
        { 'price' => 5, 'tag' => 'sale' },
        { 'price' => 20 },
        { 'price' => 8, 'tag' => 'old' }
      ]
    }

    expression = '$.items[?(@.price < $.limit && @.tag == "sale") || @.tag == "old"]'
    assert_equal [5, 8], JSON.query_json_path(data, expression).map(&:value).map { |item| item['price'] }
    assert_equal [data], JSON.query_json_path(data, '$[?$.limit == 10]').map(&:value)
  end

  def test_multibyte_and_escaped_member_names
    data = {
      '中文🎉' => 'multibyte',
      "quote'\\slash" => 'escaped',
      'dot.name' => 'dot'
    }

    assert_equal ['multibyte'], JSON.query_json_path(data, %q{$['中\u6587\ud83c\udf89']}).map(&:value)
    assert_equal "$['中\u6587🎉']", JSON.query_json_path(data, '$.中文🎉').first.path
    assert_equal ['escaped'], JSON.query_json_path(data, %q{$["quote'\\\\slash"]}).map(&:value)
    assert_equal "$['quote\\'\\\\slash']", JSON.query_json_path(data, %q{$["quote'\\\\slash"]}).first.path
    assert_equal ['dot'], JSON.query_json_path(data, '$["dot.name"]').map(&:value)
  end

  def test_compile_once_and_evaluate_many_documents
    query = JSON.compile_json_path('$.items[?@.enabled == true].name')
    first = { 'items' => [{ 'name' => 'one', 'enabled' => true }] }
    second = { 'items' => [{ 'name' => 'two', 'enabled' => false }, { 'name' => 'three', 'enabled' => true }] }

    assert_equal ['one'], query.values_at(first)
    assert_equal ['three'], query.values_at(second)
    assert_equal ['one'], JSON.compile_json_path('$.items[*].name').values_at(first)
  end

  def test_unsupported_or_invalid_syntax_raises
    invalid = [
      '',
      'store.book',
      '$..',
      '$[0:0:0]',
      '$.a[?count(@) > 0]',
      '$.a[?@.name =~ /x/]',
      '$[?null]',
      '$[?1]',
      '$.a[?@.tags[*] == "x"]'
    ]

    invalid.each do |expression|
      assert_raise(JSON::JSONPathError) { JSON.compile_json_path(expression) }
    end
  end
end
