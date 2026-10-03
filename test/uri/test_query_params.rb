# frozen_string_literal: false
require 'test/unit'
require 'uri'

class URI::TestQueryParams < Test::Unit::TestCase
  def uri(str)
    URI.parse(str)
  end

  def test_preserves_order_and_duplicate_keys
    qp = URI::QueryParams.parse('a=1&b=2&a=3')
    assert_equal([%w[a 1], %w[b 2], %w[a 3]], qp.pairs)
    assert_equal([0, 2], qp.indices('a'))
    assert_equal(1, qp.index('b'))
    assert_nil(qp.index('z'))
  end

  def test_preserves_original_encoding_of_untouched_items
    qp = URI::QueryParams.parse('a=hello+world&b=%2f%2B&c=x%20y&d=%61')
    qp[0] = 'new val'
    assert_equal('a=new+val&b=%2f%2B&c=x%20y&d=%61', qp.to_s)
  end

  def test_mixed_plus_and_percent_space
    q = uri('http://example.com/?a=x+y&b=x%20y')
    q.query_params['a'] = 'p q'
    assert_equal('a=p+q&b=x%20y', q.query)
    q.query_params[1] = 'r+s'
    assert_equal('a=p+q&b=r%2Bs', q.query)
  end

  def test_lowercase_escapes_are_preserved
    q = uri('http://example.com/?a=%2f&b=1')
    q.query_params['b'] = '2'
    assert_equal('a=%2f&b=2', q.query)
  end

  def test_positional_edit_targets_one_duplicate
    q = uri('http://example.com/?a=1&a=2&a=3')
    q.query_params[1] = '9'
    assert_equal('a=1&a=9&a=3', q.query)
    assert_equal(%w[1 9 3], q.query_params.pairs.map(&:last))
  end

  def test_key_edit_targets_only_first_duplicate
    qp = URI::QueryParams.parse('a=1&a=2&b=3')
    qp['a'] = '9'
    assert_equal('a=9&a=2&b=3', qp.to_s)
  end

  def test_key_assignment_appends_when_missing
    qp = URI::QueryParams.parse('a=1')
    qp['new key'] = 'new val'
    assert_equal('a=1&new+key=new+val', qp.to_s)
  end

  def test_positional_assignment_out_of_range_raises
    qp = URI::QueryParams.parse('a=1')
    assert_raise(IndexError) { qp[3] = 'x' }
    assert_raise(IndexError) { qp[-2] = 'x' }
  end

  def test_items_without_equals
    qp = URI::QueryParams.parse('flag&a=1&b=&c')
    items = qp.items
    assert_equal(['flag', nil], [items[0].key, items[0].value])
    assert_equal(%w[a 1], [items[1].key, items[1].value])
    assert_equal(['b', ''], [items[2].key, items[2].value])
    assert_equal(['c', nil], [items[3].key, items[3].value])
  end

  def test_set_nil_value_removes_equals
    qp = URI::QueryParams.parse('a=1&b=2')
    qp[1] = nil
    assert_equal('a=1&b', qp.to_s)
    assert_nil(qp[1])
    assert_equal('1', qp['a'])
  end

  def test_empty_value_is_distinct_from_no_equals
    qp = URI::QueryParams.parse('a=&b')
    assert_equal('', qp['a'])
    assert_nil(qp['b'])
    assert_equal([['a', ''], ['b', nil]], qp.pairs)
  end

  def test_missing_query_is_absent
    q = uri('http://example.com/path')
    assert_nil(q.query)
    qp = q.query_params
    assert_equal(false, qp.present?)
    assert_equal(false, qp.empty?)
    assert_equal(0, qp.size)
    assert_equal('http://example.com/path', q.to_s)
  end

  def test_empty_query_is_present_but_empty
    q = uri('http://example.com/path?')
    assert_equal('', q.query)
    qp = q.query_params
    assert_equal(true, qp.present?)
    assert_equal(true, qp.empty?)
    assert_equal('http://example.com/path?', q.to_s)
  end

  def test_trailing_empty_parameter_is_an_item
    q = uri('http://example.com/path?a=1&')
    assert_equal('a=1&', q.query)
    qp = q.query_params
    assert_equal(true, qp.present?)
    assert_equal(false, qp.empty?)
    assert_equal(2, qp.size)
    assert_equal([['a', '1'], ['', nil]], qp.pairs)
    assert_equal('http://example.com/path?a=1&', q.to_s)
  end

  def test_trailing_empty_parameter_can_be_edited
    q = uri('http://example.com/?a=1&')
    q.query_params[1] = 'x'
    assert_equal('a=1&=x', q.query)
    q.query_params.add('y', '')
    assert_equal('a=1&=x&y=', q.query)
  end

  def test_double_separators_are_empty_items
    qp = URI::QueryParams.parse('a=1&&b=2')
    assert_equal([['a', '1'], ['', nil], ['b', '2']], qp.pairs)
    assert_equal('a=1&&b=2', qp.to_s)
  end

  def test_clear_keeps_present_empty_query
    q = uri('http://example.com/?a=1')
    q.query_params.clear
    assert_equal('', q.query)
    assert_equal(true, q.query_params.present?)
    assert_equal(true, q.query_params.empty?)
    assert_equal('http://example.com/?', q.to_s)
    q.query = nil
    assert_equal(false, q.query_params.present?)
    assert_equal('http://example.com/', q.to_s)
  end

  def test_add_insert_and_delete
    qp = URI::QueryParams.parse('a=1&b=2')
    qp.add('a', '3')
    assert_equal('a=1&b=2&a=3', qp.to_s)
    qp.insert(1, 'x', nil)
    assert_equal('a=1&x&b=2&a=3', qp.to_s)
    assert_equal(['x', nil], qp.delete_at(1))
    assert_equal('a=1&b=2&a=3', qp.to_s)
    assert_equal('1', qp.delete('a'))
    assert_equal('b=2&a=3', qp.to_s)
    assert_nil(qp.delete('z'))
    assert_nil(qp.delete_at(9))
  end

  def test_delete_by_key_leaves_other_duplicates
    qp = URI::QueryParams.parse('a=1&a=2&b=3')
    qp.delete('a')
    assert_equal('a=2&b=3', qp.to_s)
  end

  def test_only_modified_item_is_reencoded
    q = uri('http://example.com/?a=%E3%81%82&b=%2f&a=2')
    q.query_params[1] = "\u6F22"
    assert_equal('a=%E3%81%82&b=%E6%BC%A2&a=2', q.query)
  end

  def test_edits_update_the_uri
    q = uri('http://example.com/?a=1&a=2')
    q.query_params[0] = '0'
    assert_equal('http://example.com/?a=0&a=2', q.to_s)
  end

  def test_query_assignment_discards_cached_view
    q = uri('http://example.com/?a=1')
    old = q.query_params
    q.query = 'b=2'
    assert_not_same(old, q.query_params)
    assert_equal('2', q.query_params['b'])
    assert_nil(q.query_params['a'])
  end

  def test_view_reflects_own_edits
    qp = uri('http://example.com/?a=1').query_params
    qp['a'] = '2'
    assert_equal('2', qp['a'])
    assert_equal([['a', '2']], qp.pairs)
    qp.add('c', '3')
    assert_equal('3', qp['c'])
    assert_equal([0, 1], [qp.index('a'), qp.index('c')])
  end

  def test_cached_view_is_retained_across_edits
    q = uri('http://example.com/?a=1')
    qp = q.query_params
    qp.add('b', '2')
    assert_same(qp, q.query_params)
    q.query_params[0] = '0'
    assert_same(qp, q.query_params)
    assert_equal('a=0&b=2', q.query)
  end

  def test_detached_parse_round_trips
    raw = 'a=hello+world&b=%2f&a=%20&flag'
    qp = URI::QueryParams.parse(raw)
    assert_equal(raw, qp.to_s)
  end

  def test_enumerable
    qp = URI::QueryParams.parse('a=1&b=2&c')
    assert_equal(%w[a b c], qp.map(&:key))
    yielded = []
    qp.each_pair {|k, v| yielded << [k, v] }
    assert_equal([['a', '1'], ['b', '2'], ['c', nil]], yielded)
  end

  def test_at_returns_item_snapshot
    qp = URI::QueryParams.parse('a=1&a=2')
    item = qp.at('a')
    assert_equal('a', item.key)
    assert_equal('1', item.value)
    assert_equal('2', qp.at(1).value)
  end

  def test_equals_sign_inside_value_is_preserved
    qp = URI::QueryParams.parse('a=x=y&b')
    assert_equal('x=y', qp['a'])
    assert_nil(qp['b'])
    assert_equal('a=x=y&b', qp.to_s)
    qp['a'] = 'p=q'
    assert_equal('a=p%3Dq&b', qp.to_s)
  end

  def test_index_access_negative
    qp = URI::QueryParams.parse('a=1&b=2')
    assert_equal('2', qp[-1])
    qp[-1] = '9'
    assert_equal('a=1&b=9', qp.to_s)
  end

  def test_empty_query_string_round_trip
    qp = URI::QueryParams.parse('')
    assert_equal(true, qp.empty?)
    assert_equal('', qp.to_s)
    qp.add('a', '1')
    assert_equal('a=1', qp.to_s)
  end

  def test_nil_target_is_missing_query
    qp = URI::QueryParams.new(nil)
    assert_equal(false, qp.present?)
    assert_equal(false, qp.empty?)
    assert_equal(nil, qp.to_s)
    qp.add('a', '1')
    assert_equal('a=1', qp.to_s)
  end

  def test_semicolon_is_part_of_item_not_separator
    qp = URI::QueryParams.parse('a=1;2&b=3')
    assert_equal([['a', '1;2'], ['b', '3']], qp.pairs)
    assert_equal('a=1;2&b=3', qp.to_s)
  end

  def test_plus_in_new_value_is_percent_encoded
    q = uri('http://example.com/?a=1')
    q.query_params[0] = 'x+y'
    assert_equal('a=x%2By', q.query)
  end
end
