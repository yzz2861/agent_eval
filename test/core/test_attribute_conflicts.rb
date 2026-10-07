require 'helper'

class TestSlimAttributeConflicts < TestSlim
  def test_conflict_first
    assert_html '<p a="1"></p>', "p a=\"1\" a=\"2\" a=\"3\"", attr_conflict: :first
  end

  def test_conflict_last
    assert_html '<p a="3"></p>', "p a=\"1\" a=\"2\" a=\"3\"", attr_conflict: :last
  end

  def test_conflict_reject_is_default
    assert_runtime_error 'Multiple a attributes specified', 'p a=1 a=2'
  end

  def test_conflict_first_skips_false_and_nil
    source = "- value = nil\np a=\"1\" a=false a=value a=\"3\""
    assert_html '<p a="1"></p>', source, attr_conflict: :first
  end

  def test_conflict_last_skips_false_and_nil
    source = "- value = nil\np a=\"1\" a=false a=value a=\"3\""
    assert_html '<p a="3"></p>', source, attr_conflict: :last
  end

  def test_conflict_first_skips_leading_false
    assert_html '<p a="42"></p>', "- value = 42\np a=false a=value", attr_conflict: :first
  end

  def test_conflict_all_values_false_or_nil_omits_attribute
    assert_html '<p></p>', 'p a=false a=nil', attr_conflict: :last
  end

  def test_conflict_merge_delimiter
    source = "p a=\"1\" a=\"2\" a=\"3\""
    assert_html '<p a="1-2-3"></p>', source, merge_attrs: {'class' => ' ', 'a' => '-'}
  end

  def test_conflict_policy_per_attribute
    source = "p id=\"1\" id=\"2\" class=\"a\" class=\"b\""
    assert_html '<p class="a b" id="2"></p>', source,
                merge_attrs: {'class' => ' ', 'id' => :last}
  end

  def test_three_sources_first
    source = "- attrs = {a: '2'}\np a=\"1\" *attrs a=\"3\""
    assert_html '<p a="1"></p>', source, attr_conflict: :first
  end

  def test_three_sources_last
    source = "- attrs = {a: '2'}\np a=\"1\" *attrs a=\"3\""
    assert_html '<p a="3"></p>', source, attr_conflict: :last
  end

  def test_three_sources_merge
    source = "- attrs = {a: '2'}\np a=\"1\" *attrs a=\"3\""
    assert_html '<p a="1|2|3"></p>', source, merge_attrs: {'a' => '|'}
  end

  def test_three_sources_reject
    source = "- attrs = {a: '2'}\np a=\"1\" *attrs a=\"3\""
    assert_runtime_error 'Multiple a attributes specified', source
  end

  def test_static_and_splat_paths_have_parity
    {reject: {}, first: {attr_conflict: :first}, last: {attr_conflict: :last}}.each do |policy, options|
      static = begin
        render('p a="1" a="2"', options.dup)
      rescue RuntimeError => e
        e.message
      end
      scope = Object.new
      scope.define_singleton_method(:attrs) { {a: '2'} }
      splat = begin
        render('p a="1" *attrs', options.merge(scope: scope))
      rescue RuntimeError => e
        e.message
      end
      assert_equal static, splat, "policy #{policy} differs between static and splat paths"
    end
  end

  def test_expression_evaluated_only_once
    source = "- counter = 0\np a=(counter += 1) a=(counter += 1)"
    assert_html '<p a="2"></p>', source, attr_conflict: :last
  end

  def test_splat_hash_is_not_mutated
    scope = Object.new
    attrs = {a: 1, b: [1, 2]}
    scope.define_singleton_method(:attrs) { attrs }
    render('p a=9 *attrs b=8', attr_conflict: :last, scope: scope)
    assert_equal({a: 1, b: [1, 2]}, attrs)
  end

  def test_splat_array_pairs_are_not_mutated
    scope = Object.new
    attrs = [[:a, 1], [:a, 2]]
    scope.define_singleton_method(:attrs) { attrs }
    assert_html '<p a="2"></p>', 'p *attrs', attr_conflict: :last, scope: scope
    assert_equal([[:a, 1], [:a, 2]], attrs)
  end

  def test_escaped_only_once_first
    source = "- attrs = {a: '<b>'}\np a=\"<b>\" *attrs"
    assert_html '<p a="&lt;b&gt;"></p>', source, attr_conflict: :first
  end

  def test_escaped_only_once_last
    source = "- attrs = {a: '<b>'}\np a=\"<b>\" *attrs"
    assert_html '<p a="&lt;b&gt;"></p>', source, attr_conflict: :last
  end

  def test_nested_data_expansion_first
    source = "- attrs = {'data-x' => 2}\np data={x: 1} *attrs data-x=3"
    assert_html '<p data-x="1"></p>', source, attr_conflict: :first
  end

  def test_nested_data_expansion_last
    source = "- attrs = {'data-x' => 2}\np data={x: 1} *attrs data-x=3"
    assert_html '<p data-x="3"></p>', source, attr_conflict: :last
  end

  def test_nested_data_expansion_merge
    source = "- attrs = {'data-x' => 2}\np data={x: 1} *attrs data-x=3"
    assert_html '<p data-x="1|2|3"></p>', source, merge_attrs: {'data-x' => '|'}
  end

  def test_symbol_policy_with_array_values
    source = 'p class=["a", "b"] class="c"'
    assert_html '<p class="c"></p>', source, merge_attrs: {'class' => :last}
    assert_html '<p class="a"></p>', source, merge_attrs: {'class' => :first}
  end

  def test_symbol_policy_array_ignores_false_nil_and_empty_strings
    source = 'p class=[nil, false, "a", ""] class="b"'
    assert_html '<p class="b"></p>', source, merge_attrs: {'class' => :last}
  end
end
