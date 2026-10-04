# frozen_string_literal: true

require 'test_helper'

class SafetyUnitTest < Minitest::Test
  HTML = Liquid::Safety::HTML_TEXT_GUARANTEE
  ATTR = Liquid::Safety::HTML_ATTRIBUTE_GUARANTEE
  JSONG = Liquid::Safety::JSON_STRING_GUARANTEE

  def test_mode_coercion
    assert_equal :classic, Liquid::Safety.coerce_mode(nil)
    assert_equal :html_text, Liquid::Safety.coerce_mode(:html)
    assert_equal :html_text, Liquid::Safety.coerce_mode('html')
    assert_equal :html_attribute, Liquid::Safety.coerce_mode(:attribute)
    assert_equal :json_string, Liquid::Safety.coerce_mode(:json)
    assert_raises(ArgumentError) { Liquid::Safety.coerce_mode(:bogus) }
  end

  def test_guarantee_for_mode_is_context_specific
    refute_nil Liquid::Safety.guarantee_for_mode(:html_text)
    refute_equal Liquid::Safety.guarantee_for_mode(:html_text),
      Liquid::Safety.guarantee_for_mode(:html_attribute)
    assert_nil Liquid::Safety.guarantee_for_mode(:classic)
  end

  def test_mark_wraps_and_carries_guarantees
    safe = Liquid::Safety.mark('abc', HTML)
    assert_instance_of Liquid::Safety::SafeValue, safe
    assert_includes safe.guarantees, HTML
    assert Liquid::Safety.safe_for?(safe, HTML)
    refute Liquid::Safety.safe_for?(safe, JSONG)
    assert_nil Liquid::Safety.guarantees('plain')
    assert_equal 'abc', Liquid::Safety.mark('abc', nil)
    refute_instance_of Liquid::Safety::SafeValue, Liquid::Safety.mark('abc', nil)
  end

  def test_safe_value_is_a_frozen_string
    safe = Liquid::Safety.mark('abc', HTML)
    assert_kind_of String, safe
    assert_predicate safe, :frozen?
    assert_raises(FrozenError) { safe << 'x' }
  end

  def test_derived_strings_lose_guarantees
    safe = Liquid::Safety.mark('abc', HTML)
    refute_instance_of Liquid::Safety::SafeValue, safe + 'x'
    refute_instance_of Liquid::Safety::SafeValue, safe.downcase
  end

  def test_strip_removes_guarantees_recursively
    nested = { 'a' => [Liquid::Safety.mark('<x>', HTML), 'y'] }
    result = Liquid::Safety.strip(nested)
    refute_instance_of Liquid::Safety::SafeValue, result['a'][0]
    assert_equal '<x>', result['a'][0]
    assert_equal 'y', result['a'][1]
  end

  def test_json_escape
    assert_equal [92, 34].pack('CC'), Liquid::Safety.json_escape('"')
    assert_equal 'a' + [92].pack('C') + 'nb', Liquid::Safety.json_escape("a\nb")
  end

  def test_escape_for_each_mode
    raw = %q(<a href="x">'&)
    assert_equal raw, Liquid::Safety.escape_for_mode(raw, :classic)
    assert_equal CGI.escapeHTML(raw), Liquid::Safety.escape_for_mode(raw, :html_text)
    assert_equal CGI.escapeHTML(raw), Liquid::Safety.escape_for_mode(raw, :html_attribute)
    assert_includes Liquid::Safety.escape_for_mode('"', :json_string), [92].pack('C')
  end

  def test_apply_spec_produces
    spec = Liquid::Safety::FilterSpec.new(produces: HTML)
    result = Liquid::Safety.apply_spec(spec, nil, [])
    assert_includes result, HTML
  end

  def test_apply_spec_preserves_when_input_and_all_args_safe
    spec = Liquid::Safety::FilterSpec.new(preserves: HTML)
    result = Liquid::Safety.apply_spec(spec, [HTML], [[HTML]])
    assert_includes result, HTML
  end

  def test_apply_spec_drops_preservation_on_untrusted_argument
    spec = Liquid::Safety::FilterSpec.new(preserves: HTML)
    assert_empty Liquid::Safety.apply_spec(spec, [HTML], [nil])
    assert_empty Liquid::Safety.apply_spec(spec, nil, [[HTML]])
  end

  def test_apply_spec_without_spec_returns_nil
    assert_nil Liquid::Safety.apply_spec(nil, [HTML], [])
  end
end
