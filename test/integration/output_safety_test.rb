# frozen_string_literal: true

require 'test_helper'

class OutputSafetyTest < Minitest::Test
  HTML = Liquid::Safety::HTML_TEXT_GUARANTEE
  ATTR = Liquid::Safety::HTML_ATTRIBUTE_GUARANTEE
  JSONG = Liquid::Safety::JSON_STRING_GUARANTEE
  BS = 92.chr

  module LocalFunnyFilter
    def make_funny(_input)
      'LOL'
    end
  end

  def render(template, assigns = {}, mode: :html, **options)
    Liquid::Template.parse(template).render!(assigns, { output_mode: mode }.merge!(options))
  end

  def test_classic_mode_does_not_escape_by_default
    assert_equal '<b>', render('{{ x }}', { 'x' => '<b>' }, mode: :classic)
  end

  def test_mode_is_opt_in_per_render
    template = Liquid::Template.parse('{{ x }}')
    assert_equal '<b>', template.render!('x' => '<b>')
    assert_equal '&lt;b&gt;', template.render!({ 'x' => '<b>' }, { output_mode: :html })
  end

  def test_environment_level_output_mode
    environment = Liquid::Environment.build(output_mode: :html)
    template = Liquid::Template.parse('{{ x }}', environment: environment)
    assert_equal '&lt;b&gt;', template.render!('x' => '<b>')
    assert_equal '<b>', template.render!({ 'x' => '<b>' }, { output_mode: :classic })
  end

  def test_html_text_mode_autoescapes
    assert_equal '&lt;b&gt;', render('{{ x }}', { 'x' => '<b>' })
    assert_equal '&quot; &#39; &amp;', render('{{ x }}', { 'x' => %q(" ' &) })
  end

  def test_html_attribute_mode_autoescapes
    out = render('{{ x }}', { 'x' => '"<>' }, mode: :html_attribute)
    refute_includes out, '<'
    refute_includes out, '"'
    assert_includes out, '&quot;'
  end

  def test_json_string_mode_escapes
    out = render('{{ x }}', { 'x' => 'a"b' }, mode: :json)
    assert_equal 'a' + BS + '"b', out
  end

  def test_explicit_escape_produces_html_text_safe_value
    assert_equal '&lt;b&gt;', render('{{ x | escape }}', { 'x' => '<b>' })
    assert_equal '&lt;b&gt;', render('{{ x | h }}', { 'x' => '<b>' })
    assert_equal '&lt;b&gt;', render('{{ x | escape }}', { 'x' => '<b>' }, mode: :classic)
  end

  def test_explicit_escape_is_not_double_escaped
    assert_equal '&lt;b&gt;', render('{{ x | escape }}', { 'x' => '<b>' })
  end

  def test_json_escape_filter
    assert_equal 'a' + BS + '"b',
      render('{{ x | json_escape }}', { 'x' => 'a"b' }, mode: :json)
    assert_equal 'a' + BS + '"b',
      render('{{ x | json_escape }}', { 'x' => 'a"b' }, mode: :classic)
  end

  def test_nested_filter_keeps_declared_guarantee
    assert_equal '&lt;b&gt;hi',
      render('{{ x | escape | downcase }}', { 'x' => '<B>HI' })
  end

  def test_undeclared_filter_strips_guarantee
    assert_equal 'LOL',
      render('{{ x | escape | make_funny }}', { 'x' => '<b>' }, filters: [LocalFunnyFilter])
  end

  def test_preserving_filter_requires_every_argument_to_be_safe
    # The untrusted argument blocks preservation, so the entire result is
    # treated as untrusted and re-escaped (the already-escaped fragment is
    # double-escaped); a safe fragment never whitelists the concatenation.
    assert_equal '&amp;lt;b&amp;gt;&lt;i&gt;',
      render('{{ x | escape | append: y }}', { 'x' => '<b>', 'y' => '<i>' })
  end

  def test_truncate_preserves_only_when_suffix_is_safe
    suffix = Liquid::Safety.mark('<', [HTML, ATTR, JSONG])
    assert_equal '&lt;b&gt;<',
      render('{{ x | escape | truncate: 10, y }}', { 'x' => '<b>hello</b>', 'y' => suffix })
  end

  def test_truncate_with_untrusted_suffix_is_re_escaped
    assert_equal '&amp;lt;b&amp;gt;&lt;',
      render('{{ x | escape | truncate: 10, y }}', { 'x' => '<b>hello</b>', 'y' => '<' })
  end

  def test_url_encode_is_safe_across_contexts
    assert_equal 'a%3Cb%3E', render('{{ x | url_encode }}', { 'x' => 'a<b>' })
    assert_equal 'a%3Cb%3E', render('{{ x | url_encode }}', { 'x' => 'a<b>' }, mode: :json)
  end

  def test_capture_of_a_safe_fragment_is_unmarked
    template = '{% capture c %}{{ x | escape }}{% endcapture %}{{ c }}'
    assert_equal '&amp;lt;b&amp;gt;', render(template, { 'x' => '<b>' })
  end

  def test_assign_of_safe_value_can_keep_mark
    assert_equal '&lt;b&gt;',
      render('{% assign y = x | escape %}{{ y }}', { 'x' => '<b>' })
  end

  def test_template_literal_argument_keeps_guarantee
    # A safe fragment does not whitelist ordinary concatenation on its own;
    # here the literal argument is author-controlled, but append is not
    # declared to preserve guarantees, so the whole result stays untrusted.
    assert_equal '&amp;lt;b&amp;gt;Z',
      render('{{ x | escape | append: "Z" }}', { 'x' => '<b>' })
  end

  def test_html_text_safe_value_is_not_trusted_as_json_string
    value = Liquid::Safety.mark('a &amp; b', HTML)
    assert_equal 'a &amp; b', render('{{ x }}', { 'x' => value })
    assert_equal 'a &amp; b', render('{{ x }}', { 'x' => value }, mode: :json)
  end

  def test_attribute_safe_value_is_not_trusted_as_html_text
    value = Liquid::Safety.mark('a<b', ATTR)
    assert_equal 'a&lt;b', render('{{ x }}', { 'x' => value })
    assert_equal 'a<b', render('{{ x }}', { 'x' => value }, mode: :html_attribute)
  end

  def test_json_safe_value_is_not_trusted_as_html_text
    value = Liquid::Safety.mark('<b>', JSONG)
    assert_equal '&lt;b&gt;', render('{{ x }}', { 'x' => value })
    assert_equal '<b>', render('{{ x }}', { 'x' => value }, mode: :json)
  end

  def test_value_with_all_guarantees_is_safe_everywhere
    value = Liquid::Safety.mark('<b>', [HTML, ATTR, JSONG])
    assert_equal '<b>', render('{{ x }}', { 'x' => value })
    assert_equal '<b>', render('{{ x }}', { 'x' => value }, mode: :html_attribute)
    assert_equal '<b>', render('{{ x }}', { 'x' => value }, mode: :json)
  end

  class ForgingDrop < Liquid::Drop
    def html
      Liquid::Safety.mark('<img src=x onerror=alert(1)>', HTML)
    end

    def nested
      { 'title' => Liquid::Safety.mark('<x>', HTML) }
    end

    def to_s
      Liquid::Safety.mark('<drop>', HTML)
    end
  end

  def test_drop_cannot_forge_safety
    escaped = '&lt;img src=x onerror=alert(1)&gt;'
    assert_equal escaped,
      render('{{ product.html }}', { 'product' => ForgingDrop.new })
    assert_equal '&lt;x&gt;',
      render('{{ product.nested.title }}', { 'product' => ForgingDrop.new })
  end

  def test_drop_to_s_is_escaped
    assert_equal '&lt;drop&gt;', render('{{ product }}', { 'product' => ForgingDrop.new })
  end

  def test_host_provided_safe_value_is_trusted
    assert_equal '<b>', render('{{ x }}', { 'x' => Liquid::Safety.mark('<b>', HTML) })
  end

  def test_array_elements_are_escaped
    assert_equal '&lt;a&gt;b',
      render('{% for v in items %}{{ v }}{% endfor %}', { 'items' => ['<a>', 'b'] })
  end
end
