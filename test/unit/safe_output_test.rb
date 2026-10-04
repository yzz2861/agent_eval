# frozen_string_literal: true

require 'test_helper'

class SafeOutputTest < Minitest::Test
  module CustomGuaranteeFilters
    extend Liquid::FilterGuarantees

    guarantees_output :mark_html, context: :html
    preserves_output_guarantees :shout

    def mark_html(input)
      "<mark>#{input}</mark>"
    end

    def shout(input)
      "#{input}!"
    end

    def plain_concat(input, other)
      "#{input}#{other}"
    end

    def record_class(input)
      CustomGuaranteeFilters.last_input_class = input.class
      input
    end

    class << self
      attr_accessor :last_input_class
    end
  end

  class UntrustedDrop < Liquid::Drop
    def name
      '<script>alert(1)</script>'
    end
  end

  class ExplicitlySafeDrop < Liquid::Drop
    def name
      Liquid::SafeValue.new('<b>ok</b>', :html)
    end
  end

  def render(template, assigns = {}, **options)
    Liquid::Template.parse(template).render!(assigns, **options)
  end

  def test_default_mode_is_unchanged
    template = Liquid::Template.parse('{{ x }}|{{ x | escape }}')
    assert_equal('<b>|&lt;b&gt;', template.render!('x' => '<b>'))

    context = Liquid::Context.build
    strainer = context.environment.create_strainer(context)
    assert_instance_of(String, strainer.invoke('escape', '<b>'))
  end

  def test_html_mode_escapes_plain_values
    assert_equal('&lt;b&gt;&amp;', render('{{ x }}', { 'x' => '<b>&' }, output_mode: :html))
  end

  def test_html_attribute_mode_escapes_quotes
    assert_equal(
      '&lt;a x=&quot;1&quot; y=&#39;2&#39;&gt;',
      render('{{ x }}', { 'x' => %(<a x="1" y='2'>) }, output_mode: :html_attribute)
    )
  end

  def test_json_mode_escapes_json_string_content
    template = '{"name": "{{ x }}"}'
    assert_equal(
      '{"name": "a\\"b\\\\c\\n\\u0001"}',
      render(template, { 'x' => "a\"b\\c\n\x01" }, output_mode: :json)
    )
  end

  def test_explicit_escape_is_not_double_escaped
    assert_equal('&lt;b&gt;', render('{{ x | escape }}', { 'x' => '<b>' }, output_mode: :html))
    assert_equal('&lt;b&gt;', render('{{ x | h }}', { 'x' => '<b>' }, output_mode: :html))
    assert_equal('&lt;b&gt;', render('{{ x | escape_once }}', { 'x' => '<b>' }, output_mode: :html))
  end

  def test_explicit_escape_attribute
    assert_equal(
      '&lt;a x=&quot;1&quot; y=&#39;2&#39;&gt;',
      render('{{ x | escape_attribute }}', { 'x' => %(<a x="1" y='2'>) }, output_mode: :html)
    )
  end

  def test_explicit_json_escape
    assert_equal(
      '{"name": "a\"b"}',
      render('{"name": "{{ x | json_escape }}"}', { 'x' => 'a"b' }, output_mode: :json)
    )
  end

  def test_nested_filters_keep_declared_guarantee
    assert_equal('&LT;B&GT;', render('{{ x | escape | upcase }}', { 'x' => '<b>' }, output_mode: :html))
    assert_equal('&lt;B&gt;', render('{{ x | upcase | escape }}', { 'x' => '<b>' }, output_mode: :html))
  end

  def test_concatenating_filter_drops_guarantee
    # append declares nothing, so the safe fragment cannot mark the whole
    # concatenation safe; the entire result is escaped again at output.
    assert_equal(
      '&amp;lt;b&amp;gt;&lt;i&gt;',
      render('{{ x | escape | append: y }}', { 'x' => '<b>', 'y' => '<i>' }, output_mode: :html)
    )
  end

  def test_case_mapping_does_not_preserve_json_guarantee
    # upcase only preserves HTML guarantees; in JSON mode the result is
    # escaped again, so the already-escaped quote gets its backslash escaped.
    assert_equal(
      '\\\\\\"A',
      render('{{ x | json_escape | upcase }}', { 'x' => '"a' }, output_mode: :json)
    )
  end

  def test_cross_mode_reuse_of_same_template
    template = Liquid::Template.parse('{{ x }}')
    assert_equal('&lt;b&gt;', template.render!({ 'x' => '<b>' }, output_mode: :html))
    assert_equal('<b>', template.render!({ 'x' => '<b>' }, output_mode: :json))
    assert_equal('<b>', template.render!('x' => '<b>'))
  end

  def test_safe_value_reused_in_foreign_mode_is_escaped_again
    safe_html = Liquid::SafeValue.new('a\\b', :html)
    assert_equal('a\\b', render('{{ x }}', { 'x' => safe_html }, output_mode: :html))
    assert_equal('a\\\\b', render('{{ x }}', { 'x' => safe_html }, output_mode: :json))
  end

  def test_html_guarantee_does_not_cover_attribute_context
    assert_equal(
      '&amp;lt;b&amp;gt;',
      render('{{ x | escape }}', { 'x' => '<b>' }, output_mode: :html_attribute)
    )
  end

  def test_attribute_guarantee_covers_html_text_context
    assert_equal(
      '&lt;a x=&quot;1&quot;&gt;',
      render('{{ x | escape_attribute }}', { 'x' => '<a x="1">' }, output_mode: :html)
    )
  end

  def test_custom_filter_produce_and_preserve_declarations
    filters = [CustomGuaranteeFilters]
    assert_equal(
      '<mark>&lt;b&gt;</mark>',
      render('{{ x | escape | mark_html }}', { 'x' => '<b>' }, output_mode: :html, filters: filters)
    )
    assert_equal(
      '&lt;b&gt;!',
      render('{{ x | escape | shout }}', { 'x' => '<b>' }, output_mode: :html, filters: filters)
    )
  end

  def test_undeclared_custom_filter_drops_guarantee_and_receives_unwrapped_string
    filters = [CustomGuaranteeFilters]
    assert_equal(
      '&amp;lt;b&amp;gt;&lt;i&gt;',
      render('{{ x | escape | plain_concat: y }}', { 'x' => '<b>', 'y' => '<i>' }, output_mode: :html, filters: filters)
    )

    render('{{ x | escape | record_class }}', { 'x' => '<b>' }, output_mode: :html, filters: filters)
    assert_equal(String, CustomGuaranteeFilters.last_input_class)
  end

  def test_untrusted_drop_return_values_are_escaped
    assert_equal(
      '&lt;script&gt;alert(1)&lt;/script&gt;',
      render('{{ d.name }}', { 'd' => UntrustedDrop.new }, output_mode: :html)
    )
  end

  def test_drop_can_explicitly_return_safe_value
    assert_equal(
      '<b>ok</b>',
      render('{{ d.name }}', { 'd' => ExplicitlySafeDrop.new }, output_mode: :html)
    )
  end

  def test_assign_keeps_guarantee_for_later_output
    assert_equal(
      '&lt;b&gt;',
      render('{% assign v = x | escape %}{{ v }}', { 'x' => '<b>' }, output_mode: :html)
    )
  end

  def test_capture_is_safe_to_reuse_in_same_mode
    assert_equal(
      '&lt;b&gt;',
      render('{% capture v %}{{ x }}{% endcapture %}{{ v }}', { 'x' => '<b>' }, output_mode: :html)
    )
  end

  def test_capture_in_json_mode_is_not_double_escaped
    template = '{% capture v %}{{ x }}{% endcapture %}{"v": "{{ v }}"}'
    assert_equal('{"v": "a\\"b"}', render(template, { 'x' => 'a"b' }, output_mode: :json))
  end

  def test_echo_tag_is_escaped
    assert_equal('&lt;b&gt;', render('{% echo x %}', { 'x' => '<b>' }, output_mode: :html))
  end

  def test_output_mode_propagates_to_rendered_partials
    file_system = StubFileSystem.new('snippet' => '{{ x }}')
    environment = Liquid::Environment.build(file_system: file_system)
    template = Liquid::Template.parse("{% render 'snippet', x: x %}", environment: environment)
    registers = Liquid::Registers.new(file_system: file_system)
    context = Liquid::Context.build(
      static_environments: { 'x' => '<b>' },
      registers: registers,
      environment: environment
    )
    assert_equal('&lt;b&gt;', template.render!(context, output_mode: :html))
  end

  def test_arrays_are_escaped_element_wise
    assert_equal(
      '&lt;b&gt;&lt;i&gt;',
      render('{{ x }}', { 'x' => ['<b>', '<i>'] }, output_mode: :html)
    )
  end

  def test_invalid_output_mode_raises
    error = assert_raises(ArgumentError) do
      render('{{ x }}', { 'x' => 'a' }, output_mode: :bogus)
    end
    assert_match(/unknown output mode/, error.message)
  end

  def test_safe_value_rejects_unknown_guarantee
    assert_raises(ArgumentError) do
      Liquid::SafeValue.new('x', :safe)
    end
  end

  def test_safe_value_coverage
    assert(Liquid::SafeValue.new('x', :html).safe_for?(:html))
    refute(Liquid::SafeValue.new('x', :html).safe_for?(:html_attribute))
    refute(Liquid::SafeValue.new('x', :html).safe_for?(:json))
    assert(Liquid::SafeValue.new('x', :html_attribute).safe_for?(:html))
    assert(Liquid::SafeValue.new('x', :html_attribute).safe_for?(:html_attribute))
    refute(Liquid::SafeValue.new('x', :html_attribute).safe_for?(:json))
    assert(Liquid::SafeValue.new('x', :json).safe_for?(:json))
    refute(Liquid::SafeValue.new('x', :json).safe_for?(:html))
  end
end
