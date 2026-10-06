# frozen_string_literal: true

require 'test_helper'

class SourceMapUnitTest < Minitest::Test
  include Liquid

  def map(source)
    Template.parse(source).source_map
  end

  def test_reconstruct_is_byte_exact
    source = "A{{ x }}B{%- if y -%}C{% endif %}D\r\n\t{% raw %}{{ z }}{% endraw %}"
    source_map = map(source)
    assert source_map.byte_exact?
    assert_equal(source, source_map.reconstruct)
  end

  def test_parsing_keeps_original_source_bytes
    source = "{{x}}\r\n{%- assign y = 1 -%}\t"
    template = Template.parse(source.dup)
    assert_equal(source, template.source)
  end

  def test_reports_occurrences_with_binding_and_reference_kinds
    source_map = map("{% assign x = 1 %}{{ x }}")
    kinds = source_map.occurrences.map(&:kind)
    assert_equal([:binding, :reference], kinds)
  end

  def test_ignores_identifiers_inside_strings
    source_map = map(%q({{ 'x' | replace: 'x', 'a x b' }}))
    assert source_map.occurrences.none? { |occurrence| occurrence.name == 'x' }
  end

  def test_ignores_dot_property_names
    source_map = map("{{ product.x }} and {{ x.y }}")
    names = source_map.occurrences.map(&:name)
    refute_includes(names, "product.x")
    assert_equal(%w[product x], names)
  end

  def test_ignores_filter_names_and_keyword_arguments
    source_map = map("{{ x | default: 1 | join: y, limit: 2 }}")
    names = source_map.occurrences.map(&:name)
    assert_equal(%w[x y], names)
  end

  def test_ignores_dynamic_quoted_bracket_access
    source_map = map(%q({{ hash['x'] }}{{ items[other] }}))
    names = source_map.occurrences.map(&:name)
    assert_equal(%w[hash items other], names)
  end

  def test_ignores_raw_comment_and_inline_comment_bodies
    source = "{{ x }}{% raw %}{{ x }}{% endraw %}{% comment %}{{ x }}{% endcomment %}{% # {{ x }} %}"
    source_map = map(source)
    assert_equal(1, source_map.occurrences.length)
    assert_equal("x", source_map.occurrences.first.name)
  end

  def test_nested_comment_balance
    source = "{% comment %}a {% comment %}b{% endcomment %} c {% endcomment %}{{ x }}"
    source_map = map(source)
    assert_equal(["x"], source_map.occurrences.map(&:name))
    assert source_map.byte_exact?
  end

  def test_raw_with_nested_looking_liquid_is_opaque
    source = "{% raw %}{% if x %}{{ x }}{% endif %}{% endraw %}{{ x }}"
    source_map = map(source)
    assert_equal(["x"], source_map.occurrences.map(&:name))
  end

  def test_loop_variable_shadows_outer_binding
    source = "{{ x }}{% for x in items %}{{ x }}{% endfor %}{{ x }}"
    source_map = map(source)
    bindings = source_map.bindings_named("x")
    assert_equal(2, bindings.length)
    assert(bindings.any?(&:loop_binding))
  end

  def test_collection_expression_resolves_to_outer_scope
    source_map = map("{% for item in items %}{{ item }}{% endfor %}")
    names = source_map.occurrences.map(&:name)
    assert_includes(names, "items")
    item_binding = source_map.bindings_named("item").first
    refute_includes(item_binding.occurrences.map(&:name), "items")
  end

  def test_binding_for_resolves_shadowing_by_offset
    source = "{{ x }}{% for x in items %}{{ x }}{% endfor %}"
    source_map = map(source)
    inner_offset = source.index("{{ x }}", source.index("for")) + 3
    outer_offset = 2
    assert source_map.binding_for("x", inner_offset).loop_binding
    refute source_map.binding_for("x", outer_offset).loop_binding
  end

  def test_occurrence_at_returns_enclosing_occurrence
    source = "{{ alpha }}"
    source_map = map(source)
    occurrence = source_map.occurrence_at(4)
    assert_equal("alpha", occurrence&.name)
    assert_nil(source_map.occurrence_at(0))
  end

  def test_predefined_loop_objects_are_not_variables
    source_map = map("{% for item in items %}{{ forloop.index }}{% endfor %}")
    names = source_map.occurrences.map(&:name)
    refute_includes(names, "forloop")
    assert_includes(names, "item")
  end

  def test_assign_target_binds_in_enclosing_scope
    source_map = map("{% if true %}{% assign x = 1 %}{% endif %}{{ x }}")
    assert_equal(1, source_map.bindings_named("x").length)
  end

  def test_assign_inside_loop_binds_to_outer_scope
    source_map = map("{% assign x = 0 %}{% for i in items %}{% assign x = 1 %}{{ x }}{% endfor %}")
    assert_equal(1, source_map.bindings_named("x").length)
    assert_equal(3, source_map.bindings_named("x").first.occurrences.length)
  end

  def test_capture_and_counter_tags_bind_their_target
    source_map = map("{% capture greeting %}hi{% endcapture %}{% increment counter %}")
    names = source_map.occurrences.map(&:name)
    assert_includes(names, "greeting")
    assert_includes(names, "counter")
  end

  def test_render_alias_is_not_a_local_reference
    source_map = map("{% render 'card' with product as card %}")
    names = source_map.occurrences.map(&:name)
    assert_includes(names, "product")
    refute_includes(names, "card")
  end

  def test_liquid_tag_lines_are_analyzed
    source = "{% liquid\nassign x = 1\necho x\nfor item in items\necho item\nendfor\n%}"
    source_map = map(source)
    assert source_map.byte_exact?
    assert_equal(1, source_map.bindings_named("x").length)
    assert_equal(1, source_map.bindings_named("item").length)
  end

  def test_offsets_point_to_exact_source_bytes
    source = "ab{{ x }}cd"
    source_map = map(source)
    occurrence = source_map.occurrences.first
    assert_equal("x", source.byteslice(occurrence.start_byte, occurrence.end_byte - occurrence.start_byte))
  end
end
