# frozen_string_literal: true

require 'test_helper'

class SourceEditorTest < Minitest::Test
  include Liquid

  def render_equivalent?(source, assigns, renamed_assigns, &block)
    original = Template.parse(source.dup)
    expected = original.render!(assigns)
    edited = block.call(Template.parse(source.dup))
    actual = edited.render!(renamed_assigns)
    assert_equal(expected, actual)
    [expected, actual, edited]
  end

  def test_rename_global_variable_preserves_all_other_bytes
    source = "Title: {{ title }}\r\n{%- assign label = title -%}\t\r\n"
    template = Template.parse(source.dup)
    template.rename_variable("title", "heading")
    expected = "Title: {{ heading }}\r\n{%- assign label = heading -%}\t\r\n"
    assert_equal(expected, template.source)
  end

  def test_rename_renders_identically_with_renamed_data
    source = "{{ title }}{% for item in items %}{{ item }} {{ title }}{% endfor %}"
    assigns = { "title" => "T", "items" => %w[a b] }
    renamed = { "heading" => "T", "items" => %w[a b] }
    _expected, actual, edited = render_equivalent?(source, assigns, renamed) do |template|
      template.rename_variable("title", "heading")
    end
    assert_equal("Ta Tb T", actual)
    refute_match(/title/, edited.source)
  end

  def test_rename_is_scoped_to_inner_loop_binding
    source = "{{ x }}{% for x in items %}{{ x }}{% endfor %}{{ x }}"
    template = Template.parse(source.dup)
    inner = source.index("{{ x }}", source.index("for")) + 3
    template.rename_variable("x", "y", at_byte: inner)
    assert_equal("{{ x }}{% for y in items %}{{ y }}{% endfor %}{{ x }}", template.source)
  end

  def test_rename_loop_variable_keeps_collection_and_outer_shadow
    source = "{{ item }}{% for item in item.list %}{{ item.name }}{% endfor %}"
    assigns = { "item" => { "list" => [{ "name" => "a" }] } }
    edited = Template.parse(source.dup)
    inner = source.index("item", source.index("for"))
    edited.rename_variable("item", "product", at_byte: inner)
    actual = edited.render!(assigns)
    assert_equal(Template.parse(source).render!(assigns), actual)
    assert_includes(edited.source, "item.list")
  end

  def test_rename_does_not_touch_strings_raw_or_comments
    source = %q({{ x }}|{% raw %}{{ x }}{% endraw %}|{% comment %}{{ x }}{% endcomment %}|{{ "x" }})
    template = Template.parse(source.dup)
    template.rename_variable("x", "z")
    assert_equal(%q({{ z }}|{% raw %}{{ x }}{% endraw %}|{% comment %}{{ x }}{% endcomment %}|{{ "x" }}), template.source)
  end

  def test_rename_does_not_touch_dynamic_key_or_property
    source = %q({{ x.name }}{{ hash["x"] }}{{ dyn[x] }})
    template = Template.parse(source.dup)
    template.rename_variable("x", "y")
    assert_equal(%q({{ y.name }}{{ hash["x"] }}{{ dyn[y] }}), template.source)
  end

  def test_whitespace_control_hyphens_and_crlf_survive
    source = "{{- x -}}\r\n{%- if x -%}\r\n  {{- x -}}\r\n{%- endif -%}"
    template = Template.parse(source.dup)
    template.rename_variable("x", "renamed")
    assert_includes(template.source, "{{- renamed -}}")
    assert_includes(template.source, "{%- if renamed -%}")
    assert_includes(template.source, "\r\n")
    assert_includes(template.source, "  {{- renamed -}}")
  end

  def test_irregular_indentation_is_preserved
    source = "\t{{x}}\n    {{   x   }}\n\t\t{{x}}"
    template = Template.parse(source.dup)
    template.rename_variable("x", "q")
    assert_equal("\t{{q}}\n    {{   q   }}\n\t\t{{q}}", template.source)
  end

  def test_overlapping_edits_are_rejected
    template = Template.parse("{{ alpha }}")
    editor = template.source_editor
    error = assert_raises(OverlappingEditError) do
      # Build two edits covering shared bytes and apply them together via the
      # low-level compose path used internally.
      edits = [
        SourceEditor::Edit.new(start_byte: 3, end_byte: 8, replacement: "aa"),
        SourceEditor::Edit.new(start_byte: 5, end_byte: 9, replacement: "bb"),
      ]
      editor.send(:apply_edits, edits)
    end
    assert_match(/overlapping/i, error.message)
    assert_equal("{{ alpha }}", template.source)
  end

  def test_non_overlapping_adjacent_edits_are_allowed
    template = Template.parse("{{ a }}{{ b }}")
    editor = template.source_editor
    editor.replace(3, 4, "x")
    editor.replace(10, 11, "y")
    assert_equal("{{ x }}{{ y }}", template.source)
  end

  def test_reparse_after_edit_refreshes_bindings
    template = Template.parse("{% assign x = 1 %}{{ x }}")
    template.rename_variable("x", "y")
    map = template.source_map(rebuild: true)
    assert_equal(%w[y y], map.occurrences.map(&:name))
    assert_equal("1", template.render!)
  end

  def test_rename_invalid_identifier_raises
    template = Template.parse("{{ x }}")
    assert_raises(ArgumentError) { template.rename_variable("x", "1bad") }
    assert_equal("{{ x }}", template.source)
  end

  def test_rename_unknown_variable_raises
    template = Template.parse("{{ x }}")
    assert_raises(ArgumentError) { template.rename_variable("missing", "z") }
  end

  def test_rename_everywhere_handles_shadowed_bindings
    source = "{{ x }}{% for x in xs %}{{ x }}{% endfor %}"
    template = Template.parse(source.dup)
    template.source_editor.rename_variable_everywhere("x", "renamed")
    assert_equal("{{ renamed }}{% for renamed in xs %}{{ renamed }}{% endfor %}", template.source)
  end

  def test_source_is_not_mutation_aliased_to_input
    input = +"{{ x }}"
    template = Template.parse(input)
    refute_same(input, template.source)
  end

  def test_raw_body_bytes_remain_identical_after_edit
    raw = "\r\n\t{% if weird%} {{ spaced }} {%endif%}\r\n"
    source = "{{ x }}{% raw %}" + raw + "{% endraw %}"
    template = Template.parse(source.dup)
    template.rename_variable("x", "z")
    assert_includes(template.source, raw)
  end

  def test_syntax_breaking_edit_is_rolled_back
    source = "{{ x }}"
    template = Template.parse(source.dup)
    assert_raises(SyntaxError) do
      template.source_editor.replace(0, source.bytesize, "{% assign %}")
    end
    assert_equal(source, template.source)
    assert template.source_map.byte_exact?
    assert_equal(1, template.source_map.occurrences.length)
  end
end
