# frozen_string_literal: true

require 'test_helper'

class SourceEditorTest < Minitest::Test
  include Liquid

  def test_rename_output_variable_and_render
    editor = Liquid::SourceEditor.parse("{{ name }}")
    assert_equal(1, editor.rename_variable("name", "user_name"))
    assert_equal("{{ user_name }}", editor.apply)
    assert_equal("bob", editor.render("user_name" => "bob"))
  end

  def test_apply_without_edits_returns_source_verbatim
    source = "line one\r\n  {%- if x -%}\r\n\ttext {{ x }}\r\n{%- endif -%}\r\n"
    editor = Liquid::SourceEditor.parse(source)
    assert_equal(source, editor.apply)
  end

  def test_rename_preserves_crlf_whitespace_control_and_irregular_indentation
    source = "{% assign item = 1 %}\r\n  {%- if item == 1 -%}\r\n\t{{ item }}\r\n{%- endif %}\r\n"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "count")
    renamed = "{% assign count = 1 %}\r\n  {%- if count == 1 -%}\r\n\t{{ count }}\r\n{%- endif %}\r\n"
    assert_equal(renamed, editor.apply)
    assert_equal(render_template(source), render_template(renamed))
  end

  def test_same_name_text_in_strings_is_untouched
    source = "{% assign item = 'item' %}{{ item | default: 'item' }}{% if item == \"item\" %}yes{% endif %}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    renamed = "{% assign thing = 'item' %}{{ thing | default: 'item' }}{% if thing == \"item\" %}yes{% endif %}"
    assert_equal(renamed, editor.apply)
    assert_equal(render_template(source), render_template(renamed))
    assert_equal("itemyes", editor.render)
  end

  def test_same_name_text_in_comments_raw_and_doc_is_untouched
    source = [
      "{% comment %}{{ item }}{% raw %}{{ item }}{% endraw %}{% comment %} item {% endcomment %}{% endcomment %}",
      "{% raw %}{{ item }}{% endraw %}",
      "{% doc %}{{ item }}{% enddoc %}",
      "{% # item %}",
      "{{ item }}",
    ].join
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    renamed = [
      "{% comment %}{{ item }}{% raw %}{{ item }}{% endraw %}{% comment %} item {% endcomment %}{% endcomment %}",
      "{% raw %}{{ item }}{% endraw %}",
      "{% doc %}{{ item }}{% enddoc %}",
      "{% # item %}",
      "{{ thing }}",
    ].join
    assert_equal(renamed, editor.apply)
    assert_equal(render_template(source), render_template(renamed))
  end

  def test_loop_variable_shadowing_global_rename
    source = "{% assign item = 'outer' %}{{ item }}|{% for item in items %}{{ item }};{% endfor %}|{{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "product")
    renamed = "{% assign product = 'outer' %}{{ product }}|{% for product in items %}{{ product }};{% endfor %}|{{ product }}"
    assert_equal(renamed, editor.apply)
    assert_equal(render_template(source, "items" => [1, 2]), render_template(renamed, "items" => [1, 2]))
    assert_equal("outer|1;2;|outer", editor.render("items" => [1, 2]))
  end

  def test_loop_variable_shadowing_scoped_rename
    source = "{% assign item = 'outer' %}{{ item }}|{% for item in items %}{{ item }};{% endfor %}|{{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    loop_binding = editor.bindings.find { |binding| binding.kind == :for }
    editor.rename_variable("item", "product", scope: loop_binding)
    renamed = "{% assign item = 'outer' %}{{ item }}|{% for product in items %}{{ product }};{% endfor %}|{{ item }}"
    assert_equal(renamed, editor.apply)
    assert_equal(render_template(source, "items" => [1, 2]), render_template(renamed, "items" => [1, 2]))
  end

  def test_scoped_rename_accepts_a_scope
    source = "{% assign item = 'outer' %}{{ item }}|{% for item in items %}{{ item }};{% endfor %}|{{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    loop_binding = editor.bindings.find { |binding| binding.kind == :for }
    editor.rename_variable("item", "product", scope: loop_binding.scope)
    renamed = "{% assign item = 'outer' %}{{ item }}|{% for product in items %}{{ product }};{% endfor %}|{{ item }}"
    assert_equal(renamed, editor.apply)
  end

  def test_nested_loops_shadowing
    source = "{% for item in items %}{% for item in item %}{{ item }}{% endfor %}{{ item }}{% endfor %}"
    editor = Liquid::SourceEditor.parse(source)
    inner_binding = editor.bindings.select { |binding| binding.kind == :for }.last
    editor.rename_variable("item", "sub", scope: inner_binding)
    renamed = "{% for item in items %}{% for sub in item %}{{ sub }}{% endfor %}{{ item }}{% endfor %}"
    assert_equal(renamed, editor.apply)
    assigns = { "items" => [[1, 2], [3]] }
    assert_equal(render_template(source, assigns), render_template(renamed, assigns))
  end

  def test_reference_before_definition_is_not_bound_to_it
    source = "{{ item }}{% assign item = 1 %}{{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    assign_binding = editor.bindings.first
    editor.rename_variable("item", "thing", scope: assign_binding)
    assert_equal("{{ item }}{% assign thing = 1 %}{{ thing }}", editor.apply)
  end

  def test_unbound_references_are_renamed_by_global_rename
    source = "{{ item }}{% if item %}x{% endif %}"
    editor = Liquid::SourceEditor.parse(source)
    assert_empty(editor.bindings)
    editor.rename_variable("item", "thing")
    assert_equal("{{ thing }}{% if thing %}x{% endif %}", editor.apply)
  end

  def test_self_assign_scoped_rename_leaves_rhs_to_environment
    source = "{% assign item = item | plus: 1 %}{{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "total", scope: editor.bindings.first)
    assert_equal("{% assign total = item | plus: 1 %}{{ total }}", editor.apply)
  end

  def test_assign_inside_if_is_visible_after_endif
    source = "{% if ok %}{% assign item = 1 %}{% endif %}{{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    assert_equal("{% if ok %}{% assign thing = 1 %}{% endif %}{{ thing }}", editor.apply)
  end

  def test_assign_inside_loop_is_not_visible_after_endfor
    source = "{% for i in items %}{% assign item = 1 %}{% endfor %}{{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    assign_binding = editor.bindings.find { |binding| binding.kind == :assign }
    editor.rename_variable("item", "thing", scope: assign_binding)
    assert_equal("{% for i in items %}{% assign thing = 1 %}{% endfor %}{{ item }}", editor.apply)
  end

  def test_comment_inside_liquid_tag
    source = "{% liquid\n  comment\n  {{ item }}\n  endcomment\n  echo item\n%}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    assert_equal("{% liquid\n  comment\n  {{ item }}\n  endcomment\n  echo thing\n%}", editor.apply)
  end
  def test_dynamic_access_and_static_keys
    source = "{% assign key = 'name' %}{{ user[key] }}{{ user['key'] }}{{ user.key }}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("key", "field")
    renamed = "{% assign field = 'name' %}{{ user[field] }}{{ user['key'] }}{{ user.key }}"
    assert_equal(renamed, editor.apply)
    assigns = { "user" => { "name" => "Alice", "key" => "K" } }
    assert_equal(render_template(source, assigns), render_template(renamed, assigns))
    assert_equal("AliceKK", editor.render(assigns))
  end

  def test_filter_arguments
    source = "{{ item | default: fallback | append: item }}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    editor.rename_variable("fallback", "backup")
    renamed = "{{ thing | default: backup | append: thing }}"
    assert_equal(renamed, editor.apply)
    assigns = { "thing" => nil, "backup" => "b" }
    assert_equal(render_template(renamed, assigns), editor.render(assigns))
  end

  def test_render_tag_arguments_and_alias
    source = "{% render 'snippet', foo: item, bar: 'item' %}{% render 'snippet' with item as item %}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    renamed = "{% render 'snippet', foo: thing, bar: 'item' %}{% render 'snippet' with thing as item %}"
    assert_equal(renamed, editor.apply)
  end

  def test_for_loop_attributes
    source = "{% for item in items reversed limit: limit_num offset: continue %}{{ item }}{% endfor %}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "product")
    editor.rename_variable("limit_num", "max")
    renamed = "{% for product in items reversed limit: max offset: continue %}{{ product }}{% endfor %}"
    assert_equal(renamed, editor.apply)
    assigns = { "items" => [1, 2, 3], "limit_num" => 2, "max" => 2 }
    assert_equal(render_template(source, assigns), render_template(renamed, assigns))
  end

  def test_tablerow
    source = "{% tablerow item in items cols: 2 %}{{ item }}{% endtablerow %}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "product")
    renamed = "{% tablerow product in items cols: 2 %}{{ product }}{% endtablerow %}"
    assert_equal(renamed, editor.apply)
    assigns = { "items" => [1, 2, 3] }
    assert_equal(render_template(source, assigns), render_template(renamed, assigns))
  end

  def test_case_when_and_cycle
    source = "{% case item %}{% when other, 'item' %}A{% else %}B{% endcase %}{% cycle item, 'b' %}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    renamed = "{% case thing %}{% when other, 'item' %}A{% else %}B{% endcase %}{% cycle thing, 'b' %}"
    assert_equal(renamed, editor.apply)
  end

  def test_capture_and_elsif_conditions
    source = "{% capture item %}x{% endcapture %}{% if item == 'y' %}1{% elsif item == 'x' %}2{% else %}3{% endif %}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    renamed = "{% capture thing %}x{% endcapture %}{% if thing == 'y' %}1{% elsif thing == 'x' %}2{% else %}3{% endif %}"
    assert_equal(renamed, editor.apply)
    assert_equal(render_template(source), render_template(renamed))
    assert_equal("2", editor.render)
  end

  def test_increment_decrement_counters_are_a_separate_namespace
    source = "{% increment item %}{% decrement item %}{% assign item = 1 %}{{ item }}"

    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    assert_equal("{% increment item %}{% decrement item %}{% assign thing = 1 %}{{ thing }}", editor.apply)

    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "total", namespace: :counter)
    assert_equal("{% increment total %}{% decrement total %}{% assign item = 1 %}{{ item }}", editor.apply)
  end

  def test_liquid_tag_lines
    source = "{% liquid\n  assign item = 1\n  echo item\n  for item in items\n    echo item\n  endfor\n%}"
    editor = Liquid::SourceEditor.parse(source)
    editor.rename_variable("item", "thing")
    renamed = "{% liquid\n  assign thing = 1\n  echo thing\n  for thing in items\n    echo thing\n  endfor\n%}"
    assert_equal(renamed, editor.apply)
    assigns = { "items" => [7, 8] }
    assert_equal(render_template(source, assigns), render_template(renamed, assigns))
    assert_equal("178", editor.render(assigns))
  end
  def test_overlapping_edits_are_rejected
    editor = Liquid::SourceEditor.parse("hello {{ item }}")
    editor.add_edit(0, 5, "hi")
    assert_raises(Liquid::SourceEditor::OverlappingEditError) { editor.add_edit(4, 8, "x") }
    assert_raises(Liquid::SourceEditor::OverlappingEditError) { editor.add_edit(0, 5, "yo") }
    editor.add_edit(5, 6, "") # adjacent edits do not overlap
    assert_equal("hi{{ item }}", editor.apply)
  end

  def test_conflicting_renames_are_rejected
    editor = Liquid::SourceEditor.parse("{{ item }}")
    editor.rename_variable("item", "thing")
    assert_raises(Liquid::SourceEditor::OverlappingEditError) do
      editor.rename_variable("item", "other")
    end
  end

  def test_edit_out_of_bounds_is_rejected
    editor = Liquid::SourceEditor.parse("{{ item }}")
    assert_raises(Liquid::ArgumentError) { editor.add_edit(-1, 2, "x") }
    assert_raises(Liquid::ArgumentError) { editor.add_edit(0, 100, "x") }
    assert_raises(Liquid::ArgumentError) { editor.add_edit(5, 4, "x") }
  end

  def test_invalid_new_name_is_rejected
    editor = Liquid::SourceEditor.parse("{{ item }}")
    assert_raises(Liquid::SourceEditor::InvalidVariableNameError) { editor.rename_variable("item", "1abc") }
    assert_raises(Liquid::SourceEditor::InvalidVariableNameError) { editor.rename_variable("item", "true") }
    assert_raises(Liquid::SourceEditor::InvalidVariableNameError) { editor.rename_variable("item", "with space") }
  end

  def test_invalid_scope_is_rejected
    editor = Liquid::SourceEditor.parse("{{ item }}")
    assert_raises(Liquid::ArgumentError) { editor.rename_variable("item", "thing", scope: :nope) }
  end

  def test_apply_bang_reanalyzes_source
    editor = Liquid::SourceEditor.parse("{% assign a = 1 %}{{ a }}")
    editor.rename_variable("a", "b")
    editor.apply!
    assert_equal("{% assign b = 1 %}{{ b }}", editor.source)
    editor.rename_variable("b", "c")
    assert_equal("{% assign c = 1 %}{{ c }}", editor.apply)
    assert_equal("1", editor.render)
  end

  def test_apply_revalidates_the_resulting_template
    editor = Liquid::SourceEditor.parse("{{ item }}")
    editor.add_edit(8, 10, "")
    assert_raises(Liquid::SyntaxError) { editor.apply }
  end

  def test_invalid_template_is_rejected_up_front
    assert_raises(Liquid::SyntaxError) { Liquid::SourceEditor.parse("{% raw %}") }
    assert_raises(Liquid::SyntaxError) { Liquid::SourceEditor.parse("{% if %}") }
  end

  def test_reference_spans_cover_exactly_the_variable_name
    source = "h\u00e9llo \u{1F389} {{ item }} {{ item }}"
    editor = Liquid::SourceEditor.parse(source)
    assert_equal(2, editor.references.size)
    editor.references.each do |reference|
      assert_equal("item", source.byteslice(reference.start_offset...reference.end_offset))
    end
    editor.rename_variable("item", "thing")
    assert_equal("h\u00e9llo \u{1F389} {{ thing }} {{ thing }}", editor.apply)
  end

  def test_scope_structure
    source = "{% for item in items %}{{ item }}{% endfor %}"
    editor = Liquid::SourceEditor.parse(source)

    assert(editor.root_scope.root?)
    assert_equal(0, editor.root_scope.start_offset)
    assert_equal(source.bytesize, editor.root_scope.end_offset)

    binding = editor.bindings.first
    assert_equal(:for, binding.kind)
    assert(binding.loop_variable?)
    assert_equal("item", source.byteslice(binding.start_offset...binding.end_offset))
    reference = editor.references.find { |ref| ref.name == "item" }
    assert_equal(binding, reference.binding)
    assert_equal(binding.scope, reference.scope)
    assert_equal(editor.root_scope, binding.scope.parent)
  end

  def test_rename_binding_helper
    editor = Liquid::SourceEditor.parse("{% assign item = 1 %}{{ item }}")
    editor.rename_binding(editor.bindings.first, "thing")
    assert_equal("{% assign thing = 1 %}{{ thing }}", editor.apply)
  end

  def test_counter_binding_has_no_definition_span
    editor = Liquid::SourceEditor.parse("{% increment c %}{% increment c %}")
    binding = editor.bindings_named("c", namespace: :counter).first
    assert_equal(:counter, binding.kind)
    assert_nil(binding.start_offset)
    assert_equal(2, editor.references.size)
    assert(editor.references.all? { |reference| reference.binding.equal?(binding) })
  end

  private

  def render_template(source, assigns = {})
    Liquid::Template.parse(source).render(assigns)
  end
end
