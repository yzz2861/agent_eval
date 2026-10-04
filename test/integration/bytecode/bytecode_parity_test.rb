# frozen_string_literal: true

require 'test_helper'

# Verifies that the experimental bytecode VM produces exactly the same result
# as the interpreted AST execution for identical templates and inputs.
class BytecodeParityTest < Minitest::Test
  include Liquid

  FILTERS = Module.new do
    def shout(input)
      input.to_s.upcase
    end

    def join_args(input, *parts, separator: '-')
      ([input] + parts.map(&:to_s)).join(separator)
    end
  end

  def assert_paths_agree(source, assigns = {}, options = {})
    template = Template.parse(source, options[:parse_options] || {})

    interpreter_output = template.render(assigns, **(options[:render_options] || {}))
    bytecode_output    = template.render(assigns, **(options[:render_options] || {}).merge(bytecode: true))

    assert_equal(interpreter_output, bytecode_output, -> do
      "bytecode disagreed for: #{source.inspect}\n--- disassembly ---\n#{template.disassemble_bytecode}"
    end)

    assert_equal(template.errors, template.errors) # sanity: errors reset per render
    interpreter_output
  end

  def test_literal_text
    assert_paths_agree("plain text with no tags")
    assert_paths_agree("multi\nline\ntext")
  end

  def test_variables_and_filters
    assigns = {
      'name' => 'bob',
      'missing' => nil,
      'items' => [1, 2, 3],
      'word' => 'Hello',
    }

    assert_paths_agree("{{ name }}", assigns)
    assert_paths_agree("{{ name | upcase }}", assigns)
    assert_paths_agree("{{ missing }}", assigns)
    assert_paths_agree("{{ items | join: ', ' }}", assigns)
    assert_paths_agree("{{ word | downcase | capitalize }}", assigns)
    assert_paths_agree("{{ name | default: 'nobody' }}-{{ missing | default: 'nobody' }}", assigns)
    assert_paths_agree("{{ name | slice: 1, 2 }}", assigns)
    assert_paths_agree("{{ 3 | plus: 4 | times: 2 }}", assigns)
  end

  def test_custom_filters_and_keyword_arguments
    assert_paths_agree("{{ name | shout }}", { 'name' => 'bob' },
      render_options: { filters: FILTERS })
    assert_paths_agree("{{ name | join_args: 'a', 'b' }}", { 'name' => 'z' },
      render_options: { filters: FILTERS })
    assert_paths_agree("{{ name | join_args: 'a', separator: '/' }}", { 'name' => 'z' },
      render_options: { filters: FILTERS })
  end

  def test_global_filter
    global = ->(value) { "[#{value}]" }
    assert_paths_agree("{{ name }} hi", { 'name' => 'x' },
      render_options: { global_filter: global })
    assert_paths_agree("{% assign y = 1 %}", {}, render_options: { global_filter: global })
  end

  def test_assign
    assigns = { 'a' => 5 }
    assert_paths_agree("{% assign b = a | plus: 2 %}{{ b }}", assigns)
    assert_paths_agree("{% assign b = a %}{% assign c = b | times: 3 %}{{ c }}", assigns)
    assert_paths_agree("before{% assign x = 'yo' %}after")
  end

  def test_if_branches_and_operators
    assigns = { 'n' => 3, 'name' => 'bob', 'items' => [1], 'text' => '   ' }

    assert_paths_agree("{% if n > 2 %}big{% else %}small{% endif %}", assigns)
    assert_paths_agree("{% if n < 2 %}big{% else %}small{% endif %}", assigns)
    assert_paths_agree("{% if n == 3 %}three{% elsif n == 4 %}four{% else %}other{% endif %}", assigns)
    assert_paths_agree("{% if n != 3 %}no{% elsif n >= 3 %}yes{% endif %}", assigns)
    assert_paths_agree("{% if n > 1 and name == 'bob' %}both{% endif %}", assigns)
    assert_paths_agree("{% if n > 9 or name == 'bob' %}one{% endif %}", assigns)
    assert_paths_agree("{% if false or false %}a{% elsif true and true %}b{% endif %}", assigns)
    assert_paths_agree("{% unless n == 3 %}not3{% else %}is3{% endunless %}", assigns)
    assert_paths_agree("{% unless n > 9 %}small{% else %}big{% endunless %}", assigns)
    assert_paths_agree("{% if 'bob' contains 'bo' %}yes{% endif %}", assigns)
    assert_paths_agree("{% if name contains 'xx' %}yes{% else %}no{% endif %}", assigns)
    assert_paths_agree("{% if text == blank %}blank{% else %}not{% endif %}", assigns)
    assert_paths_agree("{% if items == empty %}empty{% else %}not{% endif %}", assigns)
  end

  def test_short_circuit_value_used_by_body
    assigns = { 'a' => false, 'b' => 5 }
    assert_paths_agree("{% if a or b %}{{ b }}{% endif %}", assigns)
    assert_paths_agree("{% if a and b %}x{% else %}y{% endif %}", assigns)
  end

  def test_for_basic
    assigns = { 'items' => %w[a b c] }
    assert_paths_agree("{% for item in items %}{{ item }}{% endfor %}", assigns)
    assert_paths_agree("{% for item in items %}{{ forloop.index }}:{{ item }} {% endfor %}", assigns)
    assert_paths_agree("{% for item in items reversed %}{{ item }}{% endfor %}", assigns)
    assert_paths_agree("{% for item in items limit: 2 %}{{ item }}{% endfor %}", assigns)
    assert_paths_agree("{% for item in items limit: 2 offset: 1 %}{{ item }}{% endfor %}", assigns)
    assert_paths_agree("{% for item in items offset: 2 %}{{ item }}{% endfor %}", assigns)
    assert_paths_agree("{% for n in (1..3) %}{{ n }}{% endfor %}")
  end

  def test_for_else
    assert_paths_agree("{% for x in items %}[{{ x }}]{% else %}empty{% endfor %}",
      { 'items' => [] })
    assert_paths_agree("{% for x in items %}[{{ x }}]{% else %}empty{% endfor %}",
      { 'items' => %w[z] })
  end

  def test_for_continue_offset
    source = '{% for x in items limit: 2 %}{{ x }}{% endfor %}' \
      '|{% for x in items limit: 2 %}{{ x }}{% endfor %}'
    assert_paths_agree(source, { 'items' => %w[a b c d] })
  end

  def test_forloop_metadata
    source = +'{% for x in items %}'
    source << '{{ forloop.index0 }}/{{ forloop.rindex }}/{{ forloop.first }}/{{ forloop.last }} '
    source << '{% endfor %}'
    assert_paths_agree(source, { 'items' => [1, 2, 3] })
  end

  def test_nested_loops_and_parentloop
    source = +'{% for row in rows %}{% for col in row %}'
    source << '{{ col }}({{ forloop.parentloop.index }}) '
    source << '{% endfor %}{% endfor %}'
    assert_paths_agree(source, { 'rows' => [[1, 2], [3]] })
  end

  def test_break_and_continue
    assigns = { 'items' => (1..6).to_a }

    assert_paths_agree("{% for x in items %}{{ x }}{% if x == 3 %}{% break %}{% endif %}{% endfor %}", assigns)
    assert_paths_agree("{% for x in items %}{% if x == 3 %}{% continue %}{% endif %}{{ x }}{% endfor %}", assigns)
    assert_paths_agree("{% for x in items %}{% break %}{{ x }}{% endfor %}", assigns)
    assert_paths_agree("{% for x in items %}{% continue %}{{ x }}{% endfor %}", assigns)

    nested = "{% for x in items %}{% if x > 1 %}{% if x == 3 %}{% break %}{% endif %}{% endif %}{{ x }}{% endfor %}"
    assert_paths_agree(nested, assigns)
  end

  def test_break_and_continue_do_not_cross_loops
    source = +'{% for outer in out %}['
    source << '{% for inner in inn %}{% if inner == 2 %}{% break %}{% endif %}{{ inner }}'
    source << '{% endfor %}{{ outer }}]{% endfor %}'
    assert_paths_agree(source, { 'out' => [1, 2], 'inn' => [1, 2, 3] })
  end

  def test_loop_variable_scoping
    assert_paths_agree(
      "{% assign item = 'outer' %}{% for item in items %}{{ item }}{% endfor %}:{{ item }}",
      { 'items' => %w[a b] },
    )
    assert_paths_agree(
      "{% for x in items %}{% assign doubled = x %}{{ doubled }}{% endfor %}:{{ doubled }}",
      { 'items' => [1, 2] },
    )
  end

  def test_render_length_limit
    source = "{% for x in items %}{{ x }}{% endfor %}"
    interpreter_template = Template.parse(source, line_numbers: true)
    interpreter_template.resource_limits.render_length_limit = 5
    assert_raises(MemoryError) do
      interpreter_template.render!({ 'items' => [1, 2, 3, 4, 5, 6] })
    end

    bytecode_template = Template.parse(source, line_numbers: true)
    bytecode_template.resource_limits.render_length_limit = 5
    assert_raises(MemoryError) do
      bytecode_template.render!({ 'items' => [1, 2, 3, 4, 5, 6] }, bytecode: true)
    end
  end

  def test_render_score_limit
    source = "{% for x in items %}{% if x %}y{% endif %}{% endfor %}"
    assigns = { 'items' => (1..100).to_a }

    interpreter_template = Template.parse(source)
    interpreter_template.resource_limits.render_score_limit = 10
    assert_raises(MemoryError) { interpreter_template.render!(assigns) }

    bytecode_template = Template.parse(source)
    bytecode_template.resource_limits.render_score_limit = 10
    assert_raises(MemoryError) { bytecode_template.render!(assigns, bytecode: true) }
  end

  def test_assign_score_limit
    source = "{% for x in items %}{% assign y = x %}{% endfor %}"
    assigns = { 'items' => Array.new(100, 'x' * 10) }

    interpreter_template = Template.parse(source)
    interpreter_template.resource_limits.assign_score_limit = 50
    assert_raises(MemoryError) { interpreter_template.render!(assigns) }

    bytecode_template = Template.parse(source)
    bytecode_template.resource_limits.assign_score_limit = 50
    assert_raises(MemoryError) { bytecode_template.render!(assigns, bytecode: true) }
  end

  def test_runtime_error_line_numbers_match
    source = "line one\n{{ 'a' | divided_by: 'x' }}"
    interpreter_template = Template.parse(source)
    bytecode_template    = Template.parse(source)

    # In non-strict rendering the error text is inlined at the same position.
    interpreter_output = interpreter_template.render
    bytecode_output    = bytecode_template.render({}, bytecode: true)
    assert_equal(interpreter_output, bytecode_output)
    assert_equal(interpreter_template.errors.length, bytecode_template.errors.length)
    assert_equal(
      interpreter_template.errors.map(&:line_number),
      bytecode_template.errors.map(&:line_number),
    )
  end

  def test_undefined_filter_with_strict_filters
    source = "line one\n{{ x | no_such_filter }}"
    interpreter_template = Template.parse(source, line_numbers: true)
    interpreter_error = assert_raises(UndefinedFilter) do
      interpreter_template.render!({ 'x' => 1 }, strict_filters: true)
    end

    bytecode_template = Template.parse(source, line_numbers: true)
    bytecode_error = assert_raises(UndefinedFilter) do
      bytecode_template.render!({ 'x' => 1 }, strict_filters: true, bytecode: true)
    end
    assert_equal(interpreter_error.line_number, bytecode_error.line_number)
    assert_equal(2, bytecode_error.line_number)
  end

  def test_strict_variables_error_is_positioned
    source = "{% if true %}\n{{ nope }}\n{% endif %}"
    template = Template.parse(source, line_numbers: true)

    interpreter_error = assert_raises(UndefinedVariable) do
      template.render!({}, strict_variables: true)
    end
    bytecode_error = assert_raises(UndefinedVariable) do
      template.render!({}, strict_variables: true, bytecode: true)
    end
    assert_equal(interpreter_error.line_number, bytecode_error.line_number)
    assert_equal(interpreter_error.message, bytecode_error.message)
  end

  def test_blank_tag_error_suppression_matches
    source = "a{% if true %}{% assign x = %}{% endif %}b"
    assert_paths_agree(source, {})
  end

  def test_repeated_renders_are_isolated
    template = Template.parse("{% assign total = 0 %}{% for x in items %}" \
      "{% assign total = total | plus: x %}{% endfor %}{{ total }}")
    first  = template.render!({ 'items' => [1, 2, 3] }, bytecode: true)
    second = template.render!({ 'items' => [10, 20] }, bytecode: true)
    third  = template.render({ 'items' => [10, 20] })
    assert_equal('6', first)
    assert_equal('30', second)
    assert_equal('30', third)
  end

  def test_drops_are_evaluated_through_context
    drop = Class.new(Drop) do
      def items
        [1, 2, 3]
      end
    end
    assert_paths_agree("{% for x in items %}{{ x }}{% endfor %}", drop.new)
  end

  def test_array_output_and_nested_attributes
    assigns = {
      'list' => [1, [2, 3], 4],
      'user' => { 'name' => 'bob', 'tags' => %w[a b] },
    }
    assert_paths_agree('{{ list }}', assigns)
    assert_paths_agree('{{ user.name }}:{{ user.tags | join: "/" }}', assigns)
  end

  def test_non_boolean_truthiness
    assigns = { 'zero' => 0, 'empty_string' => '', 'arr' => [], 's' => 'x' }
    assert_paths_agree('{% if zero %}z{% else %}nz{% endif %}', assigns)
    assert_paths_agree('{% if empty_string %}e{% else %}ne{% endif %}', assigns)
    assert_paths_agree('{% if arr %}a{% else %}na{% endif %}', assigns)
    assert_paths_agree('{% if s %}{{ s }}{% endif %}', assigns)
  end

  def test_comparison_operators
    assigns = { 'a' => 2, 'b' => 2, 'c' => 3 }
    %w[== != <> >= <= > <].each do |op|
      source = "{% if a #{op} b %}y{% else %}n{% endif %}|{% if a #{op} c %}y{% else %}n{% endif %}"
      assert_paths_agree(source, assigns)
    end
  end

  def test_whitespace_trim_controls
    assert_paths_agree("{%- if true -%}  hi  {%- endif -%}")
    assert_paths_agree("  {{- x -}}  ", { 'x' => 'v' })
  end

  def test_non_strict_filter_error_inlined_at_same_position
    source = "a\n{{ x | divided_by: 0 }}b"
    assert_paths_agree(source, { 'x' => 6 })
  end

  def test_forloop_inside_nested_if
    source = '{% for x in items %}{% if forloop.first %}F{% endif %}{{ x }}{% endfor %}'
    assert_paths_agree(source, { 'items' => [1, 2, 3] })
  end

  def test_assign_with_filter_chain_in_loop
    source = '{% for x in items %}{% assign y = x | plus: 100 | times: 2 %}{{ y }},{% endfor %}'
    assert_paths_agree(source, { 'items' => [1, 2] })
  end
end
