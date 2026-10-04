# frozen_string_literal: true

require 'test_helper'

class BytecodeTest < Minitest::Test
  include Liquid

  # Renders the same template through both execution paths and asserts the
  # outputs (and collected errors) are identical.
  def assert_paths_agree(template_source, assigns = {}, expected = nil)
    interpreter_template = Template.parse(template_source, line_numbers: true)
    bytecode_template = Template.parse(template_source, line_numbers: true)

    interpreter_output = interpreter_template.render(assigns.dup)
    bytecode_output = bytecode_template.render_bytecode(assigns.dup)

    if expected
      assert_equal(expected, interpreter_output, "interpreter output mismatch")
    end
    assert_equal(interpreter_output, bytecode_output, "bytecode output diverged from interpreter")
    assert_equal(
      interpreter_template.errors.map { |e| [e.class, e.line_number, e.message] },
      bytecode_template.errors.map { |e| [e.class, e.line_number, e.message] },
      "collected errors diverged",
    )
  end

  def test_plain_text
    assert_paths_agree("just plain text\nwith two lines", {}, "just plain text\nwith two lines")
  end

  def test_variable_output_and_filters
    assert_paths_agree(
      "{{ greeting | upcase }} {{ name | default: 'world' }}",
      { 'greeting' => 'hi' },
      "HI world",
    )
  end

  def test_variable_array_flattening
    assert_paths_agree("{{ items }}", { 'items' => %w[a b c] }, "abc")
  end

  def test_assign
    assert_paths_agree(
      "{% assign x = 3 | plus: 4 %}{{ x }}",
      {},
      "7",
    )
  end

  def test_if_elsif_else
    source = "{% if v == 1 %}one{% elsif v == 2 %}two{% else %}other{% endif %}"
    assert_paths_agree(source, { 'v' => 2 }, "two")
    assert_paths_agree(source, { 'v' => 9 }, "other")
    assert_paths_agree(source, { 'v' => 1 }, "one")
  end

  def test_if_with_and_or
    assert_paths_agree("{% if true and false %}a{% elsif false or true %}b{% endif %}", {}, "b")
  end

  def test_if_with_contains
    assert_paths_agree("{% if 'hello' contains 'ell' %}yes{% endif %}", {}, "yes")
  end

  def test_unless
    source = "{% unless v %}falsy{% else %}truthy{% endunless %}"
    assert_paths_agree(source, { 'v' => false }, "falsy")
    assert_paths_agree(source, { 'v' => 1 }, "truthy")
  end

  def test_nested_conditions
    source = "{% for i in (1..3) %}{% if i > 1 %}{{ i }}{% endif %}{% endfor %}"
    assert_paths_agree(source, {}, "23")
  end

  def test_for_basic
    assert_paths_agree("{% for x in items %}{{ x }} {% endfor %}", { 'items' => [1, 2, 3] }, "1 2 3 ")
  end

  def test_for_with_limit_offset_and_reversed
    assert_paths_agree(
      "{% for x in items limit:2 offset:1 %}{{ x }},{% endfor %}",
      { 'items' => [1, 2, 3, 4] },
      "2,3,",
    )
    assert_paths_agree(
      "{% for x in items reversed %}{{ x }}{% endfor %}",
      { 'items' => [1, 2, 3] },
      "321",
    )
  end

  def test_for_range
    assert_paths_agree("{% for i in (3..6) %}{{ i }}-{% endfor %}", {}, "3-4-5-6-")
  end

  def test_for_else
    assert_paths_agree("{% for x in empty %}{{ x }}{% else %}none{% endfor %}", { 'empty' => [] }, "none")
  end

  def test_forloop_metadata_and_parentloop
    source = "{% for i in (1..2) %}{% for j in (1..2) %}" \
      "{{ forloop.parentloop.index }}.{{ forloop.index }} " \
      "{% endfor %}{% endfor %}"
    assert_paths_agree(source, {}, "1.1 1.2 2.1 2.2 ")
  end

  def test_break
    assert_paths_agree(
      "{% for x in (1..5) %}{{ x }}{% if x == 3 %}{% break %}{% endif %}.{% endfor %}|done",
      {},
      "1.2.3|done",
    )
  end

  def test_break_only_exits_inner_loop
    source = "{% for x in (1..2) %}{% for y in (1..3) %}" \
      "{% if y == 2 %}{% break %}{% endif %}({{x}},{{y}})" \
      "{% endfor %}{{x}};{% endfor %}"
    assert_paths_agree(source, {}, "(1,1)1;(2,1)2;")
  end

  def test_continue
    assert_paths_agree(
      "{% for x in (1..5) %}{% if x == 3 %}{% continue %}{% endif %}{{ x }}{% endfor %}",
      {},
      "1245",
    )
  end

  def test_break_outside_loop_halts_like_interpreter
    assert_paths_agree("before{% break %}after", {}, "before")
  end

  def test_continue_outside_loop_halts_like_interpreter
    assert_paths_agree("before{% continue %}after", {}, "before")
  end

  def test_assign_scope_matches_interpreter
    # Assigned loop variables follow the interpreter's exact scope semantics.
    source = "{% for x in (1..2) %}{% assign d = x | times: 2 %}{{ d }} {% endfor %}[{{ d }}]"
    assert_paths_agree(source, {}, "2 4 [4]")
  end

  def test_drops_work_identically
    product = Class.new(Liquid::Drop) do
      def initialize(name)
        super()
        @name = name
      end

      def title
        @name.upcase
      end
    end
    source = "{% for p in products %}{{ p.title }} {% endfor %}"
    assert_paths_agree(
      source,
      { 'products' => [product.new('a'), product.new('b')] },
      "A B ",
    )
  end

  def test_custom_filters_apply
    filter = Module.new do
      def shout(input)
        "#{input}!"
      end
    end

    source = "{{ 'go' | shout }}"
    interpreter_context = Context.new
    bytecode_context = Context.new
    interpreter_context.add_filters(filter)
    bytecode_context.add_filters(filter)
    assert_equal("go!", Template.parse(source).render(interpreter_context))
    assert_equal("go!", Template.parse(source).render_bytecode(bytecode_context))
  end

  def test_whitespace_control
    source = "a\n{{- x -}}\nb"
    assert_paths_agree(source, { 'x' => 'Z' }, "aZb")
  end

  def test_undefined_variable_errors_agree
    source = "{{ missing }}"
    assert_paths_agree(source, {}, "")

    interpreter_template = Template.parse(source, line_numbers: true)
    interpreter_error = assert_raises(UndefinedVariable) { interpreter_template.render!(nil, strict_variables: true) }
    assert_equal(1, interpreter_error.line_number)

    bytecode_template = Template.parse(source, line_numbers: true)
    bytecode_error = assert_raises(UndefinedVariable) { bytecode_template.render_bytecode!(nil, strict_variables: true) }
    assert_equal(interpreter_error.line_number, bytecode_error.line_number)
  end

  def test_condition_error_attributed_to_template_line
    source = "one\n{% if a > 'x' %}yes{% endif %}"
    interpreter_template = Template.parse(source, line_numbers: true)
    bytecode_template = Template.parse(source, line_numbers: true)
    interpreter_output = interpreter_template.render('a' => 1)
    bytecode_output = bytecode_template.render_bytecode('a' => 1)
    assert_equal(interpreter_output, bytecode_output)
    assert_includes(interpreter_output, "comparison of Integer with String failed")
    assert_equal(1, interpreter_template.errors.size)
    assert_equal(1, bytecode_template.errors.size)
    assert_equal(interpreter_template.errors.first.class, bytecode_template.errors.first.class)
    assert_equal(2, bytecode_template.errors.first.line_number)
  end

  def test_render_score_resource_limits_match
    source = "{% for x in (1..100) %}{{ x }}{% endfor %}"

    interpreter_template = Template.parse(source)
    interpreter_context = Context.build(
      environments: { 'x' => nil },
      resource_limits: ResourceLimits.new(render_score_limit: 100),
    )
    assert_raises(MemoryError) { interpreter_template.render!(interpreter_context) }

    bytecode_template = Template.parse(source)
    bytecode_context = Context.build(
      environments: { 'x' => nil },
      resource_limits: ResourceLimits.new(render_score_limit: 100),
    )
    assert_raises(MemoryError) { bytecode_template.render_bytecode!(bytecode_context) }
  end

  def test_assign_score_resource_limits_match
    source = "{% assign x = 'abcdef' %}{{ x }}"

    interpreter_template = Template.parse(source)
    interpreter_context = Context.build(
      resource_limits: ResourceLimits.new(assign_score_limit: 3),
    )
    assert_raises(MemoryError) { interpreter_template.render!(interpreter_context) }

    bytecode_template = Template.parse(source)
    bytecode_context = Context.build(
      resource_limits: ResourceLimits.new(assign_score_limit: 3),
    )
    assert_raises(MemoryError) { bytecode_template.render_bytecode!(bytecode_context) }
  end

  def test_unsupported_tag_is_rejected_at_compile_time
    source = "{% capture x %}hi{% endcapture %}"
    template = Template.parse(source)
    # Ordinary rendering is unaffected.
    assert_equal("", template.render)
    error = assert_raises(Bytecode::Compiler::UnsupportedTagError) { template.compile_bytecode }
    assert_kind_of(SyntaxError, error)
  end

  def test_custom_registered_tag_is_rejected_but_renders_normally
    custom_tag = Class.new(Tag) do
      def render(_context)
        "CUSTOM"
      end
    end
    environment = Environment.build { |env| env.register_tag('mytag', custom_tag) }
    template = Template.parse("{% mytag %}", environment: environment)
    assert_equal("CUSTOM", template.render)
    assert_raises(Bytecode::Compiler::UnsupportedTagError) { template.compile_bytecode }
  end

  def test_program_is_reusable_across_renders
    template = Template.parse("{% for x in items %}{{ x }}{% endfor %}")
    program = template.compile_bytecode
    assert_same(program, template.bytecode_program)
    first = Liquid::Bytecode.render(program, Context.new({ 'items' => [1, 2] }))
    second = Liquid::Bytecode.render(program, Context.new({ 'items' => %w[a b] }))
    assert_equal("12", first)
    assert_equal("ab", second)
  end

  def test_disassemble_lists_instructions
    template = Template.parse("{% if true %}hi{% endif %}")
    disassembly = template.disassemble_bytecode
    assert_includes(disassembly, "jump_if_false")
    assert_includes(disassembly, "halt")
    assert_includes(disassembly, "text")
  end

  def test_render_option_uses_bytecode
    template = Template.parse("{{ 'a' | upcase }}")
    assert_equal("A", template.render({}, bytecode: true))
  end

  def test_program_only_uses_known_opcodes
    # Programs are explicit instruction objects, never generated Ruby source.
    template = Template.parse("{{ x }}{% if x %}a{% endif %}")
    program = template.compile_bytecode
    opcodes = program.instructions.map(&:opcode)
    known = %i[text render_variable assign jump jump_if_false render_score write_score
      for_begin for_inc for_cleanup break_interrupt continue_interrupt halt]
    assert_empty(opcodes - known)
    assert(program.instructions.all? { |i| i.is_a?(Bytecode::Instruction) })
  end
end
