# frozen_string_literal: true

require 'test_helper'

class BytecodeMemoryErrorTest < Minitest::Test
  include Liquid

  def test_memory_error_inside_for_body
    source = '{% for x in items %}{{ x }}{% endfor %}'
    assigns = { 'items' => Array.new(100, 'x' * 50) }

    interpreter = Template.parse(source)
    interpreter.resource_limits.render_length_limit = 120
    assert_raises(MemoryError) { interpreter.render!(assigns) }

    bytecode = Template.parse(source)
    bytecode.resource_limits.render_length_limit = 120
    assert_raises(MemoryError) { bytecode.render!(assigns, bytecode: true) }
  end

  def test_memory_error_inside_nested_if
    source = '{% for x in items %}{% if true %}{{ x }}{% endif %}{% endfor %}'
    assigns = { 'items' => Array.new(100, 'y' * 50) }

    interpreter = Template.parse(source)
    interpreter.resource_limits.render_length_limit = 40
    assert_raises(MemoryError) { interpreter.render!(assigns) }

    bytecode = Template.parse(source)
    bytecode.resource_limits.render_length_limit = 40
    assert_raises(MemoryError) { bytecode.render!(assigns, bytecode: true) }
  end

  def test_render_score_iteration_charge_matches
    source = '{% for x in items limit: 2 %}x{% endfor %}'
    assigns = { 'items' => Array.new(50, 1) }

    interpreter = Template.parse(source)
    interpreter.render!(assigns)
    interpreter_score = interpreter.resource_limits.render_score

    bytecode = Template.parse(source)
    bytecode.render!(assigns, bytecode: true)
    bytecode_score = bytecode.resource_limits.render_score

    assert_equal(interpreter_score, bytecode_score)
  end
end
