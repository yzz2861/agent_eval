# frozen_string_literal: true

require 'test_helper'

class MacroTagTest < Minitest::Test
  include Liquid

  def test_macro_renders_with_named_and_default_arguments
    template = <<~LIQUID
      {%- macro greet(name, greeting: 'Hi', mark: '!') -%}
      {{ greeting }}, {{ name }}{{ mark }}
      {%- endmacro -%}
      {% call greet(name: 'Ada') -%}
      {% call greet(name: 'Lin', greeting: 'Hello') -%}
    LIQUID

    assert_template_result('Hi, Ada!Hello, Lin!', template)
  end

  def test_macro_uses_definition_scope_not_caller_scope
    template = <<~LIQUID
      {%- macro show -%}
      [{{ word }}|{{ item }}|{% assign word = 'inside' %}{{ word }}]
      {%- endmacro -%}
      {%- for item in (1..1) -%}
        {%- for word in ('caller'..'caller') -%}
          {%- call show -%}
        {%- endfor -%}
      {%- endfor -%}
      [{{ word }}]
    LIQUID

    assert_template_result("[definition||inside][definition]\n", template, { 'word' => 'definition' })
  end

  def test_macro_arguments_are_evaluated_in_caller_scope
    template = <<~LIQUID
      {%- macro greet(name) -%}Hi {{ name }}{%- endmacro -%}
      {%- for item in (1..2) -%}
        {%- call greet(name: item) -%}
      {%- endfor -%}
    LIQUID

    assert_template_result('Hi 1Hi 2', template)
  end

  def test_assign_inside_a_macro_is_local_to_the_call
    template = <<~LIQUID
      {%- assign value = 'outer' -%}
      {%- macro change(copy) -%}{{ copy }}{% assign copy = 'inside' %}{{ copy }}{%- endmacro -%}
      {%- call change(copy: value) -%}
      {% call change(copy: value) -%}{{- value -}}
    LIQUID

    assert_template_result('outerinsideouterinsideouter', template)
  end

  def test_macro_arguments_support_filters
    template = "{% macro shout(value) %}{{ value }}{% endmacro %}{% call shout(value: 'hi' | upcase) %}"

    assert_template_result('HI', template)
  end

  def test_macro_arguments_support_filters_with_multiple_arguments
    template = "{% macro shout(value, suffix) %}{{ value }}{{ suffix }}{% endmacro %}{% call shout(value: 'a,b' | replace: 'a', 'b', suffix: '!') %}"

    assert_template_result('b,b!', template)
  end

  def test_macro_default_arguments_are_evaluated_in_definition_scope
    template = <<~LIQUID
      {%- assign prefix = 'outer' -%}
      {%- macro label(value, prefix: prefix) -%}{{ prefix }}:{{ value }}{%- endmacro -%}
      {%- for prefix in ('caller'..'caller') -%}
        {%- call label(value: 'x') -%}
      {%- endfor -%}
    LIQUID

    assert_template_result('outer:x', template)
  end

  def test_nested_macros_share_the_outer_macro_lexical_scope
    template = <<~LIQUID
      {%- macro outer(prefix, suffix: '!') -%}
        {%- macro inner(value) -%}{{ prefix }}:{{ value }}{{ suffix }}{%- endmacro -%}
        {%- call inner(value: 'nested') -%}
      {%- endmacro -%}
      {%- call outer(prefix: 'Hi') -%}
    LIQUID

    assert_template_result('Hi:nested!', template)
  end

  def test_same_named_macro_in_a_loop_shadows_the_outer_macro_only_inside_the_loop
    template = <<~LIQUID
      {%- macro answer -%}outer{%- endmacro -%}
      {%- for item in (1..1) -%}
        {%- macro answer -%}inner {{ item }}{%- endmacro -%}
        {%- call answer -%}
      {%- endfor -%}
      {%- call answer -%}
    LIQUID

    assert_template_result('inner 1outer', template)
  end

  def test_recursive_macro_calls_use_the_existing_stack_limit
    template = <<~LIQUID
      {%- macro count(n) -%}
        {{ n }}{%- unless n == 0 -%}{%- call count(n: n | minus: 1) -%}{%- endunless -%}
      {%- endmacro -%}
      {%- call count(n: 3) -%}
    LIQUID

    assert_template_result('3210', template)

    recursive_template = <<~LIQUID
      {%- macro loop -%}{%- call loop -%}{%- endmacro -%}
      {%- call loop -%}
    LIQUID

    assert_raises(StackLevelError) do
      Template.parse(recursive_template).render!
    end
  end

  def test_missing_arguments_raise_a_clear_error
    template = %q({% macro greet(name, greeting) %}{{ greeting }} {{ name }}{% endmacro %}{% call greet(name: 'Ada') %})

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_match("macro 'greet' is missing argument(s): greeting", error.message)
  end

  def test_extra_arguments_raise_a_clear_error
    template = %q({% macro greet(name) %}{{ name }}{% endmacro %}{% call greet(name: 'Ada', greeting: 'Hi') %})

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_match("macro 'greet' does not accept argument(s): greeting", error.message)
  end

  def test_duplicate_parameters_raise_a_syntax_error
    assert_syntax_error('{% macro greet(name, name) %}{% endmacro %}')
  end

  def test_duplicate_call_arguments_raise_a_syntax_error
    template = %q({% macro greet(name) %}{% endmacro %}{% call greet(name: 'Ada', name: 'Lin') %})
    assert_syntax_error(template)
  end

  def test_positional_call_arguments_are_not_allowed
    assert_syntax_error('{% macro greet(name) %}{% endmacro %}{% call greet("Ada") %}')
  end

  def test_call_only_invokes_defined_macros
    assert_raises(ArgumentError) do
      Template.parse('{% call missing %}').render!
    end

    assert_raises(ArgumentError) do
      Template.parse('{% assign greet = 1 %}{% call greet %}').render!
    end
  end

  def test_macro_data_cannot_be_used_to_call_arbitrary_ruby_methods
    template = %q({% macro greet(name) %}{{ name.public_methods.first }}{% endmacro %}{% call greet(name: 1) %})

    assert_template_result('', template)
  end
end
