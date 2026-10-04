# frozen_string_literal: true

require 'test_helper'

class MacroTagTest < Minitest::Test
  include Liquid

  def test_macro_renders_reusable_output_with_default_arguments
    template = '{% macro greet(name, greeting = "Hello") %}{{ greeting }}, {{ name }}!{% endmacro %}' \
      '{% call greet("World") %} {% call greet(name: "Liquid", greeting: "Hi") %}'

    assert_equal("Hello, World! Hi, Liquid!", Template.parse(template).render!)
  end

  def test_default_arguments_can_reference_previous_arguments
    template = '{% macro pair(first, second = first) %}{{ first }}/{{ second }}{% endmacro %}' \
      '{% call pair("one") %} {% call pair("one", "two") %}'

    assert_equal("one/one one/two", Template.parse(template).render!)
  end

  def test_macro_captures_definition_scope_not_call_scope
    template = '{% assign word = "definition" %}' \
      '{% macro show_word %}{{ word }}|{{ caller_only }}{% endmacro %}' \
      '{% assign word = "later" %}{% assign caller_only = "caller" %}' \
      '{% call show_word %}'

    assert_equal("definition|", Template.parse(template).render!)
  end

  def test_call_has_its_own_local_scope
    template = '{% assign value = "outer" %}' \
      '{% macro change(inner) %}{% assign value = inner %}inside={{ value }};{% endmacro %}' \
      '{% call change("inner") %}outside={{ value }}'

    assert_equal("inside=inner;outside=outer", Template.parse(template).render!)
  end

  def test_nested_calls_and_parameter_shadowing
    template = '{% macro label(text) %}[{{ text }}]{% endmacro %}' \
      '{% macro outer(text, prefix) %}{% call label(prefix | append: text) %}{% endmacro %}' \
      '{% call outer("outer", "inner ") %}'

    assert_equal("[inner outer]", Template.parse(template).render!)
  end

  def test_recursive_calls_are_limited_by_existing_stack_depth
    template = <<~LIQUID
      {% macro forever %}{% call forever %}{% endmacro %}
      {% call forever %}
    LIQUID

    error = assert_raises(StackLevelError) do
      Template.parse(template).render!
    end
    assert_equal("Liquid error: Nesting too deep", error.message)
  end

  def test_missing_argument_has_clear_error
    template = '{% macro greet(name) %}{{ name }}{% endmacro %}{% call greet %}'

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_equal("Liquid error: missing argument name for macro greet", error.message)
  end

  def test_extra_argument_has_clear_error
    template = '{% macro greet(name) %}{{ name }}{% endmacro %}{% call greet("Ada", "Byron") %}'

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_equal("Liquid error: wrong number of arguments for macro greet", error.message)
  end

  def test_unknown_keyword_argument_has_clear_error
    template = '{% macro greet(name) %}{{ name }}{% endmacro %}{% call greet(name: "Ada", other: "Byron") %}'

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_equal("Liquid error: unknown argument other for macro greet", error.message)
  end

  def test_duplicate_call_argument_has_clear_error
    template = '{% macro greet(name) %}{{ name }}{% endmacro %}{% call greet(name: "Ada", name: "Byron") %}'

    error = assert_raises(SyntaxError) { Template.parse(template) }
    assert_match(/Liquid syntax error: duplicate name argument\b/, error.message)
  end

  def test_positional_argument_after_keyword_argument_has_clear_error
    template = '{% macro greet(name, greeting) %}{{ greeting }} {{ name }}{% endmacro %}' \
      '{% call greet(greeting: "Hi", "Ada") %}'

    error = assert_raises(SyntaxError) { Template.parse(template) }
    assert_match(/Liquid syntax error: positional argument after keyword argument/, error.message)
  end

  def test_positional_and_keyword_argument_for_same_parameter_has_clear_error
    template = '{% macro greet(name) %}{{ name }}{% endmacro %}{% call greet("Ada", name: "Byron") %}'

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_equal("Liquid error: duplicate name argument for macro greet", error.message)
  end

  def test_duplicate_macro_parameter_has_clear_error
    template = '{% macro greet(name, name) %}{% endmacro %}'

    error = assert_raises(SyntaxError) { Template.parse(template) }
    assert_match(/Liquid syntax error: duplicate macro parameter name\b/, error.message)
  end

  def test_undefined_macro_has_clear_error
    template = '{% call missing %}'

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_equal("Liquid error: undefined macro missing", error.message)
  end

  def test_macro_names_are_static_and_cannot_dispatch_arbitrary_methods
    template = '{% assign name = "greet" %}{% macro greet() %}safe{% endmacro %}{% call name %}'

    error = assert_raises(ArgumentError) { Template.parse(template).render! }
    assert_equal("Liquid error: undefined macro name", error.message)
  end
end
