# frozen_string_literal: true

require 'test_helper'

class StaticVariableAnalysisTest < Minitest::Test
  include Liquid

  def test_collects_certain_variable_paths_with_positions
    result = analyze(<<~LIQUID)
      {{ settings.colors.primary }}
      {% echo cart.item_count %}
    LIQUID

    assert_equal([
      reference(['settings', 'colors', 'primary'], 1),
      reference(['cart', 'item_count'], 2),
    ], result[:certain])
    assert_equal([], result[:conditional])
    assert_equal([], result[:dynamic])
  end

  def test_collects_filter_arguments_without_invoking_filters
    result = analyze("{{ product | slice: settings.offset, settings.length }}")

    assert_equal([
      reference(['product'], 1),
      reference(['settings', 'offset'], 1),
      reference(['settings', 'length'], 1),
    ], result[:certain])
  end

  def test_assign_shadows_external_variables
    result = analyze(<<~LIQUID)
      {{ source.value }}
      {% assign value = source.initial %}
      {{ value.local }}
    LIQUID

    assert_equal([
      reference(['source', 'value'], 1),
      reference(['source', 'initial'], 2),
    ], result[:certain])
  end

  def test_capture_body_is_scoped_to_the_captured_name
    result = analyze(<<~LIQUID)
      {% capture message %}
        {{ external.value }}
      {% endcapture %}
      {{ message }}
    LIQUID

    assert_equal([reference(['external', 'value'], 2)], result[:certain])
  end

  def test_conditional_bodies_and_branch_conditions_are_marked
    result = analyze(<<~LIQUID)
      {{ always.available }}
      {% if condition.first %}
        {{ yes.path }}
      {% elsif second.condition %}
        {{ maybe.path }}
      {% else %}
        {{ fallback.path }}
      {% endif %}
    LIQUID

    assert_equal([
      reference(['always', 'available'], 1),
      reference(['condition'], 2),
      reference(['second', 'condition'], 4),
    ], result[:certain])
    assert_equal([
      reference(['yes', 'path'], 3),
      reference(['maybe', 'path'], 5),
      reference(['fallback', 'path'], 7),
    ], result[:conditional])
  end

  def test_conditional_assignment_causes_conservative_shadowing
    result = analyze(<<~LIQUID)
      {% if condition %}
        {% assign value = branch.source %}
      {% endif %}
      {{ value.after }}
    LIQUID

    assert_equal([
      reference(['branch', 'source'], 2),
      reference(['value', 'after'], 4),
    ], result[:conditional])
    assert_equal([reference(['condition'], 1)], result[:certain])
  end

  def test_complete_conditional_assignment_shadows_after_merge
    result = analyze(<<~LIQUID)
      {% if condition %}
        {% assign value = first.source %}
      {% else %}
        {% assign value = second.source %}
      {% endif %}
      {{ value.after }}
    LIQUID

    assert_equal([
      reference(['first', 'source'], 2),
      reference(['second', 'source'], 4),
    ], result[:conditional])
    assert_equal([reference(['condition'], 1)], result[:certain])
  end

  def test_complete_conditional_inside_branch_only_possibly_shadows
    result = analyze(<<~LIQUID)
      {% if outer %}
        {% if inner %}
          {% assign value = first.source %}
        {% else %}
          {% assign value = second.source %}
        {% endif %}
      {% endif %}
      {{ value.after }}
    LIQUID

    assert_includes(result[:conditional], reference(['value', 'after'], 8))
  end

  def test_for_loop_scopes_item_and_forloop
    result = analyze(<<~LIQUID)
      {% for item in products limit: limits.size offset: offsets.start %}
        {{ item.title }}
        {{ forloop.index }}
        {{ outside.item }}
      {% else %}
        {{ empty.message }}
      {% endfor %}
    LIQUID

    assert_equal([
      reference(['products'], 1),
      reference(['limits'], 1),
      reference(['offsets', 'start'], 1),
    ], result[:certain])
    assert_equal([
      reference(['outside', 'item'], 4),
      reference(['empty', 'message'], 6),
    ], result[:conditional])
  end

  def test_table_row_loop_scopes_item_and_tablerowloop
    result = analyze(<<~LIQUID)
      {% tablerow item in products cols: table.cols %}
        {{ item.title }}
        {{ tablerowloop.col }}
        {{ outside.item }}
      {% endtablerow %}
    LIQUID

    assert_equal([
      reference(['products'], 1),
      reference(['table', 'cols'], 1),
    ], result[:certain])
    assert_equal([reference(['outside', 'item'], 4)], result[:conditional])
  end

  def test_dynamic_subscript_preserves_static_prefix_and_reports_key
    result = analyze("{{ products[selected.handle].title }}")

    assert_equal([reference(['selected', 'handle'], 1)], result[:certain])
    assert_equal([], result[:conditional])
    assert_equal([dynamic(['products'], 1)], result[:dynamic])
  end

  def test_dynamic_subscript_in_branch_is_marked_conditional
    result = analyze("{% if condition %}{{ products[selected.handle] }}{% endif %}")

    assert_equal([reference(['condition'], 1)], result[:certain])
    assert_equal([dynamic(['products'], 1, true)], result[:dynamic])
  end

  def test_dynamic_root_is_not_invented_as_a_field_name
    result = analyze("{{ self[selected.key] }}")

    assert_equal([reference(['selected', 'key'], 1)], result[:certain])
    assert_equal([dynamic(['self'], 1)], result[:dynamic])
  end

  def test_direct_self_access_and_commands_do_not_become_dynamic_field_names
    result = analyze("{{ self.title }}|{{ products.first.title }}|{{ products.size }}")

    assert_equal([
      reference(['title'], 1),
      reference(['products'], 1),
    ], result[:certain])
    assert_equal([], result[:dynamic])
  end

  def test_render_arguments_are_external_but_partial_locals_are_filtered
    dependencies = {
      certain: [%w[global outside], 'shop.name'],
      conditional: [%w[outside conditional_only]],
      dynamic: [%w[shop]],
    }
    resolver = ->(_name) { dependencies }

    result = analyze(<<~LIQUID, render_resolver: resolver)
      {% render 'card', product: selected.product, inside: passed.value, global: sent.global, cart: sent.cart %}
    LIQUID

    assert_equal([
      reference(['selected', 'product'], 1),
      reference(['passed', 'value'], 1),
      reference(['sent', 'global'], 1),
      reference(['sent', 'cart'], 1),
      reference(['shop', 'name'], 1),
    ], result[:certain])
    assert_equal([reference(['outside', 'conditional_only'], 1)], result[:conditional])
    assert_equal([dynamic(['shop'], 1)], result[:dynamic])
  end

  def test_render_without_resolver_does_not_read_partials
    result = analyze("{% render 'card' with product.value %}")

    assert_equal([reference(['product', 'value'], 1)], result[:certain])
  end

  def test_class_method_entry_accepts_source_and_positional_resolver
    resolver = { 'card' => { certain: [['shop', 'name']] } }
    result = Template.analyze_external_variables("{% render 'card' %}", { line_numbers: true }, resolver)

    assert_equal([reference(['shop', 'name'], 1)], result[:certain])
  end

  def test_include_remains_in_the_parent_scope
    result = analyze("{% include 'card' with product.value %}")

    assert_equal([reference(['product', 'value'], 1)], result[:certain])
  end

  def test_custom_tag_expressions_are_conservatively_visited
    custom_tag = Class.new(Tag) do
      attr_reader :expression

      def initialize(*)
        super
        @expression = parse_expression('custom.external')
      end

      def nodelist
        [@expression]
      end
    end

    environment = Environment.default.dup
    environment.register_tag('custom_ref', custom_tag)
    template = Template.parse('{% custom_ref %}', line_numbers: true, environment: environment)

    assert_equal(
      [reference(['custom', 'external'], 1)],
      StaticVariableAnalysis.analyze(template)[:certain],
    )
  end

  private

  def analyze(source, render_resolver: nil)
    Template
      .parse(source, line_numbers: true, error_mode: :strict2)
      .analyze_external_variables(render_resolver: render_resolver)
  end

  def reference(path, line_number)
    StaticVariableAnalysis::Reference.new(path: path, line_number: line_number)
  end

  def dynamic(prefix, line_number, conditional = false)
    StaticVariableAnalysis::DynamicReference.new(
      prefix: prefix,
      line_number: line_number,
      conditional: conditional,
    )
  end
end
