# frozen_string_literal: true

require 'test_helper'

class StaticVariableAnalyzerUnitTest < Minitest::Test
  include Liquid

  def test_reports_definite_external_paths_with_locations
    result = analyze(<<~LIQUID)
      {{ user.name }}
      {% echo cart.total | default: fallback %}
    LIQUID

    assert_equal([%w[user name], ['cart', 'total'], ['fallback']], paths(result.definite))
    assert_equal([1, 2, 2], result.definite.map(&:line_number))
    assert_equal(result.definite.map(&:line_number), result.definite.map(&:line))
    assert_empty(result.conditional)
    assert_empty(result.dynamic)
  end

  def test_class_entry_accepts_template_source
    result = StaticVariableAnalyzer.analyze('{{ user.name }}')

    assert_equal([%w[user name]], paths(result.definite))
    assert_equal(1, result.definite.first.line_number)
  end

  def test_does_not_execute_filters_or_drops_and_still_reads_arguments
    template = Template.parse("{{ user | dangerous: settings.flag }}", line_numbers: true)

    result = template.variable_references

    assert_equal([['user'], ['settings', 'flag']], paths(result.definite))
  end

  def test_assign_aliases_external_paths_and_shadows_later_bare_reads
    result = analyze(<<~LIQUID)
      {% assign account = user.account %}
      {{ account.name }}
      {{ account }}
    LIQUID

    assert_equal([%w[user account], %w[user account name]], paths(result.definite))
  end

  def test_assign_with_filter_is_opaque_local
    result = analyze(<<~LIQUID)
      {% assign name = user.name | upcase %}
      {{ name }}
    LIQUID

    assert_equal([['user', 'name']], paths(result.definite))
  end

  def test_capture_body_is_not_conditioned_by_capture_itself
    result = analyze("{% capture title %}{{ page.title }}{% endcapture %}{{ title }}")

    assert_equal([['page', 'title']], paths(result.definite))
  end

  def test_conditional_reads_and_branch_local_bindings_are_possible
    result = analyze(<<~LIQUID)
      {% if feature.enabled %}
        {{ offer.title }}
        {% assign selected = offer %}
      {% endif %}
      {{ selected.id }}
    LIQUID

    assert_equal([['feature', 'enabled']], paths(result.definite))
    assert_equal(
      [%w[offer title], ['offer'], %w[offer id]],
      paths(result.conditional),
    )
  end

  def test_else_makes_unconditional_assignment_definite
    result = analyze(<<~LIQUID)
      {% if flag %}
        {% assign value = primary %}
      {% else %}
        {% assign value = secondary %}
      {% endif %}
      {{ value }}
    LIQUID

    assert_equal([['flag']], paths(result.definite))
    assert_equal([['primary'], ['secondary']], paths(result.conditional).sort)
  end

  def test_for_scopes_item_and_forloop_while_preserving_collection_paths
    result = analyze(<<~LIQUID)
      {% for item in items limit: limit offset: offset %}
        {{ item.title }}
        {{ forloop.index }}
      {% else %}
        {{ empty_message }}
      {% endfor %}
      {{ item }}
    LIQUID

    assert_equal([['items'], ['limit'], ['offset']], paths(result.definite).sort)
    assert_equal([['empty_message']], paths(result.conditional))
    assert_equal(1, result.dynamic.length)
    assert_equal('items', result.dynamic.first.path.first)
    assert_predicate(result.dynamic.first.path[1], :iteration?)
    assert_equal('title', result.dynamic.first.path.last)
  end

  def test_nested_loop_aliases_compose_external_paths
    result = analyze(<<~LIQUID)
      {% assign accounts = company.accounts %}
      {% for account in accounts %}
        {% for owner in account.owners %}{{ owner.email }}{% endfor %}
      {% endfor %}
    LIQUID

    assert_equal([%w[company accounts]], paths(result.definite).uniq)
    assert_equal(
      ['company', 'accounts', :dynamic, 'owners', :dynamic, 'email'],
      paths(result.dynamic).last,
    )
  end

  def test_dynamic_subscripts_are_not_reported_as_fixed_fields
    result = analyze(<<~LIQUID)
      {{ user[key] }}
      {{ products[category.handle].name }}
      {{ self[root] }}
    LIQUID

    assert_equal([%w[key], %w[category handle], ['root']], paths(result.definite))
    assert_equal(3, result.dynamic.length)
    assert_equal(['user'], result.dynamic[0].path[0, 1])
    assert_predicate(result.dynamic[0].path[1], :dynamic?)
    refute_predicate(result.dynamic[0].path[1], :iteration?)
    assert_equal('key', result.dynamic[0].path[1].expression)
    assert_equal(['products'], result.dynamic[1].path[0, 1])
    assert_equal('name', result.dynamic[1].path.last)
    assert_predicate(result.dynamic[2].path.first, :dynamic?)
  end

  def test_render_reads_arguments_and_uses_caller_supplied_resolver
    source = '{% render "card", item: product.items[handle], count: total %}'
    template = Template.parse(source, line_numbers: true)
    resolver = proc { { definite: [['shop', 'name']], conditional: [['settings', 'color']], dynamic: [] } }

    result = template.variable_references(render_dependency_resolver: resolver)

    assert_equal([
      ['handle'],
      ['product', 'items'],
      ['total'],
      %w[shop name],
    ], paths(result.definite))
    assert_equal([['settings', 'color']], paths(result.conditional))
    assert_equal(1, result.dynamic.length)
    assert_equal('handle', result.dynamic.first.path.last.expression)
  end

  def test_render_resolver_can_return_plain_paths
    template = Template.parse("{% render 'card' %}", line_numbers: true)

    result = template.variable_references(render_resolver: ->(_node) { [%w[shop name], ['settings']] })

    assert_equal([%w[shop name], ['settings']], paths(result.definite))
  end

  def test_render_without_resolver_is_reported_but_no_template_is_loaded
    result = analyze("{% render 'card', item: item %}")

    assert_equal([['item']], paths(result.definite))
    assert_equal(1, result.unresolved_renders.length)
    assert_equal(1, result.unresolved_renders.first.line_number)
  end

  def test_include_is_reported_unresolved
    result = analyze("{% include 'card', item: item %}")

    assert_equal([['item']], paths(result.definite))
    assert_equal(1, result.unresolved_includes.length)
  end

  private

  def analyze(source)
    Template.parse(source, line_numbers: true).variable_references
  end

  def paths(references)
    references.map do |reference|
      reference.path.map do |segment|
        if segment.respond_to?(:dynamic?) && segment.dynamic?
          :dynamic
        else
          segment
        end
      end
    end
  end
end
