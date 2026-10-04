# frozen_string_literal: true

require 'test_helper'

# Pure filters declared explicitly: no context dependency, no side effects.
module CountingPureFilter
  extend Liquid::PureFilters

  class << self
    attr_accessor :call_count
  end
  self.call_count = 0

  def self.reset!
    self.call_count = 0
  end

  def cf_shout(input)
    CountingPureFilter.call_count += 1
    "#{input}!"
  end
  pure_filter :cf_shout

  def cf_echo(input)
    CountingPureFilter.call_count += 1
    input
  end
  pure_filter :cf_echo

  def cf_kwarg(input, options = {})
    CountingPureFilter.call_count += 1
    "#{input}#{options['suffix']}"
  end
  pure_filter :cf_kwarg

  def cf_boom(input)
    CountingPureFilter.call_count += 1
    raise Liquid::ArgumentError, "boom for #{input}"
  end
  pure_filter :cf_boom

  # Same interface as cf_shout but deliberately NOT declared pure.
  def cf_runtime(input)
    CountingPureFilter.call_count += 1
    input
  end
end

# Context-dependent filters: never folded.
module ContextCountingFilter
  class << self
    attr_accessor :call_count
  end
  self.call_count = 0

  def self.reset!
    self.call_count = 0
  end

  def cf_contextual(input)
    ContextCountingFilter.call_count += 1
    "#{input}-#{@context['suffix']}"
  end

  # Overrides the registered pure cf_shout with a context-local implementation.
  def cf_shout(input)
    ContextCountingFilter.call_count += 1
    "#{input}?"
  end
end

# Registered after parse to prove a registry change invalidates folded results.
module LaterOverrideFilter
  def cf_shout(input)
    "overridden:#{input}"
  end
end

class ConstantFoldFilterTest < Minitest::Test
  include Liquid

  def setup
    @environment = Liquid::Environment.build do |env|
      env.register_filter(CountingPureFilter)
    end
    CountingPureFilter.reset!
    ContextCountingFilter.reset!
  end

  def parse(source)
    Liquid::Template.parse(source, environment: @environment, error_mode: :strict)
  end

  def render_with(template, assigns = {})
    context = Liquid::Context.build(environments: assigns, environment: @environment)
    template.render(context)
  end

  def test_all_literal_chain_folds_once_and_reuses_constant
    template = parse("{{ 'hi' | cf_shout }}")

    # The filter ran exactly once, at compile time.
    assert_equal(1, CountingPureFilter.call_count)

    3.times { assert_equal('hi!', render_with(template)) }

    # Repeated renders reuse the cached constant instead of invoking the filter.
    assert_equal(1, CountingPureFilter.call_count)
  end

  def test_chained_pure_filters_with_literal_kwargs_fold_once
    template = parse("{{ 'hi' | cf_echo | cf_shout | cf_kwarg: suffix: '?' }}")

    # cf_echo + cf_shout + cf_kwarg each invoked exactly once during parsing.
    assert_equal(3, CountingPureFilter.call_count)

    2.times { assert_equal('hi!?', render_with(template)) }
    assert_equal(3, CountingPureFilter.call_count)
  end

  def test_dynamic_leading_expression_is_not_folded
    template = parse("{{ name | cf_shout }}")

    assert_equal(0, CountingPureFilter.call_count)

    assert_equal('a!', render_with(template, 'name' => 'a'))
    assert_equal('b!', render_with(template, 'name' => 'b'))

    # The filter runs at render time, once per render.
    assert_equal(2, CountingPureFilter.call_count)
  end

  def test_dynamic_filter_argument_is_not_folded
    template = parse("{{ 'hi' | cf_kwarg: suffix: suffix }}")

    assert_equal(0, CountingPureFilter.call_count)

    assert_equal('hi-x', render_with(template, 'suffix' => '-x'))
    assert_equal('hi-y', render_with(template, 'suffix' => '-y'))
    assert_equal(2, CountingPureFilter.call_count)
  end

  def test_undeclared_filter_is_always_runtime
    template = parse("{{ 'a' | cf_runtime }}")

    assert_equal(0, CountingPureFilter.call_count)
    assert_equal('a', render_with(template))
    assert_equal('a', render_with(template))

    # Not declared pure, so a fully literal expression still runs each render.
    assert_equal(2, CountingPureFilter.call_count)
  end

  def test_context_dependent_filter_is_not_folded
    env = Liquid::Environment.build do |e|
      e.register_filter(ContextCountingFilter)
    end
    template = Liquid::Template.parse(
      "{{ 'hi' | cf_contextual }}",
      environment: env,
      error_mode: :strict,
    )

    assert_equal(0, ContextCountingFilter.call_count)

    cxt = ->(suffix) { Liquid::Context.build(environments: { 'suffix' => suffix }, environment: env) }
    assert_equal('hi-a', template.render(cxt.call('a')))
    assert_equal('hi-b', template.render(cxt.call('b')))
    assert_equal(2, ContextCountingFilter.call_count)
  end

  def test_unregistered_filter_is_not_blindly_folded
    # A custom pure-looking name is not registered on this environment, so it
    # must take the normal runtime path and raise under strict_filters rather
    # than being optimized based on any built-in assumptions.
    env = Liquid::Environment.build do |e|
      e.strainer_template = Class.new(Liquid::StrainerTemplate)
    end
    template = Liquid::Template.parse("{{ 'hi' | upcase }}", environment: env, error_mode: :strict)

    assert_raises(Liquid::UndefinedFilter) do
      template.render!({}, strict_filters: true)
    end
  end

  def test_raising_pure_filter_is_deferred_to_runtime_and_behavior_matches
    template = parse("{{ 'x' | cf_boom }}")

    # The compile-time attempt ran the filter once and failed; folding bailed.
    assert_equal(1, CountingPureFilter.call_count)

    # Default error handling renders the error as text, same as non-folded.
    assert_match(/boom for x/, template.render)

    # With rethrow enabled the same error is raised.
    assert_raises(Liquid::ArgumentError) { template.render! }

    # Deferred to runtime: the filter runs again on every render.
    assert_operator CountingPureFilter.call_count, :>=, 3
  end

  def test_runtime_zero_division_falls_back_from_fold
    # divided_by is declared pure, but dividing by zero raises during folding,
    # so the expression defers to runtime error handling.
    template = Liquid::Template.parse("{{ 6 | divided_by: 0 }}")

    assert_match(/divided/i, template.render)
    assert_raises(Liquid::ZeroDivisionError) { template.render! }
  end

  def test_folded_constant_is_bypassed_for_context_local_filter_override
    template = parse("{{ 'hi' | cf_shout }}")
    assert_equal('hi!', render_with(template))
    assert_equal(1, CountingPureFilter.call_count)

    context = Liquid::Context.build(environment: @environment)
    context.add_filters(ContextCountingFilter)

    assert_equal('hi?', template.render(context))
    assert_equal(1, ContextCountingFilter.call_count)
    # The bypass used the local override without re-running the pure filter.
    assert_equal(1, CountingPureFilter.call_count)
  end

  def test_registry_change_after_parse_invalidates_fold
    template = parse("{{ 'hi' | cf_shout }}")
    assert_equal('hi!', render_with(template))

    @environment.register_filter(LaterOverrideFilter)

    # The registry changed; the stale constant must not be reused.
    assert_equal('overridden:hi', render_with(template))
  end

  def test_fold_is_not_reused_across_incompatible_environments
    template = parse("{{ 'hi' | cf_shout }}")
    assert_equal('hi!', render_with(template))

    other_env = Liquid::Environment.build do |env|
      env.register_filter(ContextCountingFilter)
    end

    # A context from a different environment resolves the filter differently,
    # so the fold captured against @environment must be ignored.
    context = Liquid::Context.build(
      environments: { 'suffix' => 'z' },
      environment: other_env,
    )
    assert_equal('hi?', template.render(context))
  end

  def test_standard_pure_filters_fold
    template = Liquid::Template.parse("{{ 'HELLO' | downcase | capitalize }}")
    assert_equal('Hello', template.render)
    assert_equal('Hello', template.render)
  end

  def test_special_literal_keywords_are_foldable
    assert_equal('FALSE', Liquid::Template.parse("{{ false | upcase }}").render)
    assert_equal('', Liquid::Template.parse("{{ nil | upcase }}").render)
    assert_equal('', Liquid::Template.parse("{{ blank | upcase }}").render)
  end

  def test_pure_filter_declaration_is_explicit
    assert CountingPureFilter.pure_filter_declared?(:cf_shout)
    refute CountingPureFilter.pure_filter_declared?(:cf_runtime)
    refute ContextCountingFilter.respond_to?(:pure_filter_declared?)
  end
end
