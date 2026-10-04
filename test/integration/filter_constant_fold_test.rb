# frozen_string_literal: true

require 'test_helper'

class FilterConstantFoldTest < Minitest::Test
  module PureFilters
    def self.calls
      @calls ||= Hash.new(0)
    end

    def shout(input)
      PureFilters.calls[:shout] += 1
      "#{input.to_s.upcase}!"
    end

    def wrap(input, left, options)
      PureFilters.calls[:wrap] += 1
      "#{left}#{input}#{options['right']}"
    end

    def boom(_input)
      PureFilters.calls[:boom] += 1
      raise Liquid::ArgumentError, 'boom'
    end
  end

  module PlainFilters
    def self.calls
      @calls ||= Hash.new(0)
    end

    def shout(input)
      PlainFilters.calls[:shout] += 1
      "#{input.to_s.upcase}!"
    end

    def wrap(input, left, options)
      PlainFilters.calls[:wrap] += 1
      "#{left}#{input}#{options['right']}"
    end

    def boom(_input)
      PlainFilters.calls[:boom] += 1
      raise Liquid::ArgumentError, 'boom'
    end
  end

  module BuiltinNameFilters
    def self.calls
      @calls ||= Hash.new(0)
    end

    def upcase(input)
      BuiltinNameFilters.calls[:upcase] += 1
      "fake-#{input}"
    end
  end

  module ShadowShout
    def shout(_input)
      'shadow'
    end
  end

  module ExtraFilter
    def extra(input)
      "extra-#{input}"
    end
  end

  def setup
    PureFilters.calls.clear
    PlainFilters.calls.clear
    BuiltinNameFilters.calls.clear
  end

  def test_literal_filter_chain_is_folded_at_parse_time
    environment = pure_environment
    template = Liquid::Template.parse("{{ 'abc' | shout }}", environment: environment)

    assert_equal(1, PureFilters.calls[:shout])

    3.times { assert_equal('ABC!', template.render) }
    assert_equal(1, PureFilters.calls[:shout])
  end

  def test_folded_output_matches_unoptimized_output
    source = "{{ 'abc' | shout | wrap: '[', right: ']' }}"
    optimized = Liquid::Template.parse(source, environment: pure_environment)
    unoptimized = Liquid::Template.parse(source, environment: plain_environment)

    3.times do
      assert_equal('[ABC!]', optimized.render)
      assert_equal('[ABC!]', unoptimized.render)
    end

    assert_equal(1, PureFilters.calls[:shout])
    assert_equal(1, PureFilters.calls[:wrap])
    assert_equal(3, PlainFilters.calls[:shout])
  end

  def test_keyword_arguments_are_folded
    template = Liquid::Template.parse("{{ 'x' | wrap: '[', right: ']' }}", environment: pure_environment)

    assert_equal(1, PureFilters.calls[:wrap])
    2.times { assert_equal('[x]', template.render) }
    assert_equal(1, PureFilters.calls[:wrap])
  end

  def test_assign_tag_benefits_from_folding
    template = Liquid::Template.parse("{% assign x = 'abc' | shout %}{{ x }}", environment: pure_environment)

    assert_equal(1, PureFilters.calls[:shout])
    2.times { assert_equal('ABC!', template.render) }
    assert_equal(1, PureFilters.calls[:shout])
  end

  def test_builtin_filter_names_are_not_blindly_folded
    environment = Liquid::Environment.build do |env|
      env.register_filter(BuiltinNameFilters)
    end
    template = Liquid::Template.parse("{{ 'abc' | upcase }}", environment: environment)

    assert_equal(0, BuiltinNameFilters.calls[:upcase])
    2.times { assert_equal('fake-abc', template.render) }
    assert_equal(2, BuiltinNameFilters.calls[:upcase])
  end

  def test_dynamic_input_is_not_folded
    template = Liquid::Template.parse('{{ word | shout }}', environment: pure_environment)

    assert_equal(0, PureFilters.calls[:shout])
    assert_equal('ABC!', template.render('word' => 'abc'))
    assert_equal('DEF!', template.render('word' => 'def'))
    assert_equal(2, PureFilters.calls[:shout])
  end

  def test_dynamic_argument_is_not_folded
    template = Liquid::Template.parse("{{ 'x' | wrap: left, right: ']' }}", environment: pure_environment)

    assert_equal(0, PureFilters.calls[:wrap])
    assert_equal('[x]', template.render('left' => '['))
    assert_equal('(x]', template.render('left' => '('))
    assert_equal(2, PureFilters.calls[:wrap])
  end

  def test_filter_exception_behavior_matches_unoptimized
    source = "{{ 'x' | boom }}"
    optimized = Liquid::Template.parse(source, environment: pure_environment)
    unoptimized = Liquid::Template.parse(source, environment: plain_environment)

    # the fold was attempted at parse time, failed, and deferred to runtime
    assert_equal(1, PureFilters.calls[:boom])
    assert_equal(0, PlainFilters.calls[:boom])

    optimized_error = assert_raises(Liquid::ArgumentError) { optimized.render! }
    unoptimized_error = assert_raises(Liquid::ArgumentError) { unoptimized.render! }
    assert_equal(unoptimized_error.message, optimized_error.message)

    # non-rethrow renders record identical errors and output
    optimized_lax = Liquid::Template.parse(source, environment: pure_environment)
    unoptimized_lax = Liquid::Template.parse(source, environment: plain_environment)
    assert_equal(unoptimized_lax.render, optimized_lax.render)
    assert_equal(unoptimized_lax.errors.map(&:class), optimized_lax.errors.map(&:class))
    assert_equal(unoptimized_lax.errors.map(&:message), optimized_lax.errors.map(&:message))

    # the pure-registered filter was still invoked at runtime
    assert_equal(4, PureFilters.calls[:boom])
    assert_equal(2, PlainFilters.calls[:boom])
  end

  def test_registry_change_invalidates_cached_constant
    environment = pure_environment
    template = Liquid::Template.parse("{{ 'abc' | shout }}", environment: environment)

    assert_equal('ABC!', template.render)
    assert_equal(1, PureFilters.calls[:shout])

    environment.register_filter(ExtraFilter)
    assert_equal('ABC!', template.render)
    assert_equal(2, PureFilters.calls[:shout])
  end

  def test_shadowing_filter_registration_wins_over_cached_constant
    environment = pure_environment
    template = Liquid::Template.parse("{{ 'abc' | shout }}", environment: environment)

    assert_equal('ABC!', template.render)

    environment.register_filter(ShadowShout)
    assert_equal('shadow', template.render)
  end

  def test_context_local_filters_invalidate_cached_constant
    template = Liquid::Template.parse("{{ 'abc' | shout }}", environment: pure_environment)

    assert_equal('ABC!', template.render)
    assert_equal(1, PureFilters.calls[:shout])

    2.times { assert_equal('shadow', template.render(nil, filters: [ShadowShout])) }
    assert_equal(1, PureFilters.calls[:shout])
  end

  def test_cached_constant_is_not_reused_across_environments
    other_environment = Liquid::Environment.build do |env|
      env.register_filter(ShadowShout, pure: true)
    end
    template = Liquid::Template.parse("{{ 'abc' | shout }}", environment: pure_environment)

    assert_equal('ABC!', template.render)

    context = Liquid::Context.build(environment: other_environment)
    assert_equal('shadow', template.render(context))
  end

  def test_folding_works_in_strict_error_modes
    [:strict, :strict2].each do |mode|
      environment = Liquid::Environment.build(error_mode: mode) do |env|
        env.register_filter(PureFilters, pure: true)
      end
      template = Liquid::Template.parse("{{ 'abc' | shout }}", environment: environment)

      2.times { assert_equal('ABC!', template.render) }
    end

    assert_equal(2, PureFilters.calls[:shout])
  end

  def test_pure_filter_declaration_and_registry_version
    environment = Liquid::Environment.new
    strainer = environment.strainer_template
    version = strainer.filter_version

    refute(strainer.pure_filter?('shout'))
    refute(strainer.pure_filter?('size'))

    environment.register_filter(PureFilters, pure: true)
    assert(strainer.pure_filter?('shout'))
    assert_operator(strainer.filter_version, :>, version)

    environment.register_filter(BuiltinNameFilters)
    refute(strainer.pure_filter?('upcase'))

    # standard filters are never pure unless explicitly re-registered as such
    refute(strainer.pure_filter?('size'))

    # context-local strainer subclasses inherit pure declarations
    context = Liquid::Context.build(environment: environment)
    subclass = environment.create_strainer(context, [ExtraFilter]).class
    assert(subclass.pure_filter?('shout'))
    refute(subclass.pure_filter?('extra'))
  end

  private

  def pure_environment
    Liquid::Environment.build do |env|
      env.register_filter(PureFilters, pure: true)
    end
  end

  def plain_environment
    Liquid::Environment.build do |env|
      env.register_filter(PlainFilters)
    end
  end
end
