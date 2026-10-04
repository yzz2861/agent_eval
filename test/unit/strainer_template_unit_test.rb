# frozen_string_literal: true

require 'test_helper'

class StrainerTemplateUnitTest < Minitest::Test
  include Liquid

  def test_add_filter_when_wrong_filter_class
    c = Context.new
    s = c.strainer
    wrong_filter = lambda(&:reverse)

    exception = assert_raises(TypeError) do
      s.class.add_filter(wrong_filter)
    end
    assert_equal(exception.message, "wrong argument type Proc (expected Module)")
  end

  module PrivateMethodOverrideFilter
    private

    def public_filter
      "overriden as private"
    end
  end

  def test_add_filter_raises_when_module_privately_overrides_registered_public_methods
    error = assert_raises(Liquid::MethodOverrideError) do
      Liquid::Environment.build do |env|
        env.register_filter(PublicMethodOverrideFilter)
        env.register_filter(PrivateMethodOverrideFilter)
      end
    end

    assert_equal('Liquid error: Filter overrides registered public methods as non public: public_filter', error.message)
  end

  module ProtectedMethodOverrideFilter
    protected

    def public_filter
      "overriden as protected"
    end
  end

  def test_add_filter_raises_when_module_overrides_registered_public_method_as_protected
    error = assert_raises(Liquid::MethodOverrideError) do
      Liquid::Environment.build do |env|
        env.register_filter(PublicMethodOverrideFilter)
        env.register_filter(ProtectedMethodOverrideFilter)
      end
    end

    assert_equal('Liquid error: Filter overrides registered public methods as non public: public_filter', error.message)
  end

  module PublicMethodOverrideFilter
    def public_filter
      "public"
    end
  end

  def test_add_filter_does_not_raise_when_module_overrides_previously_registered_method
    with_global_filter do
      context = Context.new
      context.add_filters([PublicMethodOverrideFilter])
      strainer = context.strainer
      assert(strainer.class.send(:filter_methods).include?('public_filter'))
    end
  end

  def test_add_filter_does_not_include_already_included_module
    mod = Module.new do
      class << self
        attr_accessor :include_count
        def included(_mod)
          self.include_count += 1
        end
      end
      self.include_count = 0
    end
    strainer = Context.new.strainer
    strainer.class.add_filter(mod)
    strainer.class.add_filter(mod)
    assert_equal(1, mod.include_count)
  end

  module ExplicitPureFilter
    extend Liquid::PureFilters

    def declared_pure(input)
      input.to_s.upcase
    end
    pure_filter :declared_pure

    def not_declared(input)
      input
    end
  end

  def test_pure_filter_methods_track_only_explicit_declarations
    strainer_class = Class.new(StrainerTemplate)
    initial_version = strainer_class.filter_registry_version

    strainer_class.add_filter(ExplicitPureFilter)

    assert(strainer_class.pure_filter?('declared_pure'))
    refute(strainer_class.pure_filter?('not_declared'))
    assert_operator(strainer_class.filter_registry_version, :>, initial_version)
  end

  module PurityOverrideFilter
    def declared_pure(input)
      "#{input}!"
    end
  end

  def test_overriding_a_pure_filter_without_declaration_drops_purity
    strainer_class = Class.new(StrainerTemplate)
    strainer_class.add_filter(ExplicitPureFilter)
    assert(strainer_class.pure_filter?('declared_pure'))

    strainer_class.add_filter(PurityOverrideFilter)

    refute(strainer_class.pure_filter?('declared_pure'))
  end

  def test_pure_filter_set_and_version_are_inherited_by_subclasses
    parent = Class.new(StrainerTemplate)
    parent.add_filter(ExplicitPureFilter)

    child = Class.new(parent)
    assert(child.pure_filter?('declared_pure'))
    assert_equal(parent.filter_registry_version, child.filter_registry_version)

    child.add_filter(PurityOverrideFilter)
    refute(child.pure_filter?('declared_pure'))
    assert(parent.pure_filter?('declared_pure'))
  end
end
