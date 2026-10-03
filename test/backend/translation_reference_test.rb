require 'test_helper'

class I18nBackendTranslationReferenceTest < I18n::TestCase
  def setup
    super
    I18n.backend = I18n::Backend::Simple.new
    store_translations(:en,
      :users => {
        :title => 'Mr.',
        :greeting => 'Hello %{@.title} %{name}',
        :absolute => 'Hello %{@users.title}',
        :nested => '%{@users.absolute}',
        :escaped => 'Literal %%{@.title}',
        :half_escaped => 'Literal %%%{@.title}',
        :non_string => 42,
        :invalid_non_string => 'Value: %{@.non_string}',
        :missing => 'Value: %{@.missing_target}',
        :invalid => 'Value: %{@.}',
        :cyc1 => '%{@users.cyc2}',
        :cyc2 => '%{@users.cyc1}',
      },
      :linked => :"users.title",
      :link_cycle_one => :link_cycle_two,
      :link_cycle_two => :link_cycle_one
    )
  end

  test 'resolves a relative reference and interpolates the containing string' do
    assert_equal 'Hello Mr. Ada', I18n.t('users.greeting', :name => 'Ada')
  end

  test 'resolves a relative reference without ordinary interpolation values' do
    assert_equal 'Hello Mr. %{name}', I18n.t('users.greeting')
  end

  test 'resolves an absolute reference' do
    assert_equal 'Hello Mr.', I18n.t('users.absolute')
  end

  test 'resolves references recursively' do
    assert_equal 'Hello Mr.', I18n.t('users.nested')
  end

  test 'resolves references inside deep interpolation hashes' do
    data = { :message => 'Hello %{@users.title}', :name => '%{name}' }
    result = I18n.t(:deep, :default => data, :deep_interpolation => true, :name => 'Ada')

    assert_equal({ :message => 'Hello Mr.', :name => 'Ada' }, result)
  end

  test 'respects the existing interpolation escape' do
    assert_equal 'Literal %{@.title}', I18n.t('users.escaped', :name => 'Ada')
    assert_equal 'Literal %Mr.', I18n.t('users.half_escaped')
    assert_equal 'Literal %%%%{@.title}', I18n.t(:escaped_reference, :default => 'Literal %%%%{@.title}')
    assert_equal 'Literal %%{@.title}', I18n.t(:escaped_reference, :default => 'Literal %%%%{@.title}', :name => 'Ada')
  end

  test 'keeps symbol aliases working' do
    assert_equal 'Mr.', I18n.t(:linked)
  end

  test 'raises when a referenced value is not a string' do
    error = assert_raises(I18n::InvalidTranslationReference) do
      I18n.t('users.invalid_non_string')
    end

    assert_equal '@.non_string', error.reference
    assert_match(/does not resolve to a String/, error.message)
  end

  test 'raises missing translation data for a missing reference' do
    assert_raises(I18n::MissingTranslationData) do
      I18n.t!('users.missing')
    end
  end

  test 'raises for an invalid reference' do
    error = assert_raises(I18n::InvalidTranslationReference) do
      I18n.t('users.invalid')
    end

    assert_equal '@.', error.reference
    assert_match(/relative reference must name a key/, error.message)
  end

  test 'reports the keys traversed by a string reference cycle' do
    error = assert_raises(I18n::CircularTranslationReference) do
      I18n.t('users.cyc1')
    end

    assert_equal ['users.cyc1', 'users.cyc2', 'users.cyc1'], error.reference_chain
    assert_equal error.reference_chain, error.keys
  end

  test 'reports the keys traversed by a symbol alias cycle' do
    error = assert_raises(I18n::CircularTranslationReference) do
      I18n.t(:link_cycle_one)
    end

    assert_equal ['link_cycle_one', 'link_cycle_two', 'link_cycle_one'], error.reference_chain
  end

  test 'resolves relative references using the requested locale and fallback locale' do
    backend = Class.new(I18n::Backend::Simple) do
      include I18n::Backend::Fallbacks
    end.new
    I18n.backend = backend
    I18n.fallbacks = I18n::Locale::Fallbacks.new(:fr => :en)
    store_translations(:en, :users => { :title => 'Mr.' })
    store_translations(:fr, :users => { :greeting => 'Bonjour %{@.title}' })

    assert_equal 'Bonjour Mr.', I18n.t('users.greeting', :locale => :fr)
  end
end
