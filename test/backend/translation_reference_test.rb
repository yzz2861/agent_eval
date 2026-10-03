require 'test_helper'

class I18nBackendTranslationReferenceTest < I18n::TestCase
  def setup
    super
    I18n.backend = I18n::Backend::Simple.new
  end

  test 'resolves an absolute reference to another key' do
    store_translations :en, :salutation => 'Dear', :greeting => '@{salutation} %{name},'
    assert_equal 'Dear Judy,', I18n.t(:greeting, :name => 'Judy')
  end

  test 'resolves a reference in the middle of a sentence' do
    store_translations :en, :title => 'Mr.', :notice => 'Please contact @{title} Smith.'
    assert_equal 'Please contact Mr. Smith.', I18n.t(:notice)
  end

  test 'resolves a relative reference against the scope of the current key' do
    store_translations :en, :mailer => { :salutation => 'Dear', :greeting => '@{.salutation} %{name},' }
    assert_equal 'Dear Judy,', I18n.t(:'mailer.greeting', :name => 'Judy')
  end

  test 'resolves a relative reference when the key is looked up with a scope' do
    store_translations :en, :mailer => { :salutation => 'Dear', :greeting => '@{.salutation} %{name},' }
    assert_equal 'Dear Judy,', I18n.t(:greeting, :scope => :mailer, :name => 'Judy')
  end

  test 'relative and absolute references can be mixed' do
    store_translations :en, :punctuation => '!', :mailer => { :salutation => 'Dear', :greeting => '@{.salutation} %{name}@{punctuation}' }
    assert_equal 'Dear Judy!', I18n.t(:'mailer.greeting', :name => 'Judy')
  end

  test 'interpolates the expanded string uniformly, including placeholders from referenced values' do
    store_translations :en, :salutation => 'Dear %{name}', :greeting => '@{salutation}, welcome to %{place}.'
    assert_equal 'Dear Judy, welcome to Berlin.', I18n.t(:greeting, :name => 'Judy', :place => 'Berlin')
  end

  test 'resolves references transitively' do
    store_translations :en, :a => 'A', :b => '@{a}B', :c => '@{b}C'
    assert_equal 'ABC', I18n.t(:c)
  end

  test 'resolves Symbol aliases in referenced values' do
    store_translations :en, :salutation => 'Dear', :alias => :salutation, :greeting => '@{alias} %{name},'
    assert_equal 'Dear Judy,', I18n.t(:greeting, :name => 'Judy')
  end

  test 'resolves references in values reached through a Symbol alias' do
    store_translations :en, :salutation => 'Dear', :linked => :greeting, :greeting => '@{salutation} %{name},'
    assert_equal 'Dear Judy,', I18n.t(:linked, :name => 'Judy')
  end

  test 'escapes a reference with a backslash' do
    store_translations :en, :greeting => '\\@{salutation} %{name},', :salutation => 'Dear'
    assert_equal '@{salutation} Judy,', I18n.t(:greeting, :name => 'Judy')
  end

  test 'does not treat a lone at sign or empty braces as a reference' do
    store_translations :en, :greeting => 'mail @ example @{} dot'
    assert_equal 'mail @ example @{} dot', I18n.t(:greeting)
  end

  test 'raises a circular reference error reporting the keys involved' do
    store_translations :en, :a => '@{b}', :b => '@{a}'
    exception = assert_raises(I18n::CircularTranslationReference) { I18n.t(:a, :raise => true) }
    assert_equal %w[a b a], exception.keys
    assert_equal 'circular translation reference detected: a -> b -> a', exception.message
  end

  test 'raises a circular reference error for a self reference' do
    store_translations :en, :a => '@{a}'
    exception = assert_raises(I18n::CircularTranslationReference) { I18n.t(:a, :raise => true) }
    assert_equal %w[a a], exception.keys
  end

  test 'raises when a reference resolves to a missing translation' do
    store_translations :en, :greeting => '@{missing} folks'
    assert_raises(I18n::MissingTranslationData) { I18n.t(:greeting, :raise => true) }
  end

  test 'raises when a reference resolves to a non-string value instead of coercing it' do
    store_translations :en, :number => 42, :greeting => 'The answer is @{number}.'
    exception = assert_raises(I18n::InvalidTranslationReference) { I18n.t(:greeting, :raise => true) }
    assert_equal 'number', exception.key
    assert_equal 42, exception.entry
  end

  test 'raises when a reference resolves to a hash' do
    store_translations :en, :nested => { :inner => 'x' }, :greeting => '@{nested}'
    assert_raises(I18n::InvalidTranslationReference) { I18n.t(:greeting, :raise => true) }
  end

  test 'references work together with pluralization' do
    store_translations :en, :salutation => 'Dear', :greeting => { :one => '@{salutation} %{name}, you have one message', :other => '@{salutation} %{name}, you have %{count} messages' }
    assert_equal 'Dear Judy, you have one message', I18n.t(:greeting, :name => 'Judy', :count => 1)
    assert_equal 'Dear Judy, you have 3 messages', I18n.t(:greeting, :name => 'Judy', :count => 3)
  end

  test 'references work together with deep interpolation' do
    store_translations :en, :salutation => 'Dear %{name}', :mailer => { :greeting => '@{salutation},' }
    assert_equal({ :greeting => 'Dear Judy,' }, I18n.t(:mailer, :deep_interpolation => true, :name => 'Judy'))
  end

  test 'resolves references in default values' do
    store_translations :en, :salutation => 'Dear'
    assert_equal 'Dear Judy,', I18n.t(:missing, :default => '@{salutation} %{name},', :name => 'Judy')
  end
end

class I18nBackendTranslationReferenceFallbacksTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Fallbacks
  end

  def setup
    super
    I18n.backend = Backend.new
    I18n.fallbacks = I18n::Locale::Fallbacks.new(:en)
    store_translations :en, :salutation => 'Dear', :greeting => '@{salutation} %{name},'
    store_translations :de, :greeting => '@{salutation} %{name},'
  end

  test 'resolves references using the fallback rules of the current locale' do
    assert_equal 'Dear Judy,', I18n.t(:greeting, :locale => :de, :name => 'Judy')
  end

  test 'resolves references in the locale the entry was found in' do
    store_translations :de, :salutation => 'Sehr geehrte'
    assert_equal 'Sehr geehrte Judy,', I18n.t(:greeting, :locale => :de, :name => 'Judy')
  end
end
