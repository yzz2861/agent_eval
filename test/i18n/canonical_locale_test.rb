# frozen_string_literal: true

require 'test_helper'

class I18nCanonicalLocaleTest < I18n::TestCase
  class HashStore
    def initialize
      @store = {}
    end

    attr_reader :store

    def read(key)
      @store[key]
    end

    def write(key, value)
      @store[key] = value
    end

    def clear
      @store.clear
    end
  end

  class FallbackBackend < I18n::Backend::Simple
    include I18n::Backend::Fallbacks
  end

  ALIASES = {
    language: { iw: :he },
    script: { hant: :Hant },
    region: { us: :US },
    tag: { :'zh-TW' => :'zh-Hant-TW' }
  }.freeze

  def setup
    super
    I18n.backend = FallbackBackend.new
    I18n.locale_aliases = ALIASES
  end

  test "canonical_locale maps equivalent identifiers" do
    assert_equal :he, I18n.canonical_locale(:iw)
    assert_equal :'zh-Hant-TW', I18n.canonical_locale('zh-tw')
    assert_equal :'en-US', I18n.canonical_locale(:'en-us')
    assert_equal :'de-DE-u-ca-gregory', I18n.canonical_locale(:'de-de-u-ca-gregory')
  end

  test "equivalent identifiers share stored translations and lookups" do
    store_translations(:'zh-Hant-TW', foo: 'TW')
    assert_equal 'TW', I18n.t(:foo, locale: 'zh-TW')
    assert_equal 'TW', I18n.t(:foo, locale: :'zh-hant-tw')
  end

  test "storing through an alias merges into the canonical locale" do
    store_translations('zh-TW', foo: 'TW')
    assert_equal 'TW', I18n.t(:foo, locale: :'zh-Hant-TW')
  end

  test "available_locales validation accepts aliases" do
    I18n.enforce_available_locales = true
    I18n.available_locales = [:'zh-Hant-TW', :en]
    assert_nothing_raised { I18n.t(:foo, locale: 'zh-tw') }
    assert I18n.locale_available?('zh-TW')
  end

  test "unavailable aliases still raise with the original input" do
    I18n.enforce_available_locales = true
    I18n.available_locales = [:en]
    error = assert_raises(I18n::InvalidLocale) { I18n.t(:foo, locale: 'zh-TW') }
    assert_equal 'zh-TW', error.locale
    assert_match(/"zh-TW"/, error.message)
  end

  test "locale= accepts aliases and stores the canonical identity" do
    I18n.enforce_available_locales = true
    I18n.available_locales = [:'zh-Hant-TW', :en]
    store_translations(:'zh-Hant-TW', foo: 'TW')
    I18n.locale = 'zh-tw'
    assert_equal :'zh-Hant-TW', I18n.locale
    assert_equal 'TW', I18n.t(:foo)
  end

  test "with_locale accepts aliases and restores the previous locale" do
    I18n.enforce_available_locales = true
    I18n.available_locales = [:'zh-Hant-TW', :en]
    store_translations(:'zh-Hant-TW', foo: 'TW')
    I18n.locale = :en
    I18n.with_locale('zh-TW') do
      assert_equal :'zh-Hant-TW', I18n.locale
      assert_equal 'TW', I18n.t(:foo)
    end
    assert_equal :en, I18n.locale
  end

  test "with_locale raises InvalidLocale with the original input preserved" do
    I18n.enforce_available_locales = true
    I18n.available_locales = [:en]
    error = assert_raises(I18n::InvalidLocale) do
      I18n.with_locale('zh-TW') { }
    end
    assert_equal 'zh-TW', error.locale
  end

  test "default_locale accepts aliases" do
    I18n.enforce_available_locales = true
    I18n.available_locales = [:'zh-Hant-TW', :en]
    I18n.default_locale = 'zh-tw'
    assert_equal :'zh-Hant-TW', I18n.default_locale
  end

  test "extensions survive fallback generation" do
    fallbacks = I18n::Locale::Fallbacks.new(:en)
    I18n.fallbacks = fallbacks
    store_translations(:en, foo: 'en bar')
    store_translations(:de, foo: 'de bar')
    assert_equal [:'de-DE-u-ca-gregory', :'de-u-ca-gregory', :'de-DE', :de, :en], fallbacks[:'de-de-u-ca-gregory']
    assert_equal 'de bar', I18n.t(:foo, locale: 'de-de-u-ca-gregory')
  end

  test "aliases share fallback chains" do
    fallbacks = I18n::Locale::Fallbacks.new
    assert_equal fallbacks[:'en-US'], fallbacks[:'en-us']
  end

  test "fallback mappings accept aliases on both sides" do
    fallbacks = I18n::Locale::Fallbacks.new
    fallbacks.map('iw' => 'zh-tw')
    assert_equal [:he, :'zh-Hant-TW', :'zh-Hant', :zh], fallbacks[:iw]
  end

  test "setting an alias table with a cycle raises LocaleAliasCycle" do
    assert_raises(I18n::LocaleAliasCycle) do
      I18n.locale_aliases = { language: { aa: :bb, bb: :aa } }
    end
  end

  test "equivalent identifiers share cache keys" do
    backend = Class.new(I18n::Backend::Simple) { include I18n::Backend::Cache }.new
    I18n.backend = backend
    store = HashStore.new
    I18n.cache_store = store
    store_translations(:'zh-Hant-TW', foo: 'TW')

    assert_equal 'TW', I18n.t(:foo, locale: 'zh-TW')
    assert_equal 1, store.store.size
    backend.expects(:lookup).never
    assert_equal 'TW', I18n.t(:foo, locale: :'zh-hant-tw')
  ensure
    I18n.cache_store = nil
  end
end
