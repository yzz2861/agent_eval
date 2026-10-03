require 'test_helper'

class I18nLocaleCanonicalTest < I18n::TestCase
  def setup
    super
    I18n.locale_aliases = {
      :iw             => :he,               # legacy language code
      :Cyrl           => :Latn,             # script replacement
      :BU             => :MM,               # region replacement
      :'zh-Hant-TW'   => :'zh-TW',          # explicit whole-tag alias
      :'en-US'        => :en
    }
  end

  test 'canonicalizes legacy language codes' do
    assert_equal :he, I18n.canonical_locale(:iw)
    assert_equal :he, I18n.canonical_locale('iw')
  end

  test 'normalizes inconsistently cased script names and applies script aliases' do
    assert_equal :'sr-Latn', I18n.canonical_locale(:'sr-cyrl')
    assert_equal :'sr-Latn', I18n.canonical_locale(:'sr-CYRL')
    assert_equal :'zh-Hant', I18n.canonical_locale(:'zh-hant')
  end

  test 'replaces region subtags' do
    assert_equal :'he-MM', I18n.canonical_locale(:'iw-BU')
    assert_equal :'he-MM', I18n.canonical_locale(:'iw-bu')
  end

  test 'applies explicit whole-tag aliases regardless of casing' do
    assert_equal :'zh-TW', I18n.canonical_locale(:'zh-Hant-TW')
    assert_equal :'zh-TW', I18n.canonical_locale(:'zh-hant-tw')
  end

  test 'accepts underscore separated tags' do
    assert_equal :en, I18n.canonical_locale(:en_US)
  end

  test 'does not silently drop extension subtags' do
    assert_equal :'he-u-ca-hebrew', I18n.canonical_locale(:'iw-u-ca-hebrew')
    assert_equal :'zh-TW-u-ca-buddhist', I18n.canonical_locale(:'zh-Hant-TW-u-ca-buddhist')
    assert_equal :'de-DE-u-co-phonebk-x-private', I18n.canonical_locale(:'de-DE-u-co-phonebk-x-private')
  end

  test 'resolves alias chains transitively' do
    I18n.locale_aliases = { :'a-aa' => :'b-bb', :'b-bb' => :'c-cc' }
    assert_equal :'c-CC', I18n.canonical_locale(:'a-aa')
  end

  test 'detects circular whole-tag aliases' do
    error = assert_raises(I18n::CircularLocaleAlias) do
      I18n.locale_aliases = { :'en-US' => :'en-GB', :'en-GB' => :'en-US' }
    end
    assert_match(/en-US -> en-GB -> en-US/, error.message)
  end

  test 'detects circular subtag aliases' do
    assert_raises(I18n::CircularLocaleAlias) do
      I18n.locale_aliases = { :iw => :he, :he => :iw }
    end
  end

  test 'returns a Symbol' do
    assert_kind_of Symbol, I18n.canonical_locale('iw-Hebr')
  end
end

class I18nLocaleAliasIntegrationTest < I18n::TestCase
  def setup
    super
    I18n.locale_aliases = { :'en-US' => :en, :iw => :he }
  end

  test 'locale= accepts aliases and stores the canonical locale' do
    begin
      I18n.available_locales = [:en]
      I18n.enforce_available_locales = true
      I18n.locale = :'en-US'
      assert_equal :en, I18n.locale
    ensure
      I18n.enforce_available_locales = false
    end
  end

  test 'available_locales validation accepts aliases of available locales' do
    begin
      I18n.available_locales = [:'en-US']
      I18n.enforce_available_locales = true
      assert_nothing_raised { I18n.locale = :en }
    ensure
      I18n.enforce_available_locales = false
    end
  end

  test 'with_locale accepts aliases' do
    begin
      I18n.available_locales = [:en]
      I18n.enforce_available_locales = true
      I18n.with_locale(:'en-US') do
        assert_equal :en, I18n.locale
      end
    ensure
      I18n.enforce_available_locales = false
    end
  end

  test 'InvalidLocale keeps the original input passed by the caller' do
    begin
      I18n.available_locales = [:en]
      I18n.enforce_available_locales = true
      error = assert_raises(I18n::InvalidLocale) { I18n.locale = :'fr-FR' }
      assert_equal :'fr-FR', error.locale
      assert_match(/fr-FR/, error.message)
    ensure
      I18n.enforce_available_locales = false
    end
  end

  test 'translate shares the lookup identity of the canonical locale' do
    store_translations(:en, :foo => 'bar')
    assert_equal 'bar', I18n.t(:foo, :locale => :'en-US')
    assert_equal 'bar', I18n.t(:foo, :locale => :en)
  end

  test 'fallbacks are computed from the canonical locale and share cache identity' do
    fallbacks = I18n::Locale::Fallbacks.new
    assert_equal [:en], fallbacks[:'en-US']
    assert_same fallbacks[:en], fallbacks[:'en-US']
  end

  test 'fallbacks do not drop extension subtags while canonicalizing' do
    I18n.locale_aliases = { :iw => :he }
    fallbacks = I18n::Locale::Fallbacks.new
    assert_equal :'he-u-ca-hebrew', fallbacks[:'iw-u-ca-hebrew'].first
  end
end
