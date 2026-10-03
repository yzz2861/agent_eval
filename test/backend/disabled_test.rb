require 'test_helper'

class I18nBackendDisabledTranslationTest < I18n::TestCase
  def setup
    super
    I18n.available_locales = [:en, :de, :'de-DE', :fr]
    I18n.backend = I18n::Backend::Simple.new
  end

  test "I18n::DISABLED is a frozen marker that identifies itself as disabled" do
    assert I18n::DISABLED.frozen?
    assert I18n::DISABLED.disabled?
    refute I18n::MissingTranslation.new(:en, :x).disabled?
  end

  test "a disabled leaf resolves to a disabled translation message" do
    I18n.backend.store_translations(:de, promo: I18n::DISABLED)
    assert_equal "Translation disabled: de.promo", I18n.t(:promo, locale: :de)
  end

  test "t! raises a distinct DisabledTranslationData error" do
    I18n.backend.store_translations(:de, promo: I18n::DISABLED)
    error = assert_raises(I18n::DisabledTranslationData) do
      I18n.t!(:promo, locale: :de)
    end
    assert_kind_of I18n::MissingTranslationData, error
    assert_match(/disabled/, error.message)
  end

  test "the textual token can declare a key disabled in memory" do
    I18n.backend.store_translations(:de, promo: I18n::DISABLED_TOKEN)
    assert_equal "Translation disabled: de.promo", I18n.t(:promo, locale: :de)
  end

  test "disabled is distinct from nil (nil stays missing)" do
    I18n.backend.store_translations(:de, present: 'here', missing_like: nil)
    assert_nil I18n.backend.send(:lookup, :de, :missing_like)
    assert_equal 'here', I18n.backend.send(:lookup, :de, :present)
  end

  test "a disabled leaf inside a namespace hash is pruned but siblings remain" do
    I18n.backend.store_translations(:fr, ns: { a: I18n::DISABLED, b: 'B', c: { d: I18n::DISABLED, e: 'E' } })
    assert_equal({ b: 'B', c: { e: 'E' } }, I18n.t(:ns, locale: :fr))
  end

  test "a disabled element inside an array becomes nil without shifting other elements" do
    I18n.backend.store_translations(:fr, list: [I18n::DISABLED, 'x'])
    assert_equal [nil, 'x'], I18n.t(:list, locale: :fr)
  end
end

class I18nBackendDisabledFallbacksTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Fallbacks
    include I18n::Backend::Pluralization
  end

  def setup
    super
    I18n.available_locales = [:en, :de, :'de-DE']
    I18n.backend = Backend.new
    I18n.fallbacks = I18n::Locale::Fallbacks.new
    I18n.fallbacks[:de] = [:de, :en]
    I18n.fallbacks[:'de-DE'] = [:'de-DE', :de, :en]
    store_translations(:en, promo: 'HQ promo', other: 'EN other')
    store_translations(:en, items: { one: 'one en', other: 'other en' })
    store_translations(:de, promo: I18n::DISABLED)
    store_translations(:de, items: I18n::DISABLED)
  end

  test "a disabled key does not fall back to a parent/default locale" do
    assert_equal "Translation disabled: de.promo", I18n.t(:promo, locale: :de)
  end

  test "a disabled parent locale blocks a more specific locale too" do
    assert_equal "Translation disabled: de-DE.promo", I18n.t(:promo, locale: :'de-DE')
  end

  test "a string default cannot override a disabled key" do
    assert_equal "Translation disabled: de.promo",
      I18n.t(:promo, locale: :de, default: 'default text')
  end

  test "a symbol default cannot override a disabled key" do
    assert_equal "Translation disabled: de.promo",
      I18n.t(:promo, locale: :de, default: :other)
  end

  test "an array default cannot override a disabled key" do
    assert_equal "Translation disabled: de.promo",
      I18n.t(:promo, locale: :de, default: [:other, 'default text'])
  end

  test "a proc default cannot override a disabled key" do
    assert_equal "Translation disabled: de.promo",
      I18n.t(:promo, locale: :de, default: -> { 'proc default' })
  end

  test "a genuinely missing key still falls back" do
    assert_equal 'EN other', I18n.t(:other, locale: :de)
  end

  test "exists? is false for a disabled key in the current locale" do
    refute I18n.exists?(:promo, locale: :de)
  end

  test "exists? does not report a disabled key via a fallback locale" do
    refute I18n.exists?(:promo, locale: :'de-DE')
  end

  test "exists? is true for a normal fallback key" do
    assert I18n.exists?(:other, locale: :de)
  end

  test "a disabled pluralization key stays disabled for every count" do
    assert_equal "Translation disabled: de.items", I18n.t(:items, locale: :de, count: 1)
    assert_equal "Translation disabled: de.items", I18n.t(:items, locale: :de, count: 5)
  end
end

class I18nBackendDisabledChainTest < I18n::TestCase
  def setup
    super
    I18n.available_locales = [:en, :de]
    @first  = I18n::Backend::Simple.new
    @second = I18n::Backend::Simple.new
    I18n.backend = I18n::Backend::Chain.new(@first, @second)
    @second.store_translations(:en, promo: 'HQ promo', other: 'OTHER', ns: { a: 'A second', b: 'B second' })
    @first.store_translations(:de, promo: I18n::DISABLED)
    @first.store_translations(:en, ns: { a: I18n::DISABLED })
  end

  test "a disabled key in an earlier backend stops later backend lookup" do
    assert_equal "Translation disabled: de.promo", I18n.t(:promo, locale: :de)
  end

  test "a default cannot bypass a disabled key in the chain" do
    assert_equal "Translation disabled: de.promo", I18n.t(:promo, locale: :de, default: 'X')
  end

  test "non-disabled keys are still found in a later backend" do
    assert_equal 'OTHER', I18n.t(:other, locale: :en)
  end

  test "exists? is false for a disabled key and true for a normal one" do
    refute I18n.exists?(:promo, locale: :de)
    assert I18n.exists?(:other, locale: :en)
  end

  test "a disabled leaf is not resurrected when namespaces are merged" do
    assert_equal({ b: 'B second' }, I18n.t(:ns, locale: :en))
  end
end

class I18nBackendDisabledChainWithFallbacksTest < I18n::TestCase
  class ChainWithFallbacks < I18n::Backend::Chain
    include I18n::Backend::Fallbacks
  end

  def setup
    super
    I18n.available_locales = [:en, :de, :'de-DE']
    first  = I18n::Backend::Simple.new
    second = I18n::Backend::Simple.new
    I18n.backend = ChainWithFallbacks.new(first, second)
    I18n.fallbacks = I18n::Locale::Fallbacks.new
    I18n.fallbacks[:'de-DE'] = [:'de-DE', :de, :en]
    second.store_translations(:en, promo: 'EN HQ', only_en: 'YEP')
    first.store_translations(:de, promo: I18n::DISABLED)
  end

  test "a disabled parent locale blocks a specific locale across chain and fallbacks" do
    assert_equal "Translation disabled: de-DE.promo", I18n.t(:promo, locale: :'de-DE')
  end

  test "exists? is false for a key disabled in a fallback locale" do
    refute I18n.exists?(:promo, locale: :'de-DE')
  end

  test "a genuinely missing key still falls back through chain and fallbacks" do
    assert_equal 'YEP', I18n.t(:only_en, locale: :'de-DE')
  end
end

class I18nBackendDisabledDeepMergeTest < I18n::TestCase
  def setup
    super
    I18n.available_locales = [:de]
    I18n.backend = I18n::Backend::Simple.new
  end

  test "a later deep merge keeps an explicitly disabled leaf disabled" do
    I18n.backend.store_translations(:de, page: { title: 'HQ title', body: 'HQ body' })
    I18n.backend.store_translations(:de, page: { title: I18n::DISABLED })
    assert_equal({ body: 'HQ body' }, I18n.t(:page, locale: :de))
    assert_equal "Translation disabled: de.page.title", I18n.t(:'page.title', locale: :de)
  end

  test "the marker is sticky even when text is merged afterwards" do
    backend = I18n::Backend::Simple.new
    backend.store_translations(:de, promo: I18n::DISABLED)
    backend.store_translations(:de, promo: 'later text')
    marker = backend.send(:lookup, :de, :promo)
    assert marker.respond_to?(:disabled?) && marker.disabled?
  end

  test "normal values can still be replaced by a later merge" do
    backend = I18n::Backend::Simple.new
    backend.store_translations(:de, key: 'v1')
    backend.store_translations(:de, key: 'v2')
    assert_equal 'v2', backend.send(:lookup, :de, :key)
  end
end

class I18nBackendDisabledFileLoadingTest < I18n::TestCase
  def setup
    super
    I18n.available_locales = [:en, :de, :fr, :es]
    I18n.backend = I18n::Backend::Simple.new
    I18n.load_path = [
      locales_dir + '/disabled.yml',
      locales_dir + '/disabled.json',
      locales_dir + '/disabled.rb',
    ]
  end

  test "a YAML token disables the key while other locales keep their text" do
    assert_equal 'HQ text', I18n.t(:hq_text, locale: :en)
    assert_equal "Translation disabled: de.hq_text", I18n.t(:hq_text, locale: :de)
  end

  test "a JSON token disables the key" do
    assert_equal "Translation disabled: fr.hq_text", I18n.t(:hq_text, locale: :fr)
  end

  test "a Ruby file can use the I18n::DISABLED constant" do
    assert_equal "Translation disabled: es.hq_text", I18n.t(:hq_text, locale: :es)
  end

  test "a disabled leaf inside a namespace does not leak" do
    namespace = I18n.t(:campaign, locale: :de)
    refute namespace.values.any? { |v| v.respond_to?(:disabled?) && v.disabled? }
    assert_equal 'Regionale Untertitel', namespace[:subtitle]
  end
end

class I18nBackendDisabledKeyValueTest < I18n::TestCase
  def setup
    super
    I18n.available_locales = [:en, :de]
    I18n.backend = I18n::Backend::KeyValue.new({})
    store_translations(:en, promo: 'HQ promo', other: 'OTHER')
    store_translations(:de, promo: I18n::DISABLED)
  end

  test "a disabled key survives JSON round-tripping in a key/value store" do
    assert_equal "Translation disabled: de.promo", I18n.t(:promo, locale: :de)
  end

  test "exists? is false for a disabled key in a key/value store" do
    refute I18n.exists?(:promo, locale: :de)
    assert I18n.exists?(:other, locale: :en)
  end

  test "a normal key still resolves from a key/value store" do
    assert_equal 'OTHER', I18n.t(:other, locale: :en)
  end
end if I18n::TestCase.key_value?
