require 'test_helper'

class I18nDisabledTranslationTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Fallbacks
  end

  def setup
    super
    I18n.backend = Backend.new
    I18n.fallbacks = I18n::Locale::Fallbacks.new(:de => :en, :'de-DE' => [:de, :en])
    store_translations(:en, :promo => { :banner => 'HQ campaign', :tagline => 'HQ tagline' }, :legacy_nil => 'EN legacy')
    store_translations(:de, :promo => { :banner => 'DE Kampagne' })
    store_translations(:'de-DE',
      :promo => {
        :banner => I18n.disabled,
        :note => 'Notiz',
        :nested => { :secret => I18n.disabled, :visible => 'sichtbar' },
        :blocked_section => { :text => I18n.disabled }
      },
      :legacy_nil => nil
    )
  end

  test "I18n.disabled returns the sentinel" do
    assert_same I18n::DisabledTranslation.instance, I18n.disabled
    assert I18n.disabled_translation?(I18n.disabled)
    assert !I18n.disabled_translation?(nil)
    assert !I18n.disabled_translation?('i18n:disabled')
  end

  test "returns nil for a disabled translation" do
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE')
  end

  test "does not fall back to other locales" do
    assert_equal 'DE Kampagne', I18n.t(:'promo.banner', :locale => :de)
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE')
  end

  test "missing keys still fall back" do
    assert_equal 'HQ tagline', I18n.t(:'promo.tagline', :locale => :de)
  end

  test "nil translations keep their old meaning and still fall back" do
    assert_equal 'EN legacy', I18n.t(:legacy_nil, :locale => :'de-DE')
  end

  test "is not bypassed by the :default option" do
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE', :default => 'Default banner')
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE', :default => :'promo.tagline')
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE', :default => ['Default banner'])
  end

  test "missing keys still use the :default option" do
    assert_equal 'Default banner', I18n.t(:'promo.missing', :locale => :'de-DE', :default => 'Default banner')
  end

  test "missing keys still report a missing translation" do
    assert_equal 'Translation missing: de-DE.promo.missing', I18n.t(:'promo.missing', :locale => :'de-DE')
    assert_raises(I18n::MissingTranslationData) { I18n.t(:'promo.missing', :locale => :'de-DE', :raise => true) }
  end

  test "does not raise with :raise or :throw" do
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE', :raise => true)
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE', :throw => true)
  end

  test "ignores interpolation values and count" do
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE', :value => 'x')
    assert_nil I18n.t(:'promo.banner', :locale => :'de-DE', :count => 2)
  end

  test "namespace lookup does not leak the marker and prunes blocked subtrees" do
    expected = { :note => 'Notiz', :nested => { :visible => 'sichtbar' } }
    assert_equal expected, I18n.t(:promo, :locale => :'de-DE')
  end

  test "exists? returns false and does not fall back" do
    assert_equal false, I18n.exists?(:'promo.banner', :locale => :'de-DE')
    assert_equal true,  I18n.exists?(:'promo.banner', :locale => :de)
    assert_equal false, I18n.exists?(:'promo.missing', :locale => :'de-DE')
  end

  test "storing the marker string converts it to the sentinel" do
    store_translations(:en, :promo => { :banner => I18n::DisabledTranslation::MARKER })
    assert_nil I18n.t(:'promo.banner', :locale => :en)
  end

  test "other strings are stored untouched" do
    store_translations(:en, :note => 'i18n:disabled-ish')
    assert_equal 'i18n:disabled-ish', I18n.t(:note, :locale => :en)
  end

  test "storing disabled after a text disables it" do
    store_translations(:de, :promo => { :banner => I18n.disabled })
    assert_nil I18n.t(:'promo.banner', :locale => :de)
  end

  test "storing a text after disabled overwrites it (last write wins)" do
    store_translations(:de, :promo => { :banner => I18n.disabled })
    store_translations(:de, :promo => { :banner => 'Neu' })
    assert_equal 'Neu', I18n.t(:'promo.banner', :locale => :de)
  end

  test "works with a plain Simple backend" do
    I18n.backend = I18n::Backend::Simple.new
    store_translations(:en, :promo => { :banner => I18n.disabled })
    assert_nil I18n.t(:'promo.banner', :locale => :en)
    assert_equal false, I18n.exists?(:'promo.banner', :locale => :en)
  end

  test "can be declared in YAML files" do
    I18n.backend.load_translations(locales_dir + '/disabled.yml')
    assert_nil I18n.t(:'promo.banner', :locale => :xx)
    assert_equal({ :note => 'Notiz' }, I18n.t(:promo, :locale => :xx))
  end

  test "can be declared in JSON files" do
    I18n.backend.load_translations(locales_dir + '/disabled.json')
    assert_nil I18n.t(:'promo.banner', :locale => :xy)
  end

  test "can be declared in Ruby files" do
    I18n.backend.load_translations(locales_dir + '/disabled.rb')
    assert_nil I18n.t(:'promo.banner', :locale => :xz)
  end
end

class I18nDisabledTranslationChainTest < I18n::TestCase
  def setup
    super
    @first = I18n::Backend::Simple.new
    @first.store_translations(:de, :promo => { :banner => I18n.disabled, :local => 'lokal' })
    @second = I18n::Backend::Simple.new
    @second.store_translations(:de, :promo => { :banner => 'HQ campaign', :other => 'anderes' })
    I18n.backend = I18n::Backend::Chain.new(@first, @second)
  end

  test "stops the backend chain" do
    assert_nil I18n.t(:'promo.banner', :locale => :de)
  end

  test "is not bypassed by the :default option" do
    assert_nil I18n.t(:'promo.banner', :locale => :de, :default => 'Default banner')
  end

  test "namespace merge does not resurrect disabled translations" do
    assert_equal({ :local => 'lokal', :other => 'anderes' }, I18n.t(:promo, :locale => :de))
  end

  test "exists? stops the chain" do
    assert_equal false, I18n.exists?(:'promo.banner', :locale => :de)
    assert_equal true,  I18n.exists?(:'promo.other', :locale => :de)
  end
end
