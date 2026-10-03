require 'test_helper'

class I18nBackendPluralizationRangeTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Pluralization
    include I18n::Backend::Fallbacks
  end

  def setup
    super
    I18n.backend = Backend.new
    @rule = lambda { |n| n == 1 ? :one : :other }
    store_translations(:en, :i18n => { :plural => { :rule => @rule } })
    @entry = { :'0' => 'none', :'1' => 'single', :one => 'one', :few => 'few', :other => 'other' }
  end

  test "count_range combines both endpoint categories through a nested Hash range rule" do
    store_translations(:en, :i18n => { :plural => { :range_rule => { :one => { :other => :few } } } })
    assert_equal 'few', I18n.t(:count_range => 1..5, :default => @entry, :locale => :en)
  end

  test "count_range combines both endpoint categories through a flat Hash range rule" do
    store_translations(:en, :i18n => { :plural => { :range_rule => { [:one, :other] => :few } } })
    assert_equal 'few', I18n.t(:count_range => 1..5, :default => @entry, :locale => :en)
  end

  test "count_range combines both endpoint categories through a Proc range rule" do
    store_translations(:en, :i18n => { :plural => { :range_rule => lambda { |start_cat, end_cat| [start_cat, end_cat] == [:one, :other] ? :one : :other } } })
    assert_equal 'one', I18n.t(:count_range => 1..5, :default => @entry, :locale => :en)
  end

  test "count_range pluralizes both endpoints independently instead of only looking at the last number" do
    rule = lambda { |n| n % 10 == 1 && n % 100 != 11 ? :one : :other }
    store_translations(:en, :i18n => { :plural => { :rule => rule } })
    store_translations(:en, :i18n => { :plural => { :range_rule => lambda { |start_cat, end_cat| [start_cat, end_cat] == [:one, :one] ? :few : :other } } })
    # 21 and 31 are both :one; a naive implementation looking only at the
    # last number of the formatted range would never see the :one/:one pair.
    assert_equal 'few', I18n.t(:count_range => 21..31, :default => @entry, :locale => :en)
  end

  test "count_range falls back to the category of the range end when no range rule is configured" do
    assert_equal 'other', I18n.t(:count_range => 1..5, :default => @entry, :locale => :en)
  end

  test "count_range falls back to the category of the range end for pairs missing from the range rule" do
    store_translations(:en, :i18n => { :plural => { :range_rule => { :one => { :one => :few } } } })
    assert_equal 'other', I18n.t(:count_range => 1..5, :default => @entry, :locale => :en)
  end

  test "count_range does Lateral Inheritance to :other to cover missing data" do
    store_translations(:en, :i18n => { :plural => { :range_rule => lambda { |*| :few } } })
    @entry.delete(:few)
    assert_equal 'other', I18n.t(:count_range => 1..5, :default => @entry, :locale => :en)
  end

  test "count_range raises InvalidPluralizationData when the combined category and :other are missing" do
    store_translations(:en, :i18n => { :plural => { :range_rule => lambda { |*| :one } } })
    assert_raises(I18n::InvalidPluralizationData) { I18n.t(:count_range => 2..5, :default => { :few => 'few' }, :locale => :en) }
  end

  test "count_range supports exact decimal endpoints" do
    rule = lambda { |n| n == Rational(3, 2) ? :one : :other }
    store_translations(:en, :i18n => { :plural => { :rule => rule } })
    store_translations(:en, :i18n => { :plural => { :range_rule => lambda { |start_cat, end_cat| start_cat == :one && end_cat == :other ? :few : :other } } })
    assert_equal 'few', I18n.t(:count_range => Rational(3, 2)..Rational(5, 2), :default => @entry, :locale => :en)
  end

  test "count_range with equal endpoints is pluralized as a single count and takes priority over the range rule" do
    store_translations(:en, :i18n => { :plural => { :range_rule => lambda { |*| :few } } })
    assert_equal 'other', I18n.t(:count_range => 3..3, :default => @entry, :locale => :en)
    assert_equal 'single', I18n.t(:count_range => 1..1, :default => @entry, :locale => :en)
    assert_equal 'single', I18n.t(:count_range => 1.0..1, :default => @entry, :locale => :en)
  end

  test "count_range zero range 0..0 uses the explicit 0 rule and takes priority over the range rule" do
    store_translations(:en, :i18n => { :plural => { :range_rule => lambda { |*| :few } } })
    assert_equal 'none', I18n.t(:count_range => 0..0, :default => @entry, :locale => :en)
    assert_equal 'none', I18n.t(:count_range => 0.0..0, :default => @entry, :locale => :en)
  end

  test "count_range zero range 0..0 picks :zero if the key is contained in the data" do
    assert_equal 'zero', I18n.t(:count_range => 0..0, :default => @entry.merge(:zero => 'zero'), :locale => :en)
  end

  test "count_range rejects reversed ranges" do
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => 5..3, :default => @entry, :locale => :en) }
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => [5, 3], :default => @entry, :locale => :en) }
  end

  test "count_range rejects open ranges" do
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => (..5), :default => @entry, :locale => :en) }
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => (3..), :default => @entry, :locale => :en) }
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => [nil, 5], :default => @entry, :locale => :en) }
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => [3, nil], :default => @entry, :locale => :en) }
  end

  test "count_range rejects empty exclusive ranges" do
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => 3...3, :default => @entry, :locale => :en) }
  end

  test "count_range rejects non-numeric endpoints and non-range values" do
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => 'a'..'z', :default => @entry, :locale => :en) }
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => 5, :default => @entry, :locale => :en) }
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => [1, 2, 3], :default => @entry, :locale => :en) }
  end

  test "count_range interpolates %{count} with the formatted range" do
    store_translations(:en, :emails => { :one => '%{count} email', :other => '%{count} emails' })
    assert_equal "3–5 emails", I18n.t(:emails, :count_range => 3..5, :locale => :en)
    assert_equal "1–2.5 emails", I18n.t(:emails, :count_range => 1..2.5, :locale => :en)
  end

  test "count_range with equal endpoints interpolates %{count} with the single value" do
    store_translations(:en, :emails => { :one => '%{count} email', :other => '%{count} emails' })
    assert_equal "3 emails", I18n.t(:emails, :count_range => 3..3, :locale => :en)
  end

  test "count_range accepts a two-element array of endpoints" do
    store_translations(:en, :emails => { :one => '%{count} email', :other => '%{count} emails' })
    assert_equal "3–5 emails", I18n.t(:emails, :count_range => [3, 5], :locale => :en)
  end

  test "count takes precedence over count_range" do
    store_translations(:en, :emails => { :one => '%{count} email', :other => '%{count} emails' })
    assert_equal "1 email", I18n.t(:emails, :count => 1, :count_range => 3..5, :locale => :en)
  end

  test "count_range on a locale without a plural rule falls back to the default implementation" do
    assert_equal 'other', I18n.t(:count_range => 1..5, :default => @entry, :locale => :pirate)
  end

  test "Fallbacks can pick up range rules from fallback locales, too" do
    store_translations(:en, :i18n => { :plural => { :range_rule => { :one => { :other => :few } } } })
    assert_equal 'few', I18n.t(:count_range => 1..5, :default => @entry, :locale => :'en-US')
  end
end

class I18nBackendBasePluralizationRangeTest < I18n::TestCase
  def setup
    super
    I18n.backend = I18n::Backend::Simple.new
    @entry = { :one => 'one', :other => 'other' }
  end

  test "count_range picks :other for any real range by default" do
    assert_equal 'other', I18n.t(:count_range => 1..5, :default => @entry, :locale => :en)
    assert_equal 'other', I18n.t(:count_range => 0..1, :default => @entry, :locale => :en)
  end

  test "count_range with equal endpoints is pluralized as a single count by default" do
    assert_equal 'one', I18n.t(:count_range => 1..1, :default => @entry, :locale => :en)
    assert_equal 'other', I18n.t(:count_range => 3..3, :default => @entry, :locale => :en)
  end

  test "count_range validation also applies without the Pluralization module" do
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => 5..3, :default => @entry, :locale => :en) }
    assert_raises(I18n::InvalidPluralizationRange) { I18n.t(:count_range => (3..), :default => @entry, :locale => :en) }
  end
end
