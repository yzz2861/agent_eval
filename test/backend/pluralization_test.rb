require 'test_helper'

class I18nBackendPluralizationTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Pluralization
    include I18n::Backend::Fallbacks
  end

  def setup
    super
    I18n.backend = Backend.new
    @rule = lambda { |n| n % 10 == 1 && n % 100 != 11 ? :one : n == 0 || (2..10).include?(n % 100) ? :few : (11..19).include?(n % 100) ? :many : :other }
    @range_rule = {
      :one => { :many => :other },
      :few => { :few => :one, :many => :many },
      :other => { :few => :many }
    }
    store_translations(:xx, :i18n => { :plural => { :rule => @rule, :range => { :rule => @range_rule } } })
    @entry = { :"0" => 'none', :"1" => 'single', :one => 'one', :few => 'few', :many => 'many', :other => 'other' }
    @entry_with_zero = @entry.merge( { :zero => 'zero' } )
  end

  test "pluralization picks a pluralizer from :'i18n.pluralize'" do
    assert_equal @rule, I18n.backend.send(:pluralizer, :xx)
  end

  test "pluralization picks the explicit 1 rule for count == 1, the explicit rule takes priority over the matching :one rule" do
    assert_equal 'single', I18n.t(:count => 1, :default => @entry, :locale => :xx)
    assert_equal 'single', I18n.t(:count => 1.0, :default => @entry, :locale => :xx)
  end

  test "pluralization picks :one for 1, since in this case that is the matching rule for 1 (when there is no explicit 1 rule)" do
    @entry.delete(:"1")
    assert_equal 'one', I18n.t(:count => 1, :default => @entry, :locale => :xx)
  end

  test "pluralization picks :few for 2" do
    assert_equal 'few', I18n.t(:count => 2, :default => @entry, :locale => :xx)
  end

  test "pluralization uses the categories of both count range endpoints and interpolates the range" do
    @entry[:one] = '%{count_range} piece'
    @entry[:many] = '%{count_range} pieces'

    assert_equal '3–5 piece', I18n.t(:count_range => 3..5, :default => @entry, :locale => :xx)
    assert_equal '3–11 pieces', I18n.t(:count_range => 3..11, :default => @entry, :locale => :xx)
  end

  test "pluralization passes exact decimal count range endpoints to the pluralizer" do
    start_count = Rational('1.10')
    end_count = Rational('2.20')
    received = []
    decimal_rule = lambda do |count|
      received << count
      count == start_count ? :one : count == end_count ? :two : :other
    end
    decimal_range_rule = { :one => { :two => :many } }
    store_translations(:xd,
      :i18n => { :plural => { :rule => decimal_rule, :range => { :rule => decimal_range_rule } } })
    entry = { :many => '%{count_range} pieces' }

    assert_equal '11/10–11/5 pieces', I18n.t(:count_range => start_count..end_count,
      :default => entry, :locale => :xd)
    assert_equal [start_count, end_count], received
  end

  test "pluralization treats a zero count range as an explicit zero count before range rules" do
    assert_equal 'none', I18n.t(:count_range => 0..0, :default => @entry, :locale => :xx)
    assert_equal 'zero', I18n.t(:count_range => 0.0..0.0, :default => @entry_with_zero, :locale => :xx)
  end

  test "pluralization does not apply count zero special cases to a non-singleton zero endpoint" do
    @range_rule[:few][:other] = :other
    store_translations(:xx, :i18n => { :plural => { :rule => @rule, :range => { :rule => @range_rule } } })

    assert_equal 'other', I18n.t(:count_range => 0..20, :default => @entry, :locale => :xx)
    assert_equal 'other', I18n.t(:count_range => 0..20, :default => @entry_with_zero, :locale => :xx)
  end

  test "pluralization treats a single-value count range with the existing count priority" do
    assert_equal 'single', I18n.t(:count_range => 1..1, :default => @entry, :locale => :xx)
    assert_equal 'few', I18n.t(:count_range => 2..2, :default => @entry, :locale => :xx)
  end

  test "pluralization rejects reversed, open-ended, half-open, non-numeric, and non-range count ranges" do
    assert_raises(I18n::InvalidCountRange) do
      I18n.t(:count_range => 5..3, :default => @entry, :locale => :xx)
    end
    assert_raises(I18n::InvalidCountRange) { I18n.t(:count_range => 3.., :default => @entry, :locale => :xx) }
    assert_raises(I18n::InvalidCountRange) { I18n.t(:count_range => ..5, :default => @entry, :locale => :xx) }
    assert_raises(I18n::InvalidCountRange) do
      I18n.t(:count_range => 3...5, :default => @entry, :locale => :xx)
    end
    assert_raises(I18n::InvalidCountRange) do
      I18n.t(:count_range => '3'..'5', :default => @entry, :locale => :xx)
    end
    assert_raises(I18n::InvalidCountRange) do
      I18n.t(:count_range => [3, 5], :default => @entry, :locale => :xx)
    end
  end

  test "pluralization raises when the locale has no count range category table" do
    store_translations(:xy, :i18n => { :plural => { :rule => @rule } })

    assert_raises(I18n::ArgumentError) do
      I18n.t(:count_range => 3..5, :default => @entry, :locale => :xy)
    end
  end

  test "pluralization raises when the selected range category is absent from the entry" do
    entry = @entry.dup
    entry.delete(:many)
    entry.delete(:other)

    assert_raises(I18n::InvalidPluralizationData) do
      I18n.t(:count_range => 3..11, :default => entry, :locale => :xx)
    end
  end

  test "pluralization picks :many for 11" do
    assert_equal 'many', I18n.t(:count => 11, :default => @entry, :locale => :xx)
  end

  test "pluralization picks zero for 0 if the key is contained in the data" do
    assert_equal 'zero', I18n.t(:count => 0, :default => @entry_with_zero, :locale => :xx)
  end

  test "pluralization picks explicit 0 rule for count == 0, since the explicit rule takes priority over the matching :few rule" do
    assert_equal 'none', I18n.t(:count => 0, :default => @entry, :locale => :xx)
    assert_equal 'none', I18n.t(:count => 0.0, :default => @entry, :locale => :xx)
    assert_equal 'none', I18n.t(:count => -0, :default => @entry, :locale => :xx)
  end

  test "pluralization picks :few for 0 (when there is no explicit 0 rule)" do
    @entry.delete(:"0")
    assert_equal 'few', I18n.t(:count => 0, :default => @entry, :locale => :xx)
  end

  test "pluralization does Lateral Inheritance to :other to cover missing data" do
    @entry.delete(:many)
    assert_equal 'other', I18n.t(:count => 11, :default => @entry, :locale => :xx)
  end

  test "pluralization picks one for 1 if the entry has attributes hash on unknown locale" do
    @entry[:attributes] = { :field => 'field', :second => 'second' }
    assert_equal 'one', I18n.t(:count => 1, :default => @entry, :locale => :pirate)
  end

  test "Nested keys within pluralization context" do
    store_translations(:xx,
      :stars => {
        one: "%{count} star",
        other: "%{count} stars",
        special: {
          one: "%{count} special star",
          other: "%{count} special stars",
        }
      }
    )
    assert_equal "1 star", I18n.t('stars', count: 1, :locale => :xx)
    assert_equal "20 stars", I18n.t('stars', count: 20, :locale => :xx)
    assert_equal "1 special star", I18n.t('stars.special', count: 1, :locale => :xx)
    assert_equal "20 special stars", I18n.t('stars.special', count: 20, :locale => :xx)
  end

  test "Fallbacks can pick up rules from fallback locales, too" do
    assert_equal @rule, I18n.backend.send(:pluralizer, :'xx-XX')
  end

  test "linked lookup works with pluralization backend" do
    I18n.backend.store_translations(:xx, {
      :automobiles => :autos,
      :autos => :cars,
      :cars => { :porsche => { :one => "I have %{count} Porsche 🚗", :other => "I have %{count} Porsches 🚗" } }
    })
    assert_equal "I have 1 Porsche 🚗", I18n.t(:'automobiles.porsche', count: 1, :locale => :xx)
    assert_equal "I have 20 Porsches 🚗", I18n.t(:'automobiles.porsche', count: 20, :locale => :xx)
  end
end
