# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

# Tests for using explicit DataSource instances (DataSource#get_timezone,
# DataSource#get_timezone_proxy and DataSource#get_country) alongside the
# process-wide default DataSource, allowing two versions of time zone data
# to be compared within the same process.
class TCDataSourceBinding < Minitest::Test
  include TZInfo

  # An in-memory DataSource that defines a single time zone (Test/Zone)
  # observing a constant UTC offset, a link to it (Test/Linked) and a single
  # country (TS). Two instances with different offsets simulate two versions
  # of the same time zone database.
 class OffsetDataSource < DataSource
    include TZInfo

    def initialize(utc_offset)
      super()
      @utc_offset = utc_offset
    end

    def data_timezone_identifiers
      ['Test/Zone'].freeze
    end

    def linked_timezone_identifiers
      ['Test/Linked'].freeze
    end

    def country_codes
      ['TS'].freeze
    end

    protected

    def load_timezone_info(identifier)
      case identifier
      when 'Test/Zone'
        DataSources::ConstantOffsetDataTimezoneInfo.new('Test/Zone', TimezoneOffset.new(@utc_offset, 0, 'TEST'))
      when 'Test/Linked'
        DataSources::LinkedTimezoneInfo.new('Test/Linked', 'Test/Zone')
      else
        raise InvalidTimezoneIdentifier, identifier
      end
    end

    def load_country_info(code)
      raise InvalidCountryCode, code unless code == 'TS'

      DataSources::CountryInfo.new('TS', 'Test Country', [
        CountryTimezone.new('Test/Zone', Rational(0, 1), Rational(0, 1), 'Test Zone')
      ])
    end
  end

  def setup
    @orig_data_source = DataSource.get
    @data_source1 = OffsetDataSource.new(3600)
    @data_source2 = OffsetDataSource.new(7200)
  end

  def teardown
    DataSource.set(@orig_data_source)
  end

  def utc_total_offset(timezone)
    timezone.period_for_utc(Time.utc(2020, 1, 1)).utc_total_offset
  end

  def test_get_timezone_uses_the_data_source_it_is_called_on
    assert_equal(3600, utc_total_offset(@data_source1.get_timezone('Test/Zone')))
    assert_equal(7200, utc_total_offset(@data_source2.get_timezone('Test/Zone')))
  end

  def test_get_timezone_linked_zone_resolves_within_the_same_data_source
    linked1 = @data_source1.get_timezone('Test/Linked')
    linked2 = @data_source2.get_timezone('Test/Linked')

    assert_kind_of(LinkedTimezone, linked1)
    assert_kind_of(LinkedTimezone, linked2)
    assert_equal(3600, utc_total_offset(linked1))
    assert_equal(7200, utc_total_offset(linked2))
    assert_equal('Test/Zone', linked1.canonical_zone.identifier)
  end

  def test_get_timezone_linked_zone_is_unaffected_by_default_data_source_change
    linked = @data_source1.get_timezone('Test/Linked')
    DataSource.set(@data_source2)

    assert_equal(3600, utc_total_offset(linked))
  end

  def test_get_timezone_proxy_remains_bound_after_default_data_source_change
    proxy = @data_source1.get_timezone_proxy('Test/Zone')
    DataSource.set(@data_source2)

    assert_kind_of(TimezoneProxy, proxy)
    assert_equal(3600, utc_total_offset(proxy))
  end

  def test_timezone_get_uses_the_current_default_data_source
    DataSource.set(@data_source1)
    assert_equal(3600, utc_total_offset(Timezone.get('Test/Zone')))

    DataSource.set(@data_source2)
    assert_equal(7200, utc_total_offset(Timezone.get('Test/Zone')))
  end

  def test_timezone_get_proxy_is_bound_to_the_default_data_source_at_creation
    DataSource.set(@data_source1)
    proxy = Timezone.get_proxy('Test/Zone')

    DataSource.set(@data_source2)
    assert_equal(3600, utc_total_offset(proxy))
  end

  def test_timezone_get_linked_zone_resolves_within_the_default_data_source_at_creation
    DataSource.set(@data_source1)
    linked = Timezone.get('Test/Linked')

    DataSource.set(@data_source2)
    assert_equal(3600, utc_total_offset(linked))
  end

  def test_get_country_zones_use_the_same_data_source
    country1 = @data_source1.get_country('TS')
    country2 = @data_source2.get_country('TS')

    DataSource.set(@data_source2)

    assert_equal(3600, utc_total_offset(country1.zones.first))
    assert_equal(7200, utc_total_offset(country2.zones.first))
  end

  def test_country_get_binds_the_default_data_source_at_creation
    DataSource.set(@data_source1)
    country = Country.get('TS')

    DataSource.set(@data_source2)
    assert_equal(3600, utc_total_offset(country.zones.first))
  end

  def test_country_timezone_timezone_with_explicit_data_source
    country_timezone = CountryTimezone.new('Test/Zone', Rational(0, 1), Rational(0, 1))
    DataSource.set(@data_source2)

    assert_equal(3600, utc_total_offset(country_timezone.timezone(@data_source1)))
    assert_equal(7200, utc_total_offset(country_timezone.timezone))
  end

  def test_timezone_info_cache_is_scoped_to_each_data_source
    info1 = @data_source1.get_timezone_info('Test/Zone')
    info2 = @data_source2.get_timezone_info('Test/Zone')

    refute_same(info1, info2)
    assert_same(info1, @data_source1.get_timezone_info('Test/Zone'))
    assert_same(info2, @data_source2.get_timezone_info('Test/Zone'))
    assert_equal(3600, info1.constant_offset.base_utc_offset)
    assert_equal(7200, info2.constant_offset.base_utc_offset)
  end

  def test_marshal_proxy_preserves_the_bound_data_source
    proxy = @data_source1.get_timezone_proxy('Test/Zone')
    DataSource.set(@data_source2)

    loaded = Marshal.load(Marshal.dump(proxy))

    assert_kind_of(TimezoneProxy, loaded)
    assert_equal('Test/Zone', loaded.identifier)
    assert_equal(3600, utc_total_offset(loaded))
  end

  def test_marshal_proxies_bound_to_different_data_sources_retain_their_identities
    proxy1 = @data_source1.get_timezone_proxy('Test/Zone')
    proxy2 = @data_source2.get_timezone_proxy('Test/Zone')

    loaded1 = Marshal.load(Marshal.dump(proxy1))
    loaded2 = Marshal.load(Marshal.dump(proxy2))

    assert_equal(3600, utc_total_offset(loaded1))
    assert_equal(7200, utc_total_offset(loaded2))
  end

  def test_load_proxy_with_unresolvable_data_source_token_falls_back_to_default
    DataSource.set(@data_source2)

    loaded = TimezoneProxy._load("999999999\nTest/Zone")

    assert_kind_of(TimezoneProxy, loaded)
    assert_equal(7200, utc_total_offset(loaded))
  end

  def test_load_proxy_legacy_format_binds_the_current_default_data_source
    # Earlier versions of TZInfo serialized proxies as just the identifier.
    DataSource.set(@data_source2)
    loaded = TimezoneProxy._load('Test/Zone')

    assert_kind_of(TimezoneProxy, loaded)
    assert_equal(7200, utc_total_offset(loaded))
  end

  def test_thread_interleaved_queries
    DataSource.set(@data_source1)
    errors = Queue.new

    # Continuously switch the default DataSource whilst bound queries are
    # being performed from other threads.
    switcher = Thread.new do
      100.times do
        DataSource.set(@data_source1)
        DataSource.set(@data_source2)
      end
    end

    queriers = [[@data_source1, 3600], [@data_source2, 7200]].map do |data_source, offset|
      Thread.new do
        100.times do
          errors << [:timezone, offset] unless utc_total_offset(data_source.get_timezone('Test/Zone')) == offset
          errors << [:proxy, offset] unless utc_total_offset(data_source.get_timezone_proxy('Test/Zone')) == offset
          errors << [:linked, offset] unless utc_total_offset(data_source.get_timezone('Test/Linked')) == offset
          errors << [:country, offset] unless utc_total_offset(data_source.get_country('TS').zones.first) == offset
        end
      end
    end

    ([switcher] + queriers).each(&:join)

    assert_equal(0, errors.size, "#{errors.size} bound queries resolved against the wrong DataSource")
  end
end
