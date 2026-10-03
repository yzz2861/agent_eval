# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

# Tests for time zones and countries that are explicitly bound to a specific
# DataSource, allowing two different versions of the time zone database to be
# used concurrently within the same process.
class TCDataSourceBinding < Minitest::Test
  include TZInfo

  # An in-memory DataSource. Every data time zone observes a constant offset
  # and every linked time zone is a link to the same-named data zone.
  class InMemoryDataSource < DataSource
    attr_reader :version

    def initialize(version, offset, with_country = false)
      super()
      @version = version
      @offset = offset
      @with_country = with_country
    end

    def to_s
      "InMemory DataSource #{@version}"
    end

    def data_timezone_identifiers
      ['Test/Zone']
    end

    def linked_timezone_identifiers
      ['Test/Link']
    end

    def country_codes
      @with_country ? ['TT'] : []
    end

    def observed_offset
      @offset
    end

    protected

    def load_timezone_info(identifier)
      validate_timezone_identifier(identifier)

      if identifier == 'Test/Link'
        TZInfo::DataSources::LinkedTimezoneInfo.new(identifier, 'Test/Zone')
      else
        offset = TZInfo::TimezoneOffset.new(@offset, 0, "V#{@version}")
        TZInfo::DataSources::ConstantOffsetDataTimezoneInfo.new(identifier, offset)
      end
    end

    def load_country_info(code)
      zones = [TZInfo::CountryTimezone.new('Test/Link', Rational(1, 1), Rational(2, 1))]
      lookup_country_info({'TT' => TZInfo::DataSources::CountryInfo.new('TT', 'Test Country', zones)}, code)
    end
  end

  TIME = Time.utc(2020, 1, 1)

  def setup
    @orig_data_source = DataSource.get
    @source1 = InMemoryDataSource.new(1, 3600, true)
    @source2 = InMemoryDataSource.new(2, 7200, true)
  end

  def teardown
    DataSource.set(@orig_data_source)
  end

  def test_same_identifier_returns_different_offsets
    tz1 = @source1.get_timezone('Test/Zone')
    tz2 = @source2.get_timezone('Test/Zone')

    assert_equal(3600, tz1.observed_utc_offset(TIME))
    assert_equal(7200, tz2.observed_utc_offset(TIME))
  end

  def test_get_with_explicit_data_source
    DataSource.set(@source2)

    tz = Timezone.get('Test/Zone', @source1)
    assert_equal(3600, tz.observed_utc_offset(TIME))
    assert_equal(7200, Timezone.get('Test/Zone').observed_utc_offset(TIME))
  end

  def test_bound_timezone_unaffected_by_default_change
    tz = @source1.get_timezone('Test/Zone')
    DataSource.set(@source2)

    assert_equal(3600, tz.observed_utc_offset(TIME))
  end

  def test_linked_timezone_uses_bound_data_source
    link1 = @source1.get_timezone('Test/Link')
    link2 = @source2.get_timezone('Test/Link')

    assert_kind_of(LinkedTimezone, link1)
    assert_equal(3600, link1.observed_utc_offset(TIME))
    assert_equal(7200, link2.observed_utc_offset(TIME))

    assert_equal(3600, link1.canonical_zone.observed_utc_offset(TIME))
    assert_equal(7200, link2.canonical_zone.observed_utc_offset(TIME))

    DataSource.set(@source2)
    assert_equal(3600, link1.observed_utc_offset(TIME))
  end

  def test_proxy_is_lazy_and_pinned_to_bound_data_source
    proxy = @source1.get_timezone_proxy('Test/Zone')
    assert_kind_of(TimezoneProxy, proxy)

    DataSource.set(@source2)

    assert_equal(3600, proxy.observed_utc_offset(TIME))
  end

  def test_proxy_created_before_set_change_pins_default_at_creation
    DataSource.set(@source1)
    proxy = Timezone.get_proxy('Test/Zone')
    DataSource.set(@source2)

    assert_equal(3600, proxy.observed_utc_offset(TIME))
  end

  def test_directly_constructed_proxy_resolves_lazily_when_no_default
    proxy = TimezoneProxy.new('Test/Zone')
    DataSource.set(@source1)

    assert_equal(3600, proxy.observed_utc_offset(TIME))

    DataSource.set(@source2)
    assert_equal(3600, proxy.observed_utc_offset(TIME))
  end

  def test_frozen_bound_proxy_resolves_against_bound_data_source
    proxy = @source1.get_timezone_proxy('Test/Zone')
    proxy.freeze
    DataSource.set(@source2)

    assert_equal(3600, proxy.observed_utc_offset(TIME))
    assert_equal(3600, proxy.observed_utc_offset(TIME))
  end

  def test_country_zones_use_bound_data_source
    country1 = @source1.get_country('TT')
    country2 = @source2.get_country('TT')

    zone1 = country1.zones.first
    zone2 = country2.zones.first

    assert_kind_of(TimezoneProxy, zone1)
    assert_equal(3600, zone1.observed_utc_offset(TIME))
    assert_equal(7200, zone2.observed_utc_offset(TIME))

    DataSource.set(@source2)
    assert_equal(3600, zone1.observed_utc_offset(TIME))
  end

  def test_concurrent_threads_interleaved_with_default_change
    DataSource.set(@source1)

    bound1 = @source1.get_timezone_proxy('Test/Zone')
    bound2 = @source2.get_timezone_proxy('Test/Zone')
    pinned1 = Timezone.get_proxy('Test/Zone')

    results = Array.new(4) { [] }
    start = Queue.new
    ready = Queue.new

    workers = [
      -> { bound1.observed_utc_offset(TIME) },
      -> { bound2.observed_utc_offset(TIME) },
      -> { pinned1.observed_utc_offset(TIME) }
    ].each_with_index.collect do |worker, index|
      Thread.new do
        ready << true
        start.pop
        200.times { results[index] << worker.call }
      end
    end

    # A separate thread interleaves reads against DataSource.set. Each read
    # resolves immediately against whichever default is current and must
    # always observe one of the two known offsets.
    global_reader = Thread.new do
      ready << true
      start.pop
      200.times do
        results[3] << Timezone.get('Test/Zone').observed_utc_offset(TIME)
        Thread.pass
      end
    end

    4.times { ready.pop }

    switcher = Thread.new do
      100.times do
        DataSource.set(@source1)
        Thread.pass
        DataSource.set(@source2)
        Thread.pass
      end
    end

    5.times { start << true }
    workers.each(&:join)
    global_reader.join
    switcher.join
    DataSource.set(@source2)

    assert_equal([3600], results[0].uniq)
    assert_equal([7200], results[1].uniq)
    assert_equal([3600], results[2].uniq)
    assert(results[0..2].all? {|r| r.length == 200 })
    assert_equal(200, results[3].length)
    assert(results[3].all? {|offset| offset == 3600 || offset == 7200 })
  end

  def test_marshal_bound_timezone_preserves_data_source_identity
    tz = @source1.get_timezone('Test/Zone')
    DataSource.set(@source2)

    restored = Marshal.load(Marshal.dump(tz))
    assert_equal(3600, restored.observed_utc_offset(TIME))
  end

  def test_marshal_bound_proxy_preserves_data_source_identity
    proxy = @source1.get_timezone_proxy('Test/Zone')
    DataSource.set(@source2)

    restored = Marshal.load(Marshal.dump(proxy))
    assert_kind_of(TimezoneProxy, restored)
    assert_equal(3600, restored.observed_utc_offset(TIME))
  end

  def test_marshal_bound_linked_timezone_preserves_data_source_identity
    link = @source1.get_timezone('Test/Link')
    DataSource.set(@source2)

    restored = Marshal.load(Marshal.dump(link))
    assert_equal(3600, restored.observed_utc_offset(TIME))
    assert_equal(3600, restored.canonical_zone.observed_utc_offset(TIME))
  end

  def test_marshal_bound_country_preserves_data_source_identity
    country = @source1.get_country('TT')
    DataSource.set(@source2)

    restored = Marshal.load(Marshal.dump(country))
    assert_equal('TT', restored.code)
    assert_equal(3600, restored.zones.first.observed_utc_offset(TIME))
  end

  def test_marshal_global_objects_use_default_on_load
    DataSource.set(@source1)
    tz = Timezone.get('Test/Zone')
    country = Country.get('TT')

    tz_dump = Marshal.dump(tz)
    country_dump = Marshal.dump(country)

    DataSource.set(@source2)
    assert_equal(7200, Marshal.load(tz_dump).observed_utc_offset(TIME))
    assert_equal(7200, Marshal.load(country_dump).zones.first.observed_utc_offset(TIME))
  end

  def test_marshal_pinned_proxy_remains_pinned_but_legacy_proxy_uses_default
    DataSource.set(@source1)
    pinned_dump = Marshal.dump(Timezone.get_proxy('Test/Zone'))
    legacy_dump = Marshal.dump(TimezoneProxy.new('Test/Zone'))

    DataSource.set(@source2)
    assert_equal(3600, Marshal.load(pinned_dump).observed_utc_offset(TIME))
    assert_equal(7200, Marshal.load(legacy_dump).observed_utc_offset(TIME))
  end

  def test_marshal_unknown_data_source_identity_raises
    tz = @source1.get_timezone('Test/Zone')
    dump = Marshal.dump(tz)
    DataSource.instances.delete(@source1.object_id)

    begin
      error = assert_raises(InvalidDataSource) { Marshal.load(dump) }
      assert_match(/\b#{@source1.object_id}\b/, error.message)
    ensure
      DataSource.register(@source1)
    end
  end
end
