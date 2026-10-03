# encoding: UTF-8
# frozen_string_literal: true

require_relative '../test_utils'
require 'json'

module DataSources
  class TCTimezonePackageDataSource < Minitest::Test
    include TZInfo
    include TZInfo::DataSources

    FROM = Time.utc(2021, 1, 1)
    TO = Time.utc(2021, 12, 31, 23, 59, 59)
    FROM_VALUE = 1609459200
    TO_VALUE = 1640995199

    def setup
      @source = RubyDataSource.new
      @exporter = TimezonePackageExporter.new(@source)
      DataSource.set(@source)
    end

    def teardown
      DataSource.set(RubyDataSource.new)
    end

    def test_import_from_json
      json = @exporter.export_to_json(['Europe/London', 'UTC', 'Etc/GMT+1'], FROM, TO)
      data_source = TimezonePackageDataSource.from_json(json)

      assert_includes(data_source.timezone_identifiers, 'Europe/London')
      assert_includes(data_source.timezone_identifiers, 'UTC')
      assert_includes(data_source.data_timezone_identifiers, 'Etc/UTC')
      assert_includes(data_source.linked_timezone_identifiers, 'UTC')
    end

    def test_round_trip_periods_match_source
      package = @exporter.export(['Europe/London', 'America/New_York'], FROM, TO)
      data_source = TimezonePackageDataSource.new(package)

      ['Europe/London', 'America/New_York'].each do |identifier|
        packaged = data_source.get_timezone_info(identifier).create_timezone
        original = @source.get_timezone_info(identifier).create_timezone

        time = FROM
        while time <= TO
          expected = original.period_for(time)
          actual = packaged.period_for(time)

          assert_equal(expected.base_utc_offset, actual.base_utc_offset, identifier)
          assert_equal(expected.std_offset, actual.std_offset, identifier)
          assert_equal(expected.abbreviation, actual.abbreviation, identifier)

          time += 137 * 60
        end

        expected_transitions = original.transitions_up_to(Time.utc(2022, 1, 1), FROM)
        actual_transitions = packaged.transitions_up_to(Time.utc(2022, 1, 1), FROM)
        assert_equal(expected_transitions, actual_transitions, identifier)
      end
    end

    def test_period_for_window_endpoints
      packaged = imported_zone('Europe/London')

      assert_equal('GMT', packaged.period_for(FROM).abbreviation)
      assert_equal('GMT', packaged.period_for(TO).abbreviation)
    end

    def test_period_for_fails_outside_window
      packaged = imported_zone('Europe/London')

      [Time.utc(2020, 12, 31, 23, 59, 59), Time.utc(2022, 1, 1), Time.utc(2030, 1, 1)].each do |time|
        assert_raises(TimezonePackageTimeOutOfRange) { packaged.period_for(time) }
      end
    end

    def test_period_for_fails_on_subsecond_outside_window
      packaged = imported_zone('Europe/London')

      assert_raises(TimezonePackageTimeOutOfRange) { packaged.period_for(FROM - 1 + 0.5) }
      assert_raises(TimezonePackageTimeOutOfRange) { packaged.period_for(TO + 0.5) }
    end

    def test_constant_zone_fails_outside_window
      packaged = imported_zone('Etc/GMT+1')

      assert_equal(-3600, packaged.period_for(Time.utc(2021, 6, 1)).base_utc_offset)
      assert_raises(TimezonePackageTimeOutOfRange) { packaged.period_for(Time.utc(2022, 1, 1)) }
      assert_raises(TimezonePackageTimeOutOfRange) { packaged.period_for(Time.utc(2020, 1, 1)) }
    end

    def test_periods_for_local_resolves_ambiguity
      packaged = imported_zone('Europe/London')

      # 01:30 local on the October fall-back occurs twice.
      periods = packaged.periods_for_local(Time.utc(2021, 10, 31, 1, 30))
      assert_equal([3600, 0], periods.map(&:std_offset))
    end

    def test_periods_for_local_fails_far_outside_window
      packaged = imported_zone('Europe/London')

      assert_raises(TimezonePackageTimeOutOfRange) do
        packaged.periods_for_local(Time.utc(2020, 12, 30))
      end
      assert_raises(TimezonePackageTimeOutOfRange) do
        packaged.periods_for_local(Time.utc(2022, 1, 3))
      end
    end

    def test_linked_zone_round_trip
      data_source = import_package(['UTC'])
      TZInfo::DataSource.set(data_source)
      linked = TZInfo::Timezone.get('UTC')

      assert_kind_of(LinkedTimezone, linked)
      assert_equal('Etc/UTC', linked.canonical_zone.identifier)
      assert_equal(0, linked.period_for(Time.utc(2021, 6, 1)).observed_utc_offset)
      assert_raises(TimezonePackageTimeOutOfRange) { linked.period_for(Time.utc(2030, 1, 1)) }
    end

    def test_multi_level_link_round_trip
      source = MultiLevelLinkDataSource.new
      package = TimezonePackageExporter.new(source).export(['Test/Alias2'], FROM, TO)
      data_source = TimezonePackageDataSource.new(package)
      TZInfo::DataSource.set(data_source)
      linked = TZInfo::Timezone.get('Test/Alias2')

      assert_equal('Europe/London', linked.canonical_zone.identifier)
      assert_equal('BST', linked.period_for(Time.utc(2021, 7, 1)).abbreviation)
    end

    def test_get_unincluded_identifier_fails
      data_source = import_package(['Europe/London'])
      assert_raises(InvalidTimezoneIdentifier) do
        data_source.get_timezone_info('Europe/Paris')
      end
    end

    def test_country_data_not_available
      data_source = import_package(['Europe/London'])
      assert_equal([], data_source.country_codes)
      assert_raises(InvalidCountryCode) { data_source.get_country_info('GB') }
    end

    def test_rejects_invalid_json
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.from_json('{') }
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.from_json('[]') }
    end

    def test_rejects_bad_format_or_version
      package = valid_package_hash
      package['format'] = 'ruby'
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }

      package = valid_package_hash
      package['version'] = 2
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_invalid_window
      package = valid_package_hash
      package['window'] = { 'from' => TO_VALUE, 'to' => FROM_VALUE }
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_non_integer_offset
      package = valid_package_hash
      zone = package['data_timezones'].find {|z| z['identifier'] == 'Europe/London' }
      zone['offsets'].first['base_utc_offset'] = '0'
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_out_of_range_offset
      package = valid_package_hash
      zone = package['data_timezones'].find {|z| z['identifier'] == 'Europe/London' }
      zone['offsets'].first['std_offset'] = 100_000
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_dangling_offset_reference
      package = valid_package_hash
      zone = package['data_timezones'].find {|z| z['identifier'] == 'Europe/London' }
      zone['transitions'].first['offset'] = zone['offsets'].length
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_non_increasing_transitions
      package = valid_package_hash
      zone = package['data_timezones'].find {|z| z['identifier'] == 'Europe/London' }
      times = zone['transitions'].map {|t| t['at'] }
      zone['transitions'][1]['at'] = times.first
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_inconsistent_previous_offset
      package = valid_package_hash
      zone = package['data_timezones'].find {|z| z['identifier'] == 'Europe/London' }
      second = zone['transitions'][1]
      second['previous_offset'] = second['offset']
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_missing_bounding_transition
      package = valid_package_hash
      zone = package['data_timezones'].find {|z| z['identifier'] == 'Europe/London' }
      zone['transitions'].pop
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_dangling_link
      package = valid_package_hash
      package['linked_timezones'] << { 'identifier' => 'Test/Dangling', 'link_to' => 'Europe/Paris' }
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_cyclic_link
      package = valid_package_hash
      package['linked_timezones'] = [
        { 'identifier' => 'Test/A', 'link_to' => 'Test/B' },
        { 'identifier' => 'Test/B', 'link_to' => 'Test/A' }
      ]
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_self_link
      package = valid_package_hash
      package['linked_timezones'] = [{ 'identifier' => 'Test/A', 'link_to' => 'Test/A' }]
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_rejects_duplicate_identifier
      package = valid_package_hash
      package['data_timezones'] << Marshal.load(Marshal.dump(package['data_timezones'].first))
      assert_raises(InvalidTimezonePackage) { TimezonePackageDataSource.new(package) }
    end

    def test_transitions_up_to_exclusive_end_boundary_allowed
      packaged = imported_zone('Europe/London')
      transitions = packaged.transitions_up_to(Time.utc(2022, 1, 1))
      assert_equal([1603587600, 1616893200, 1635642000], transitions.map(&:timestamp_value))
    end

    private

    def import_package(identifiers)
      TimezonePackageDataSource.new(@exporter.export(identifiers, FROM, TO))
    end

    def imported_zone(identifier)
      import_package([identifier]).get_timezone_info(identifier).create_timezone
    end

    def valid_package_hash
      @exporter.export(['Europe/London'], FROM, TO)
    end

    class MultiLevelLinkDataSource < RubyDataSource
      def linked_timezone_identifiers
        (super + ['Test/Alias1', 'Test/Alias2']).sort.freeze
      end

      protected

      def load_timezone_info(identifier)
        case identifier
        when 'Test/Alias1'
          ::TZInfo::DataSources::LinkedTimezoneInfo.new('Test/Alias1', 'Europe/London')
        when 'Test/Alias2'
          ::TZInfo::DataSources::LinkedTimezoneInfo.new('Test/Alias2', 'Test/Alias1')
        else
          super(identifier)
        end
      end
    end
  end
end
