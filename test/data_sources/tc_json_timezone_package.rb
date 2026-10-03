# encoding: UTF-8
# frozen_string_literal: true

require_relative '../test_utils'
require 'json'

module DataSources
  class TCJsonTimezonePackage < Minitest::Test
    include TZInfo
    include TZInfo::DataSources

    def setup
      TZInfo::DataSource.set(:ruby)
      @start = Time.utc(2020, 1, 1)
      @end = Time.utc(2020, 12, 31, 23, 59, 59)
      @package = JsonTimezonePackage.export(
        ['Europe/London', 'UTC', 'EST'],
        @start,
        @end,
        false
      )
    end

    def teardown
      TZInfo::DataSource.set(:ruby)
    end

    def test_export_is_plain_json_data
      json = JsonTimezonePackage.dump(['Europe/London'], @start, @end, false)
      parsed = JSON.parse(json)

      assert_equal('tzinfo-limited-timezone-package', parsed['format'])
      assert_equal(1, parsed['version'])
      assert_equal(1577836800, parsed['window']['start_at'])
      assert_equal(1609459199, parsed['window']['end_at'])
      assert_kind_of(Array, parsed['timezones'])
    end

    def test_roundtrip_transitions_and_alias
      zone = @package['timezones'].find {|z| z['identifier'] == 'Europe/London'}
      linked = @package['timezones'].find {|z| z['identifier'] == 'UTC'}
      assert_equal('transitions', zone['type'])
      assert_equal('linked', linked['type'])
      assert_equal('Etc/UTC', linked['link_to'])

      source = JsonTimezonePackage.import(@package)
      TZInfo::DataSource.set(source)

      london = Timezone.get('Europe/London')
      utc = Timezone.get('UTC')

      assert_equal(0, london.period_for(@start).observed_utc_offset)
      assert_equal(3600, london.period_for(Time.utc(2020, 7, 1)).observed_utc_offset)
      assert_equal(1577836800, london.period_for(@start).starts_at.value)
      assert_equal(1609459199, london.period_for(@end).ends_at.value)
      assert_equal('Etc/UTC', utc.canonical_identifier)
    end

    def test_roundtrip_fixed_offset_time_zones
      source = JsonTimezonePackage.import(@package)
      TZInfo::DataSource.set(source)

      assert_equal(0, Timezone.get('Etc/UTC').period_for(Time.utc(2030, 1, 1)).observed_utc_offset)
      assert_equal(-18000, Timezone.get('EST').period_for(Time.utc(1900, 1, 1)).observed_utc_offset)
    end

    def test_export_from_limited_package_requires_subwindow
      source = JsonTimezonePackage.import(@package)
      TZInfo::DataSource.set(source)

      narrower = JsonTimezonePackage.export(
        ['Europe/London'],
        Time.utc(2020, 2, 1),
        Time.utc(2020, 11, 30),
        false
      )
      narrower_source = JsonTimezonePackage.import(narrower)
      assert_equal('Limited JSON DataSource', source.to_s.split(' (').first)

      TZInfo::DataSource.set(narrower_source)
      assert_equal(3600, Timezone.get('Europe/London').period_for(Time.utc(2020, 7, 1)).observed_utc_offset)

      error = assert_raises(ArgumentError) do
        JsonTimezonePackage.export(
          ['Europe/London'],
          Time.utc(2019, 12, 31),
          @end,
          false
        )
      end
      assert_match(/does not cover/, error.message)
    end

    def test_multi_level_aliases_roundtrip
      add_multi_level_alias(@package, 'Test/Level1', 'Etc/UTC')
      add_multi_level_alias(@package, 'Test/Level2', 'Test/Level1')

      TZInfo::DataSource.set(JsonTimezonePackage.import(@package))

      assert_equal('Etc/UTC', Timezone.get('Test/Level2').canonical_identifier)
      assert_equal(0, Timezone.get('Test/Level2').period_for(Time.utc(2020, 6, 1)).observed_utc_offset)
    end

    def test_query_outside_coverage_fails
      TZInfo::DataSource.set(JsonTimezonePackage.import(@package))
      london = Timezone.get('Europe/London')

      assert_raises(PeriodNotFound) { london.period_for(@start - 1) }
      assert_raises(PeriodNotFound) { london.period_for(@end + 1) }
      assert_raises(PeriodNotFound) { london.period_for(Timestamp.utc(@end.to_i, Rational(1, 2))) }
      assert_raises(PeriodNotFound) { london.period_for_local(Time.utc(2031, 1, 1, 0, 0, 0)) }
    end

    def test_local_periods_remain_within_coverage
      TZInfo::DataSource.set(JsonTimezonePackage.import(@package))
      london = Timezone.get('Europe/London')

      assert_equal([3600, 0], london.periods_for_local(Time.utc(2020, 10, 25, 1, 30, 0)).map(&:observed_utc_offset))
      assert_equal([], london.periods_for_local(Time.utc(2020, 3, 29, 1, 30, 0)))
    end

    def test_transitions_do_not_extend_last_offset
      TZInfo::DataSource.set(JsonTimezonePackage.import(@package))
      london = Timezone.get('Europe/London')

      transitions = london.transitions_up_to(Time.utc(2021, 2, 1), Time.utc(2020, 1, 1))
      assert_equal(1585443600, transitions.first.timestamp_value)
      assert_equal(1603587600, transitions.last.timestamp_value)
      assert(transitions.all? {|transition| transition.timestamp_value <= @end.to_i })
    end

    def test_import_rejects_non_increasing_transition
      london = transition_zone(@package)
      london['transitions'][1]['at'] = london['transitions'].first['at']

      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import(@package) }
      assert_match(/strictly increasing/, error.message)
    end

    def test_import_rejects_broken_transition_order
      london = transition_zone(@package)
      london['transitions'][1]['previous_offset'] = london['transitions'][1]['offset']

      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import(@package) }
      assert_match(/does not continue/, error.message)
    end

    def test_import_rejects_bad_observed_offset
      london = transition_zone(@package)
      london['offsets'].first['observed_utc_offset'] += 60

      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import(@package) }
      assert_match(/observed_utc_offset/, error.message)
    end

    def test_import_rejects_unknown_alias_target
      @package['timezones'] << {
        'identifier' => 'Test/BrokenAlias',
        'type' => 'linked',
        'link_to' => 'Missing/Zone'
      }

      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import(@package) }
      assert_match(/unknown time zone/, error.message)
    end

    def test_import_rejects_alias_cycle
      add_multi_level_alias(@package, 'Test/Cycle1', 'Test/Cycle2')
      add_multi_level_alias(@package, 'Test/Cycle2', 'Test/Cycle1')

      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import(@package) }
      assert_match(/alias cycle/, error.message)
    end

    def test_import_rejects_unexpected_field
      @package['unexpected'] = true

      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import(@package) }
      assert_match(/unexpected fields/, error.message)
    end

    def test_import_rejects_missing_type
      @package['timezones'].first.delete('type')

      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import(@package) }
      assert_match(/missing field: type/, error.message)
    end

    def test_import_rejects_malformed_json
      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import('{') }
      assert_match(/Invalid JSON/, error.message)
    end

    def test_import_rejects_unsupported_root_type
      error = assert_raises(InvalidTimezonePackage) { JsonTimezonePackage.import([]) }
      assert_match(/JSON object/, error.message)
    end

    def test_imported_package_is_frozen
      source = JsonTimezonePackage.import(@package)

      assert(source.package.frozen?)
      assert(source.package['window'].frozen?)
    end

    private

    def transition_zone(package)
      package['timezones'].find {|zone| zone['identifier'] == 'Europe/London'}
    end

    def add_multi_level_alias(package, identifier, target)
      package['timezones'] << {
        'identifier' => identifier,
        'type' => 'linked',
        'link_to' => target
      }
    end
  end
end
