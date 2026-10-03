# encoding: UTF-8
# frozen_string_literal: true

require_relative '../test_utils'
require 'json'

module DataSources
  class TCTimezonePackageExporter < Minitest::Test
    include TZInfo
    include TZInfo::DataSources

    def setup
      @data_source = RubyDataSource.new
      @exporter = TimezonePackageExporter.new(@data_source)
      @from = Time.utc(2021, 1, 1)
      @to = Time.utc(2021, 12, 31, 23, 59, 59)
    end

    def test_export_envelope
      package = export_package(['Europe/London'])

      assert_equal('tzinfo-limited-timezone-package', package['format'])
      assert_equal(1, package['version'])
      assert_equal({ 'from' => 1609459200, 'to' => 1640995199 }, package['window'])
    end

    def test_export_is_plain_json_data
      package = export_package(['Europe/London', 'Etc/UTC', 'UTC', 'Etc/GMT+1'])
      json = TimezonePackageFormat.dump(package)
      reparsed = ::JSON.parse(json)

      assert_equal(package, reparsed)
      assert_kind_of(String, json)
    end

    def test_export_transitions_zone_includes_bounding_transitions
      package = export_package(['Europe/London'])
      zone = find_data_zone(package, 'Europe/London')
      times = zone['transitions'].map {|t| t['at'] }

      # First transition is at or before window start; last is strictly after
      # window end so the final period cannot be extrapolated.
      assert(times.first <= 1609459200)
      assert(times.last > 1640995199)
      assert_equal([1603587600, 1616893200, 1635642000, 1648342800], times)
    end

    def test_export_transitions_reference_offsets
      package = export_package(['Europe/London'])
      zone = find_data_zone(package, 'Europe/London')
      offsets = zone['offsets']

      assert_equal([
        { 'base_utc_offset' => 0, 'std_offset' => 0, 'abbreviation' => 'GMT' },
        { 'base_utc_offset' => 0, 'std_offset' => 3600, 'abbreviation' => 'BST' }
      ], offsets)

      zone['transitions'].each do |transition|
        [transition['offset'], transition['previous_offset']].each do |index|
          assert(index >= 0 && index < offsets.length)
        end
      end
    end

    def test_export_constant_offset_zone
      package = export_package(['Etc/GMT+1'])
      zone = find_data_zone(package, 'Etc/GMT+1')

      assert_equal('constant', zone['type'])
      assert_equal({
        'base_utc_offset' => -3600,
        'std_offset' => 0,
        'abbreviation' => '-01'
      }, zone['offset'])
    end

    def test_export_alias_follows_link
      package = export_package(['UTC'])

      linked = package['linked_timezones']
      assert_equal([{ 'identifier' => 'UTC', 'link_to' => 'Etc/UTC' }], linked)
      assert_equal(['Etc/UTC'], package['data_timezones'].map {|z| z['identifier'] })
    end

    def test_export_multi_level_link
      source = MultiLevelLinkDataSource.new
      exporter = TimezonePackageExporter.new(source)
      package = exporter.export(['Test/Alias2'], @from, @to)

      links = package['linked_timezones'].map {|z| [z['identifier'], z['link_to']] }
      assert_includes(links, ['Test/Alias1', 'Europe/London'])
      assert_includes(links, ['Test/Alias2', 'Test/Alias1'])
      assert_equal(['Europe/London'], package['data_timezones'].map {|z| z['identifier'] })
    end

    def test_export_deduplicates_zones
      package = export_package(['UTC', 'Etc/UTC', 'UTC'])

      assert_equal(['Etc/UTC'], package['data_timezones'].map {|z| z['identifier'] })
      assert_equal(['UTC'], package['linked_timezones'].map {|z| z['identifier'] })
    end

    def test_export_rejects_unknown_zone
      error = assert_raises(InvalidTimezonePackageExport) do
        export_package(['Not/A_Zone'])
      end
      assert_match(/unknown time zone/, error.message)
    end

    def test_export_rejects_empty_identifiers
      assert_raises(InvalidTimezonePackageExport) { @exporter.export([], @from, @to) }
      assert_raises(InvalidTimezonePackageExport) { @exporter.export([nil], @from, @to) }
      assert_raises(InvalidTimezonePackageExport) { @exporter.export([''], @from, @to) }
    end

    def test_export_rejects_invalid_window
      assert_raises(InvalidTimezonePackageExport) do
        @exporter.export(['Etc/UTC'], @to, @from)
      end
    end

    def test_export_rejects_window_without_bounding_transition
      # The truncated Buenos_Aires test fixture stops at its final transition in
      # 2009. A window after that cannot be bounded, so export must fail.
      error = assert_raises(InvalidTimezonePackageExport) do
        @exporter.export(['America/Argentina/Buenos_Aires'], Time.utc(2020, 1, 1), Time.utc(2021, 1, 1))
      end
      assert_match(/no transition after the window end/, error.message)
    end

    def test_export_to_json
      json = @exporter.export_to_json(['Europe/London'], @from, @to)
      assert_kind_of(String, json)
      assert_kind_of(Hash, ::JSON.parse(json))
    end

    private

    def export_package(identifiers)
      @exporter.export(identifiers, @from, @to)
    end

    def find_data_zone(package, identifier)
      package['data_timezones'].find {|z| z['identifier'] == identifier }
    end

    # Adds a second level of alias on top of the Europe/London data.
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
