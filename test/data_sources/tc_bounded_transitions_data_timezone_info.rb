# encoding: UTF-8
# frozen_string_literal: true

require_relative '../test_utils'

module DataSources
  class TCBoundedTransitionsDataTimezoneInfo < Minitest::Test
    include TZInfo
    include TZInfo::DataSources

    def test_initialize_validates_coverage_order
      offset = TimezoneOffset.new(0, 0, 'UTC')
      transition = TimezoneTransition.new(offset, offset, 100)

      error = assert_raises(ArgumentError) do
        BoundedTransitionsDataTimezoneInfo.new('Test/Zone', [transition], 200, 100)
      end
      assert_match(/coverage_start_value/, error.message)
    end

    def test_period_for_requires_specified_offset
      info = build_info

      error = assert_raises(ArgumentError) { info.period_for(Timestamp.new(150)) }
      assert_match(/utc_offset/, error.message)
    end

    def test_periods_for_local_rejects_specified_offset
      info = build_info

      error = assert_raises(ArgumentError) { info.periods_for_local(Timestamp.utc(150)) }
      assert_match(/unspecified utc_offset/, error.message)
    end

    private

    def build_info
      standard = TimezoneOffset.new(0, 0, 'STD')
      daylight = TimezoneOffset.new(0, 3600, 'DST')
      transitions = [
        TimezoneTransition.new(daylight, standard, 100),
        TimezoneTransition.new(standard, daylight, 200)
      ]
      BoundedTransitionsDataTimezoneInfo.new('Test/Zone', transitions, 50, 250)
    end
  end
end
