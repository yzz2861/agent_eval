# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCTimezoneLocalRangeToUtc < Minitest::Test
  include TZInfo

  # A Timezone subclass with a fixed set of transitions. Used to test
  # local_range_to_utc with rules that are not found in the bundled test time
  # zone data (half-hour offset changes and a whole day being skipped).
  class RuleTestTimezone < Timezone
    # @param initial_offset [Integer] the offset from UTC in seconds observed
    #   before the first transition.
    # @param transitions [Array<Array(Integer, Integer)>] the transitions as
    #   [UTC timestamp value, new offset from UTC in seconds] pairs, in
    #   ascending order.
    def initialize(initial_offset, transitions)
      super()
      @initial_offset = initial_offset
      @transitions = transitions
    end

    def identifier
      'Test/Rule'
    end

    def period_for(time)
      timestamp = TZInfo::Timestamp.for(time)
      value = timestamp.value
      offset = @initial_offset

      @transitions.each do |transition_value, transition_offset|
        break if transition_value > value
        offset = transition_offset
      end

      TZInfo::OffsetTimezonePeriod.new(TZInfo::TimezoneOffset.new(offset, 0, 'TEST'))
    end

    def periods_for_local(local_time)
      raise NotImplementedError, 'periods_for_local is not implemented'
    end

    def transitions_up_to(to, from = nil)
      to = TZInfo::Timestamp.for(to)
      from = from && TZInfo::Timestamp.for(from)
      result = []
      previous_offset = @initial_offset

      @transitions.each do |value, offset|
        if (!from || value >= from.value) && value < to.value
          result << TZInfo::TimezoneTransition.new(
            TZInfo::TimezoneOffset.new(offset, 0, 'TEST'),
            TZInfo::TimezoneOffset.new(previous_offset, 0, 'TEST'),
            value)
        end

        previous_offset = offset
      end

      result
    end
  end

  # A zone with half-hour offset changes (like Australia/Lord_Howe).
  #
  # At UTC 1000000 the offset changes from +10:30 to +11:00, skipping local
  # times [1037800, 1039600). At UTC 2000000 the offset changes back from
  # +11:00 to +10:30, repeating local times [2037800, 2039600).
  def half_hour_zone
    RuleTestTimezone.new(37800, [[1000000, 39600], [2000000, 37800]])
  end

  # A zone that skips a whole day (like Pacific/Apia on 2011-12-30).
  #
  # At UTC 5000000 the offset changes from -10:00 to +14:00, skipping local
  # times [4964000, 5050400).
  def day_skip_zone
    RuleTestTimezone.new(-36000, [[5000000, 50400]])
  end

  # A zone with a constant +01:00 offset.
  def constant_zone
    RuleTestTimezone.new(3600, [])
  end

  def test_no_transitions
    result = constant_zone.local_range_to_utc(
      Timestamp.new(1000000), Timestamp.new(1008000))

    assert_equal([[Timestamp.utc(996400), Timestamp.utc(1004400)]], result)
  end

  def test_half_hour_gap_range_entirely_within_gap_returns_empty
    result = half_hour_zone.local_range_to_utc(
      Timestamp.new(1038000), Timestamp.new(1039000))

    assert_equal([], result)
  end

  def test_half_hour_gap_range_spanning_gap
    result = half_hour_zone.local_range_to_utc(
      Timestamp.new(1037000), Timestamp.new(1040000))

    assert_equal([[Timestamp.utc(999200), Timestamp.utc(1000400)]], result)
  end

  def test_half_hour_gap_range_ending_within_gap
    result = half_hour_zone.local_range_to_utc(
      Timestamp.new(1037000), Timestamp.new(1038500))

    assert_equal([[Timestamp.utc(999200), Timestamp.utc(1000000)]], result)
  end

  def test_half_hour_gap_range_starting_within_gap
    result = half_hour_zone.local_range_to_utc(
      Timestamp.new(1038500), Timestamp.new(1040000))

    assert_equal([[Timestamp.utc(1000000), Timestamp.utc(1000400)]], result)
  end

  def test_half_hour_fold_range_within_fold_returns_both_occurrences
    result = half_hour_zone.local_range_to_utc(
      Timestamp.new(2038000), Timestamp.new(2039000))

    assert_equal([
      [Timestamp.utc(1998400), Timestamp.utc(1999400)],
      [Timestamp.utc(2000200), Timestamp.utc(2001200)]
    ], result)
  end

  def test_half_hour_fold_range_covering_fold_merges_occurrences
    result = half_hour_zone.local_range_to_utc(
      Timestamp.new(2037800), Timestamp.new(2039600))

    assert_equal([[Timestamp.utc(1998200), Timestamp.utc(2001800)]], result)
  end

  def test_skipped_day_returns_empty
    result = day_skip_zone.local_range_to_utc(
      Timestamp.new(4964000), Timestamp.new(5050400))

    assert_equal([], result)
  end

  def test_range_spanning_skipped_day
    result = day_skip_zone.local_range_to_utc(
      Timestamp.new(4960400), Timestamp.new(5054000))

    assert_equal([[Timestamp.utc(4996400), Timestamp.utc(5003600)]], result)
  end

  def test_fractional_seconds_are_preserved
    result = constant_zone.local_range_to_utc(
      Timestamp.new(1000000, Rational(1,2)), Timestamp.new(1000100, Rational(1,4)))

    assert_equal(1, result.length)
    assert_equal(Timestamp.utc(996400, Rational(1,2)), result[0][0])
    assert_equal(Timestamp.utc(996500, Rational(1,4)), result[0][1])
    assert_equal(Rational(1,2), result[0][0].sub_second)
    assert_equal(Rational(1,4), result[0][1].sub_second)
  end

  def test_fractional_seconds_are_preserved_across_transition
    result = half_hour_zone.local_range_to_utc(
      Timestamp.new(1037000, Rational(1,2)), Timestamp.new(1040000, Rational(1,4)))

    assert_equal([[Timestamp.utc(999200, Rational(1,2)), Timestamp.utc(1000400, Rational(1,4))]], result)
  end

  def test_new_york_fold_returns_both_occurrences
    tz = Timezone.get('America/New_York')

    result = tz.local_range_to_utc(Time.utc(2015,11,1,1,15,0), Time.utc(2015,11,1,1,45,0))

    assert_equal([
      [Time.utc(2015,11,1,5,15,0), Time.utc(2015,11,1,5,45,0)],
      [Time.utc(2015,11,1,6,15,0), Time.utc(2015,11,1,6,45,0)]
    ], result)
  end

  def test_new_york_gap_returns_empty
    tz = Timezone.get('America/New_York')

    result = tz.local_range_to_utc(Time.utc(2016,3,13,2,15,0), Time.utc(2016,3,13,2,45,0))

    assert_equal([], result)
  end

  def test_new_york_range_without_transition
    tz = Timezone.get('America/New_York')

    result = tz.local_range_to_utc(Time.utc(2016,1,15,10,0,0), Time.utc(2016,1,15,12,0,0))

    assert_equal([[Time.utc(2016,1,15,15,0,0), Time.utc(2016,1,15,17,0,0)]], result)
  end

  def test_new_york_range_spanning_gap
    tz = Timezone.get('America/New_York')

    result = tz.local_range_to_utc(Time.utc(2016,3,13,1,30,0), Time.utc(2016,3,13,3,30,0))

    assert_equal([[Time.utc(2016,3,13,6,30,0), Time.utc(2016,3,13,7,30,0)]], result)
  end

  def test_time_results_are_times_in_utc
    tz = Timezone.get('America/New_York')

    result = tz.local_range_to_utc(Time.utc(2016,1,15,10,0,0), Time.utc(2016,1,15,12,0,0))

    assert_equal(1, result.length)
    assert_kind_of(Time, result[0][0])
    assert_kind_of(Time, result[0][1])
    assert(result[0][0].utc?)
    assert(result[0][1].utc?)
  end

  def test_datetime_results_are_datetimes_in_utc
    tz = Timezone.get('America/New_York')

    result = tz.local_range_to_utc(DateTime.new(2016,1,15,10,0,0), DateTime.new(2016,1,15,12,0,0))

    assert_equal([[DateTime.new(2016,1,15,15,0,0), DateTime.new(2016,1,15,17,0,0)]], result)
    assert_kind_of(DateTime, result[0][0])
    assert_equal(0, result[0][0].offset)
  end

  def test_timestamp_results_are_timestamps_with_zero_utc_offset
    tz = Timezone.get('America/New_York')

    result = tz.local_range_to_utc(Timestamp.new(1451779200), Timestamp.new(1451786400))

    assert_equal(1, result.length)
    assert_kind_of(Timestamp, result[0][0])
    assert_equal(0, result[0][0].utc_offset)
    assert_equal(Timestamp.utc(1451797200), result[0][0])
    assert_equal(Timestamp.utc(1451804400), result[0][1])
  end

  def test_nil_start_time
    error = assert_raises(ArgumentError) { constant_zone.local_range_to_utc(nil, Timestamp.new(1000000)) }
    assert_equal('start_time must be specified', error.message)
  end

  def test_nil_end_time
    error = assert_raises(ArgumentError) { constant_zone.local_range_to_utc(Timestamp.new(1000000), nil) }
    assert_equal('end_time must be specified', error.message)
  end

  def test_end_time_equal_to_start_time
    error = assert_raises(ArgumentError) do
      constant_zone.local_range_to_utc(Timestamp.new(1000000), Timestamp.new(1000000))
    end
    assert_equal('end_time must be greater than start_time', error.message)
  end

  def test_end_time_before_start_time
    error = assert_raises(ArgumentError) do
      constant_zone.local_range_to_utc(Timestamp.new(1000000), Timestamp.new(999999))
    end
    assert_equal('end_time must be greater than start_time', error.message)
  end
end
