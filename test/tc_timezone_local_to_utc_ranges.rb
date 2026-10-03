# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCTimezoneLocalToUtcRanges < Minitest::Test
  include TZInfo

  def timezone(transitions)
    DataTimezone.new(DataSources::TransitionsDataTimezoneInfo.new('Test/Zone', transitions))
  end

  def transition(new_offset, previous_offset, year, month, day, hour, minute = 0)
    TimezoneTransition.new(new_offset, previous_offset, Time.utc(year, month, day, hour, minute).to_i)
  end

  def range(start_year, start_month, start_day, start_hour, start_minute, start_second = 0, start_sub_second = 0,
    end_year = start_year, end_month = start_month, end_day = start_day, end_hour = start_hour, end_minute = start_minute, end_second = 0, end_sub_second = 0)

    start_time = Time.utc(start_year, start_month, start_day, start_hour, start_minute, start_second + start_sub_second)
    end_time = Time.utc(end_year, end_month, end_day, end_hour, end_minute, end_second + end_sub_second)
    start_time...end_time
  end

  def assert_utc_ranges(expected, actual)
    assert_equal(expected, actual)
    assert(actual.all?(&:exclude_end?))
    assert(actual.each_cons(2).all? {|first, second| first.end <= second.begin})
  end

  def test_constant_offset
    tz = Timezone.get('UTC')

    expected = [range(2004, 3, 28, 1, 15, 0, 0, 2004, 3, 28, 3, 30)]
    assert_utc_ranges(expected, tz.local_to_utc_ranges(expected.first))
  end

  def test_precision_and_result_type
    tz = Timezone.get('UTC')

    [
      TestUtils::TimeTypesTimeHelper,
      TestUtils::TimeTypesDateTimeHelper,
      TestUtils::TimeTypesTimestampHelper
    ].each do |helper_class|
      h = helper_class.new
      start_time = h.time(2004, 3, 28, 1, 15, 15, Rational(1, 8), :utc)
      end_time = h.time(2004, 3, 28, 3, 30, 30, Rational(1, 4), :utc)

      actual = tz.local_to_utc_ranges(start_time...end_time)

      assert_equal(1, actual.length)
      assert_equal_with_offset_and_class(start_time, actual.first.begin)
      assert_equal_with_offset_and_class(end_time, actual.first.end)
      assert_equal(Rational(1, 8), actual.first.begin.subsec) if actual.first.begin.respond_to?(:subsec)
      assert_equal(Rational(1, 8), actual.first.begin.sec_fraction) if actual.first.begin.respond_to?(:sec_fraction)
      assert_equal(Rational(1, 4), actual.first.end.subsec) if actual.first.end.respond_to?(:subsec)
      assert_equal(Rational(1, 4), actual.first.end.sec_fraction) if actual.first.end.respond_to?(:sec_fraction)
    end
  end

  def test_skipped_half_hour
    standard = TimezoneOffset.new(0, 0, 'STD')
    advanced = TimezoneOffset.new(0, 1800, 'ADV')
    tz = timezone([transition(advanced, standard, 2020, 3, 29, 1, 30)])

    expected = [
      range(2020, 3, 29, 1, 15, 15, Rational(1, 8), 2020, 3, 29, 1, 30),
      range(2020, 3, 29, 1, 30, 0, 0, 2020, 3, 29, 3, 0, 0, Rational(1, 8))
    ]

    actual = tz.local_to_utc_ranges(range(2020, 3, 29, 1, 15, 15, Rational(1, 8), 2020, 3, 29, 3, 30, 0, Rational(1, 8)))
    assert_utc_ranges(expected, actual)
    assert_equal(Rational(1, 8), actual.first.begin.subsec)
    assert_equal(Rational(1, 8), actual.last.end.subsec)
  end

  def test_repeated_half_hour
    standard = TimezoneOffset.new(0, 0, 'STD')
    advanced = TimezoneOffset.new(0, 1800, 'ADV')
    tz = timezone([transition(standard, advanced, 2020, 10, 25, 1, 30)])

    expected = [
      range(2020, 10, 25, 0, 15, 0, 0, 2020, 10, 25, 1, 30),
      range(2020, 10, 25, 1, 30, 0, 0, 2020, 10, 25, 2, 15)
    ]

    actual = tz.local_to_utc_ranges(range(2020, 10, 25, 0, 45, 0, 0, 2020, 10, 25, 2, 15))
    assert_utc_ranges(expected, actual)
  end

  def test_skipped_day
    old_offset = TimezoneOffset.new(0, 0, 'OLD')
    new_offset = TimezoneOffset.new(0, 86400, 'NEW')
    tz = timezone([transition(new_offset, old_offset, 2020, 1, 1, 0)])

    assert_empty(tz.local_to_utc_ranges(range(2020, 1, 1, 0, 0, 0, 0, 2020, 1, 2, 0, 0)))

    expected = [
      range(2019, 12, 31, 0, 0, 0, 0, 2020, 1, 1, 0, 0),
      range(2020, 1, 1, 0, 0, 0, 0, 2020, 1, 2, 0, 0)
    ]

    actual = tz.local_to_utc_ranges(range(2019, 12, 31, 0, 0, 0, 0, 2020, 1, 3, 0, 0))
    assert_utc_ranges(expected, actual)
  end

  def test_repeated_hour_with_real_timezone
    tz = Timezone.get('Europe/London')

    expected = [
      range(2004, 10, 31, 0, 15, 0, 0, 2004, 10, 31, 1, 0),
      range(2004, 10, 31, 1, 15, 0, 0, 2004, 10, 31, 3, 30)
    ]

    actual = tz.local_to_utc_ranges(range(2004, 10, 31, 1, 15, 0, 0, 2004, 10, 31, 3, 30))
    assert_utc_ranges(expected, actual)
  end

  def test_separate_start_and_end_times
    tz = Timezone.get('UTC')
    start_time = Time.utc(2004, 3, 28, 1, 15)
    end_time = Time.utc(2004, 3, 28, 3, 30)

    assert_utc_ranges([start_time...end_time], tz.local_to_utc_ranges(start_time, end_time))
  end

  def test_empty_range
    tz = Timezone.get('UTC')
    time = Time.utc(2004, 3, 28, 1, 15)

    assert_empty(tz.local_to_utc_ranges(time...time))
  end

  def test_inclusive_range
    tz = Timezone.get('UTC')
    time = Time.utc(2004, 3, 28, 1, 15)

    error = assert_raises(ArgumentError) { tz.local_to_utc_ranges(time..time) }
    assert_equal('local range must be half-open (use ... rather than ..)', error.message)
  end

  def test_end_before_start
    tz = Timezone.get('UTC')
    start_time = Time.utc(2004, 3, 28, 3, 30)
    end_time = Time.utc(2004, 3, 28, 1, 15)

    error = assert_raises(ArgumentError) { tz.local_to_utc_ranges(start_time...end_time) }
    assert_equal('local_end must be greater than local_start', error.message)
  end

  def test_missing_range_end
    tz = Timezone.get('UTC')

    error = assert_raises(ArgumentError) { tz.local_to_utc_ranges(Time.utc(2004, 3, 28, 1, 15), nil) }
    assert_equal('local_end must be specified', error.message)
  end
end
