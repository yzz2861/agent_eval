# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCTimezoneDifference < Minitest::Test
  include TZInfo

  def test_initialize
    starts_at = Timestamp.utc(1156939200)
    ends_at = Timestamp.utc(1162080000)
    first_period = OffsetTimezonePeriod.new(TimezoneOffset.new(0, 3600, 'BST'))
    second_period = OffsetTimezonePeriod.new(TimezoneOffset.new(-18000, 3600, 'EDT'))

    difference = TimezoneDifference.new(starts_at, ends_at, first_period, second_period)

    assert_same(starts_at, difference.starts_at)
    assert_same(ends_at, difference.ends_at)
    assert_same(first_period, difference.first_period)
    assert_same(second_period, difference.second_period)
  end

  def test_initialize_nil_starts_at
    error = assert_raises(ArgumentError) do
      TimezoneDifference.new(nil, Timestamp.utc(1162080000), period, period)
    end
    assert_equal('starts_at must be specified', error.message)
  end

  def test_initialize_nil_ends_at
    error = assert_raises(ArgumentError) do
      TimezoneDifference.new(Timestamp.utc(1156939200), nil, period, period)
    end
    assert_equal('ends_at must be specified', error.message)
  end

  def test_initialize_nil_first_period
    error = assert_raises(ArgumentError) do
      TimezoneDifference.new(Timestamp.utc(1156939200), Timestamp.utc(1162080000), nil, period)
    end
    assert_equal('first_period must be specified', error.message)
  end

  def test_initialize_nil_second_period
    error = assert_raises(ArgumentError) do
      TimezoneDifference.new(Timestamp.utc(1156939200), Timestamp.utc(1162080000), period, nil)
    end
    assert_equal('second_period must be specified', error.message)
  end

  def test_equality
    starts_at = Timestamp.utc(1156939200)
    ends_at = Timestamp.utc(1162080000)
    first_period = OffsetTimezonePeriod.new(TimezoneOffset.new(0, 3600, 'BST'))
    second_period = OffsetTimezonePeriod.new(TimezoneOffset.new(-18000, 3600, 'EDT'))

    d1 = TimezoneDifference.new(starts_at, ends_at, first_period, second_period)
    d2 = TimezoneDifference.new(starts_at, ends_at, first_period, second_period)

    assert_equal(d1, d2)
    assert(d1.eql?(d2))
    assert_equal(d1.hash, d2.hash)
  end

  def test_equality_with_different_values
    starts_at = Timestamp.utc(1156939200)
    ends_at = Timestamp.utc(1162080000)
    period = OffsetTimezonePeriod.new(TimezoneOffset.new(0, 3600, 'BST'))
    other_period = OffsetTimezonePeriod.new(TimezoneOffset.new(0, 0, 'GMT'))

    d = TimezoneDifference.new(starts_at, ends_at, period, period)

    refute_equal(d, TimezoneDifference.new(Timestamp.utc(1156939201), ends_at, period, period))
    refute_equal(d, TimezoneDifference.new(starts_at, Timestamp.utc(1162080001), period, period))
    refute_equal(d, TimezoneDifference.new(starts_at, ends_at, other_period, period))
    refute_equal(d, TimezoneDifference.new(starts_at, ends_at, period, other_period))
    refute_equal(d, Object.new)
  end

  def test_inspect
    starts_at = Timestamp.utc(1156939200)
    ends_at = Timestamp.utc(1162080000)
    first_period = OffsetTimezonePeriod.new(TimezoneOffset.new(0, 3600, 'BST'))
    second_period = OffsetTimezonePeriod.new(TimezoneOffset.new(-18000, 3600, 'EDT'))

    difference = TimezoneDifference.new(starts_at, ends_at, first_period, second_period)

    expected = "#<TZInfo::TimezoneDifference: @starts_at=#{starts_at.inspect}, " +      "@ends_at=#{ends_at.inspect}, @first_period=#{first_period.inspect}, " +      "@second_period=#{second_period.inspect}>"

    assert_equal(expected, difference.inspect)
  end

  private

  def period
    OffsetTimezonePeriod.new(TimezoneOffset.new(0, 0, 'GMT'))
  end
end
