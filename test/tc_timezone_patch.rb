# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCTimezonePatch < Minitest::Test
  include TZInfo

  OFFSET_STD = TimezoneOffset.new(0, 0, 'STD')
  OFFSET_DST = TimezoneOffset.new(0, 3600, 'DST')

  def test_accessors
    transition = TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 1500)
    patch = TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_DST, [transition])

    assert_equal(Timestamp.utc(1000), patch.starts_at)
    assert_equal(Timestamp.utc(2000), patch.ends_at)
    assert_equal(OFFSET_DST, patch.offset)
    assert_equal([transition], patch.transitions)
  end

  def test_time_and_datetime_bounds
    patch = TimezonePatch.new(Time.utc(2020, 1, 1), DateTime.new(2020, 2, 1), OFFSET_STD)

    assert_equal(Time.utc(2020, 1, 1).to_i, patch.starts_at.value)
    assert_equal(DateTime.new(2020, 2, 1).to_time.utc.to_i, patch.ends_at.value)
  end

  def test_default_transitions
    patch = TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD)
    assert_equal([], patch.transitions)
  end

  def test_frozen
    patch = TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD)
    assert(patch.frozen?)
    assert(patch.transitions.frozen?)
  end

  def test_nil_starts_at
    assert_raises(ArgumentError) do
      TimezonePatch.new(nil, Timestamp.utc(2000), OFFSET_STD)
    end
  end

  def test_nil_ends_at
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), nil, OFFSET_STD)
    end
  end

  def test_starts_at_without_utc_offset
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.new(1000), Timestamp.utc(2000), OFFSET_STD)
    end
  end

  def test_ends_at_without_utc_offset
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.new(2000), OFFSET_STD)
    end
  end

  def test_ends_at_equal_to_starts_at
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(1000), OFFSET_STD)
    end
  end

  def test_ends_at_before_starts_at
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(2000), Timestamp.utc(1000), OFFSET_STD)
    end
  end

  def test_nil_offset
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), nil)
    end
  end

  def test_offset_not_timezone_offset
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), 3600)
    end
  end

  def test_transitions_not_array
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD, :not_an_array)
    end
  end

  def test_transition_not_timezone_transition
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD, [:not_a_transition])
    end
  end

  def test_transition_at_starts_at
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD,
        [TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 1000)])
    end
  end

  def test_transition_at_ends_at
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD,
        [TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 2000)])
    end
  end

  def test_transition_outside_window
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD,
        [TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 3000)])
    end
  end

  def test_transitions_out_of_order
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD, [
        TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 1500),
        TimezoneTransition.new(OFFSET_DST, OFFSET_STD, 1200)
      ])
    end
  end

  def test_transitions_at_same_time
    assert_raises(ArgumentError) do
      TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD, [
        TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 1500),
        TimezoneTransition.new(OFFSET_DST, OFFSET_STD, 1500)
      ])
    end
  end

  def test_equality
    transition = TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 1500)
    patch1 = TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_DST, [transition])
    patch2 = TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_DST, [transition])

    assert(patch1 == patch2)
    assert(patch1.eql?(patch2))
    assert_equal(patch1.hash, patch2.hash)
  end

  def test_inequality
    patch = TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_DST)

    refute(patch == TimezonePatch.new(Timestamp.utc(1001), Timestamp.utc(2000), OFFSET_DST))
    refute(patch == TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2001), OFFSET_DST))
    refute(patch == TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_STD))
    refute(patch == TimezonePatch.new(Timestamp.utc(1000), Timestamp.utc(2000), OFFSET_DST,
      [TimezoneTransition.new(OFFSET_STD, OFFSET_DST, 1500)]))
    refute(patch == nil)
  end
end

