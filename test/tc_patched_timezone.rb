# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCPatchedTimezone < Minitest::Test
  include TZInfo

  OFFSET_A = TimezoneOffset.new(0, 0, 'A')
  OFFSET_B = TimezoneOffset.new(0, 3600, 'B')
  OFFSET_C = TimezoneOffset.new(7200, 0, 'C')
  OFFSET_D = TimezoneOffset.new(3600, 0, 'D')

  # A base zone observing A up to 1000, B to 2000, A to 5000 and then B.
  def transitions_base_timezone
    info = DataSources::TransitionsDataTimezoneInfo.new('Test/Base', [
      TimezoneTransition.new(OFFSET_B, OFFSET_A, 1000),
      TimezoneTransition.new(OFFSET_A, OFFSET_B, 2000),
      TimezoneTransition.new(OFFSET_B, OFFSET_A, 5000)
    ])
    DataTimezone.new(info)
  end

  # A base zone constantly observing A.
  def constant_base_timezone
    DataTimezone.new(DataSources::ConstantOffsetDataTimezoneInfo.new('Test/Constant', OFFSET_A))
  end

  # A patch observing C from 1500, transitioning to D at 1800 and reverting
  # to the base zone at 2500.
  def window_patch
    TimezonePatch.new(Timestamp.utc(1500), Timestamp.utc(2500), OFFSET_C,
      [TimezoneTransition.new(OFFSET_D, OFFSET_C, 1800)])
  end

  def patched_timezone(base = transitions_base_timezone, patches = [window_patch], identifier = nil)
    PatchedTimezone.new(base, patches, identifier)
  end

  def assert_period(offset, start_value, end_value, period)
    assert_equal(offset, period.offset)

    if start_value
      assert_equal(start_value, period.start_transition.timestamp_value)
    else
      assert_nil(period.start_transition)
    end

    if end_value
      assert_equal(end_value, period.end_transition.timestamp_value)
    else
      assert_nil(period.end_transition)
    end
  end

  def test_identifier
    assert_equal('Test/Base (patched)', patched_timezone.identifier)
  end

  def test_custom_identifier
    assert_equal('Test/Custom', patched_timezone(transitions_base_timezone, [window_patch], 'Test/Custom').identifier)
  end

  def test_base_timezone_and_patches
    base = transitions_base_timezone
    patch = window_patch
    tz = patched_timezone(base, [patch])

    assert_same(base, tz.base_timezone)
    assert_equal([patch], tz.patches)
    assert(tz.patches.frozen?)
  end

  def test_canonical_zone
    tz = patched_timezone
    assert_same(tz, tz.canonical_zone)
  end

  def test_nil_base_timezone
    assert_raises(ArgumentError) { PatchedTimezone.new(nil, [window_patch]) }
  end

  def test_base_timezone_not_timezone
    assert_raises(ArgumentError) { PatchedTimezone.new(:not_a_timezone, [window_patch]) }
  end

  def test_patches_not_array
    assert_raises(ArgumentError) { PatchedTimezone.new(transitions_base_timezone, :not_an_array) }
  end

  def test_patches_not_timezone_patches
    assert_raises(ArgumentError) { PatchedTimezone.new(transitions_base_timezone, [:not_a_patch]) }
  end

  def test_patches_out_of_order
    later = TimezonePatch.new(Timestamp.utc(3000), Timestamp.utc(4000), OFFSET_C)
    earlier = TimezonePatch.new(Timestamp.utc(1500), Timestamp.utc(2000), OFFSET_C)

    error = assert_raises(ArgumentError) do
      PatchedTimezone.new(transitions_base_timezone, [later, earlier])
    end
    assert_equal('patches must be in ascending order', error.message)
  end

  def test_patches_overlapping
    first = TimezonePatch.new(Timestamp.utc(1500), Timestamp.utc(2500), OFFSET_C)
    second = TimezonePatch.new(Timestamp.utc(2400), Timestamp.utc(3000), OFFSET_C)

    error = assert_raises(ArgumentError) do
      PatchedTimezone.new(transitions_base_timezone, [first, second])
    end
    assert_equal('patches must not overlap', error.message)
  end

  def test_abutting_patches_allowed
    first = TimezonePatch.new(Timestamp.utc(1500), Timestamp.utc(2000), OFFSET_C)
    second = TimezonePatch.new(Timestamp.utc(2000), Timestamp.utc(2500), OFFSET_D)
    tz = PatchedTimezone.new(constant_base_timezone, [first, second])

    assert_period(OFFSET_C, 1500, 2000, tz.period_for(Timestamp.utc(1999)))
    assert_period(OFFSET_D, 2000, 2500, tz.period_for(Timestamp.utc(2000)))

    transitions = tz.transitions_up_to(Timestamp.utc(3000))
    assert_equal([1500, 2000, 2500], transitions.map(&:timestamp_value))
    assert_equal([OFFSET_A, OFFSET_C, OFFSET_D], transitions.map(&:previous_offset))
    assert_equal([OFFSET_C, OFFSET_D, OFFSET_A], transitions.map(&:offset))
  end

  def test_period_for_before_window
    tz = patched_timezone
    assert_period(OFFSET_A, nil, 1000, tz.period_for(Timestamp.utc(500)))
  end

  def test_period_for_between_base_transition_and_window
    tz = patched_timezone
    # The base period is clipped at the start of the patch window.
    assert_period(OFFSET_B, 1000, 1500, tz.period_for(Timestamp.utc(1200)))
  end

  def test_period_for_within_window
    tz = patched_timezone
    assert_period(OFFSET_C, 1500, 1800, tz.period_for(Timestamp.utc(1500)))
    assert_period(OFFSET_C, 1500, 1800, tz.period_for(Timestamp.utc(1700)))
    assert_period(OFFSET_D, 1800, 2500, tz.period_for(Timestamp.utc(1800)))
    assert_period(OFFSET_D, 1800, 2500, tz.period_for(Timestamp.utc(2499)))
  end

  def test_period_for_within_window_suppresses_base_transitions
    tz = patched_timezone
    # The base zone transitions to A at 2000, but that is within the window.
    assert_period(OFFSET_D, 1800, 2500, tz.period_for(Timestamp.utc(2100)))
  end

  def test_period_for_at_end_of_window
    tz = patched_timezone
    # The base zone rules apply again from the end of the window.
    assert_period(OFFSET_A, 2500, 5000, tz.period_for(Timestamp.utc(2500)))
    assert_period(OFFSET_A, 2500, 5000, tz.period_for(Timestamp.utc(3000)))
  end

  def test_period_for_after_window
    tz = patched_timezone
    assert_period(OFFSET_B, 5000, nil, tz.period_for(Timestamp.utc(5500)))
  end

  def test_period_for_nil
    assert_raises(ArgumentError) { patched_timezone.period_for(nil) }
  end

  def test_period_for_timestamp_without_utc_offset
    assert_raises(ArgumentError) { patched_timezone.period_for(Timestamp.new(1500)) }
  end

  def test_transitions_up_to
    tz = patched_timezone
    transitions = tz.transitions_up_to(Timestamp.utc(6000))

    assert_equal([1000, 1500, 1800, 2500, 5000], transitions.map(&:timestamp_value))
    assert_equal([OFFSET_A, OFFSET_B, OFFSET_C, OFFSET_D, OFFSET_A], transitions.map(&:previous_offset))
    assert_equal([OFFSET_B, OFFSET_C, OFFSET_D, OFFSET_A, OFFSET_B], transitions.map(&:offset))
  end

  def test_transitions_up_to_to_is_exclusive
    tz = patched_timezone
    assert_equal([1000, 1500, 1800], tz.transitions_up_to(Timestamp.utc(2500)).map(&:timestamp_value))
    assert_equal([1000, 1500, 1800, 2500], tz.transitions_up_to(Timestamp.utc(2501)).map(&:timestamp_value))
  end

  def test_transitions_up_to_from_is_inclusive
    tz = patched_timezone
    assert_equal([1500, 1800, 2500, 5000],
      tz.transitions_up_to(Timestamp.utc(6000), Timestamp.utc(1500)).map(&:timestamp_value))
    assert_equal([1800, 2500, 5000],
      tz.transitions_up_to(Timestamp.utc(6000), Timestamp.utc(1501)).map(&:timestamp_value))
  end

  def test_transitions_up_to_nil_to
    assert_raises(ArgumentError) { patched_timezone.transitions_up_to(nil) }
  end

  def test_transitions_up_to_to_not_greater_than_from
    tz = patched_timezone
    assert_raises(ArgumentError) { tz.transitions_up_to(Timestamp.utc(1500), Timestamp.utc(1500)) }
    assert_raises(ArgumentError) { tz.transitions_up_to(Timestamp.utc(1400), Timestamp.utc(1500)) }
  end

  def test_period_for_and_transitions_up_to_are_consistent
    tz = patched_timezone
    transitions = tz.transitions_up_to(Timestamp.utc(6000))
    offset = OFFSET_A

    (0..6000).step(137) do |value|
      while !transitions.empty? && transitions.first.timestamp_value <= value
        offset = transitions.shift.offset
      end

      assert_equal(offset, tz.period_for(Timestamp.utc(value)).offset, "offset at #{value}")
    end
  end

  def test_periods_for_local_unambiguous
    tz = patched_timezone
    assert_equal([OFFSET_A], tz.periods_for_local(Timestamp.new(500)).map(&:offset))
    assert_equal([OFFSET_D], tz.periods_for_local(Timestamp.new(5700)).map(&:offset))
  end

  def test_periods_for_local_gap_at_start_of_window
    tz = patched_timezone(constant_base_timezone)

    # The window starts by moving from A (+0) to C (+2) at 1500. Local times
    # from 1500 up to 1500 + 7200 do not occur unless covered by another
    # period. The base zone resumes at 2500, covering local times from 2500.
    assert_equal([], tz.periods_for_local(Timestamp.new(2000)))
    assert_raises(PeriodNotFound) { tz.period_for_local(Timestamp.new(2000)) }
  end

  def test_periods_for_local_overlap_at_end_of_window
    tz = patched_timezone(constant_base_timezone)

    # The window ends by moving from D (+1) back to A (+0) at 2500. Local
    # times from 2500 + 3600 = 6100 down to 2500 occur twice.
    periods = tz.periods_for_local(Timestamp.new(5700))
    assert_equal([OFFSET_D, OFFSET_A], periods.map(&:offset))
    assert_equal([2100, 5700], periods.map {|p| 5700 - p.observed_utc_offset })

    assert_raises(AmbiguousTime) { tz.period_for_local(Timestamp.new(5700)) }
    assert_equal(OFFSET_D, tz.period_for_local(Timestamp.new(5700)) {|periods| periods.first }.offset)
    assert_equal(OFFSET_A, tz.period_for_local(Timestamp.new(5700)) {|periods| periods.last }.offset)
  end

  def test_periods_for_local_ambiguous_across_window_and_base
    tz = patched_timezone

    # Observed by C within the window (UTC 1600) and by the base zone
    # observing B after 5000 (UTC 5200).
    periods = tz.periods_for_local(Timestamp.new(8800))
    assert_equal([OFFSET_C, OFFSET_B], periods.map(&:offset))
  end

  def test_periods_for_local_nil
    assert_raises(ArgumentError) { patched_timezone.periods_for_local(nil) }
  end

  def test_utc_to_local_within_window
    tz = patched_timezone(constant_base_timezone)
    local = tz.utc_to_local(Timestamp.utc(1600))

    assert_equal(1600, local.value)
    assert_equal(7200, local.utc_offset)
  end

  def test_local_to_utc_gap_and_overlap
    tz = patched_timezone(constant_base_timezone)

    assert_raises(PeriodNotFound) { tz.local_to_utc(Timestamp.new(2000)) }
    assert_raises(AmbiguousTime) { tz.local_to_utc(Timestamp.new(5700)) }
    assert_equal(1600, tz.local_to_utc(Timestamp.new(8800)) {|periods| periods.first }.value)
  end

  def test_base_transition_at_start_of_window
    info = DataSources::TransitionsDataTimezoneInfo.new('Test/Boundary', [
      TimezoneTransition.new(OFFSET_B, OFFSET_A, 1500),
      TimezoneTransition.new(OFFSET_A, OFFSET_B, 5000)
    ])
    base = DataTimezone.new(info)
    patch = TimezonePatch.new(Timestamp.utc(1500), Timestamp.utc(2500), OFFSET_C)
    tz = PatchedTimezone.new(base, [patch])

    # The base transition at 1500 is replaced by the transition into the
    # window (from the offset observed before the window).
    transitions = tz.transitions_up_to(Timestamp.utc(6000))
    assert_equal([1500, 2500, 5000], transitions.map(&:timestamp_value))
    assert_equal([OFFSET_A, OFFSET_C, OFFSET_B], transitions.map(&:previous_offset))
    assert_equal([OFFSET_C, OFFSET_B, OFFSET_A], transitions.map(&:offset))

    assert_period(OFFSET_A, nil, 1500, tz.period_for(Timestamp.utc(1499)))
    assert_period(OFFSET_C, 1500, 2500, tz.period_for(Timestamp.utc(1500)))
  end

  def test_base_transition_at_end_of_window
    info = DataSources::TransitionsDataTimezoneInfo.new('Test/Boundary', [
      TimezoneTransition.new(OFFSET_B, OFFSET_A, 1000),
      TimezoneTransition.new(OFFSET_A, OFFSET_B, 2500)
    ])
    base = DataTimezone.new(info)
    patch = TimezonePatch.new(Timestamp.utc(1500), Timestamp.utc(2500), OFFSET_C)
    tz = PatchedTimezone.new(base, [patch])

    # The base transition at 2500 is replaced by the transition reverting to
    # the base zone (to the offset the base zone observes from 2500).
    transitions = tz.transitions_up_to(Timestamp.utc(6000))
    assert_equal([1000, 1500, 2500], transitions.map(&:timestamp_value))
    assert_equal([OFFSET_A, OFFSET_B, OFFSET_C], transitions.map(&:previous_offset))
    assert_equal([OFFSET_B, OFFSET_C, OFFSET_A], transitions.map(&:offset))

    assert_period(OFFSET_C, 1500, 2500, tz.period_for(Timestamp.utc(2499)))
    assert_period(OFFSET_A, 2500, nil, tz.period_for(Timestamp.utc(2500)))
  end

  def test_empty_patches_delegates_to_base
    base = transitions_base_timezone
    tz = PatchedTimezone.new(base, [])

    assert_equal(base.period_for(Timestamp.utc(1200)), tz.period_for(Timestamp.utc(1200)))
    assert_equal(base.periods_for_local(Timestamp.new(1200)), tz.periods_for_local(Timestamp.new(1200)))
    assert_equal(base.transitions_up_to(Timestamp.utc(6000)), tz.transitions_up_to(Timestamp.utc(6000)))
    assert_equal('Test/Base (patched)', tz.identifier)
  end

  def test_multiple_separate_patches
    first = TimezonePatch.new(Timestamp.utc(1500), Timestamp.utc(1800), OFFSET_C)
    second = TimezonePatch.new(Timestamp.utc(3000), Timestamp.utc(4000), OFFSET_D,
      [TimezoneTransition.new(OFFSET_C, OFFSET_D, 3500)])
    tz = PatchedTimezone.new(transitions_base_timezone, [first, second])

    transitions = tz.transitions_up_to(Timestamp.utc(6000))
    assert_equal([1000, 1500, 1800, 2000, 3000, 3500, 4000, 5000], transitions.map(&:timestamp_value))
    assert_equal([OFFSET_A, OFFSET_B, OFFSET_C, OFFSET_B, OFFSET_A, OFFSET_D, OFFSET_C, OFFSET_A],
      transitions.map(&:previous_offset))
    assert_equal([OFFSET_B, OFFSET_C, OFFSET_B, OFFSET_A, OFFSET_D, OFFSET_C, OFFSET_A, OFFSET_B],
      transitions.map(&:offset))

    assert_period(OFFSET_A, 2000, 3000, tz.period_for(Timestamp.utc(2000)))
    assert_period(OFFSET_D, 3000, 3500, tz.period_for(Timestamp.utc(3000)))
    assert_period(OFFSET_C, 3500, 4000, tz.period_for(Timestamp.utc(3600)))
    assert_period(OFFSET_A, 4000, 5000, tz.period_for(Timestamp.utc(4500)))
  end

  def test_base_timezone_is_not_modified
    base = transitions_base_timezone
    tz = patched_timezone(base)

    tz.period_for(Timestamp.utc(2100))
    tz.periods_for_local(Timestamp.new(5700))
    tz.transitions_up_to(Timestamp.utc(6000))

    assert_equal([1000, 2000, 5000],
      base.transitions_up_to(Timestamp.utc(6000)).map(&:timestamp_value))
    assert_equal(OFFSET_A, base.period_for(Timestamp.utc(2100)).offset)
  end

  def test_patches_array_is_copied
    patch = window_patch
    patches = [patch]
    tz = patched_timezone(transitions_base_timezone, patches)
    patches.clear

    assert_equal([patch], tz.patches)
    assert_period(OFFSET_C, 1500, 1800, tz.period_for(Timestamp.utc(1600)))
  end
end
