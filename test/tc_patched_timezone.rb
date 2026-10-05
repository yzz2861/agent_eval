# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCPatchedTimezone < Minitest::Test
  include TZInfo

  # Base zone used by most tests:
  #
  #   UTC time       Offset
  #   < 10000        A (UTC+1)
  #   10000 - 20000  B (UTC+2)
  #   20000 - 30000  A (UTC+1)
  #   30000 - 40000  B (UTC+2)
  #   >= 40000       A (UTC+1)
  def create_base_timezone
    transitions = [
      TimezoneTransition.new(offset_b, offset_a, 10000),
      TimezoneTransition.new(offset_a, offset_b, 20000),
      TimezoneTransition.new(offset_b, offset_a, 30000),
      TimezoneTransition.new(offset_a, offset_b, 40000)
    ]

    DataTimezone.new(DataSources::TransitionsDataTimezoneInfo.new('Test/Base', transitions))
  end

  def offset_a
    @offset_a ||= TimezoneOffset.new(3600, 0, 'A')
  end

  def offset_b
    @offset_b ||= TimezoneOffset.new(3600, 3600, 'B')
  end

  def offset_c
    @offset_c ||= TimezoneOffset.new(7200, 3600, 'C')
  end

  def offset_d
    @offset_d ||= TimezoneOffset.new(1800, 0, 'D')
  end

  def create_patched_timezone(patches, identifier = nil)
    PatchedTimezone.new(create_base_timezone, patches, identifier)
  end

  def transition_values(timezone, to, from = nil)
    timezone.transitions_up_to(Timestamp.utc(to), from && Timestamp.utc(from)).map {|t| [t.timestamp_value, t.previous_offset, t.offset] }
  end

  def test_identifier
    assert_equal('Test/Base+patched', create_patched_timezone([]).identifier)
    assert_equal('Test/Custom', create_patched_timezone([], 'Test/Custom').identifier)
  end

  def test_base_timezone_and_patches
    base = create_base_timezone
    patch = TimezonePatch.new(15000, 35000, offset_c)
    timezone = PatchedTimezone.new(base, [patch])

    assert_same(base, timezone.base_timezone)
    assert_equal([patch], timezone.patches)
    assert(timezone.patches.frozen?)
  end

  def test_canonical_zone
    timezone = create_patched_timezone([])
    assert_same(timezone, timezone.canonical_zone)
  end

  def test_initialize_invalid_arguments
    base = create_base_timezone
    patch = TimezonePatch.new(15000, 35000, offset_c)

    assert_raises(ArgumentError) { PatchedTimezone.new(nil, [patch]) }
    assert_raises(ArgumentError) { PatchedTimezone.new(:invalid, [patch]) }
    assert_raises(ArgumentError) { PatchedTimezone.new(base, nil) }
    assert_raises(ArgumentError) { PatchedTimezone.new(base, :invalid) }
    assert_raises(ArgumentError) { PatchedTimezone.new(base, [:invalid]) }
  end

  def test_patches_must_be_in_ascending_order
    p1 = TimezonePatch.new(15000, 19000, offset_c)
    p2 = TimezonePatch.new(11000, 12000, offset_c)

    error = assert_raises(ArgumentError) { create_patched_timezone([p1, p2]) }
    assert_match(/\bascending\b/, error.message)
  end

  def test_patches_must_not_overlap
    p1 = TimezonePatch.new(11000, 19000, offset_c)
    p2 = TimezonePatch.new(15000, 25000, offset_c)

    error = assert_raises(ArgumentError) { create_patched_timezone([p1, p2]) }
    assert_match(/overlap/, error.message)
  end

  def test_patches_must_not_abut
    p1 = TimezonePatch.new(11000, 19000, offset_c)
    p2 = TimezonePatch.new(19000, 25000, offset_c)

    error = assert_raises(ArgumentError) { create_patched_timezone([p1, p2]) }
    assert_match(/overlap/, error.message)
  end

  def test_empty_patches_behaves_like_base
    base = create_base_timezone
    timezone = PatchedTimezone.new(base, [])

    assert_equal(transition_values(base, 50000), transition_values(timezone, 50000))
    assert_equal(base.period_for(Timestamp.utc(5000)), timezone.period_for(Timestamp.utc(5000)))
    assert_equal(base.period_for(Timestamp.utc(15000)), timezone.period_for(Timestamp.utc(15000)))
  end

  # Patch window [15000, 35000) observing C (UTC+3) with an internal
  # transition to D (UTC+0:30) at 25000. Merged result:
  #
  #   UTC time       Offset
  #   < 10000        A
  #   10000 - 15000  B
  #   15000 - 25000  C
  #   25000 - 35000  D
  #   35000 - 40000  B
  #   >= 40000       A
  def create_standard_patched_timezone
    patch = TimezonePatch.new(15000, 35000, offset_c, [TimezoneTransition.new(offset_d, offset_c, 25000)])
    create_patched_timezone([patch])
  end

  def test_transitions_up_to
    timezone = create_standard_patched_timezone

    assert_equal(
      [
        [10000, offset_a, offset_b],
        [15000, offset_b, offset_c],
        [25000, offset_c, offset_d],
        [35000, offset_d, offset_b],
        [40000, offset_b, offset_a]
      ],
      transition_values(timezone, 50000))
  end

  def test_transitions_up_to_with_from_and_to
    timezone = create_standard_patched_timezone

    # to is exclusive
    assert_equal(
      [[10000, offset_a, offset_b], [15000, offset_b, offset_c], [25000, offset_c, offset_d]],
      transition_values(timezone, 35000))

    # from is inclusive
    assert_equal(
      [[15000, offset_b, offset_c], [25000, offset_c, offset_d], [35000, offset_d, offset_b]],
      transition_values(timezone, 36000, 15000))

    assert_equal([], transition_values(timezone, 25000, 16000))
  end

  def test_period_for
    timezone = create_standard_patched_timezone

    period = timezone.period_for(Timestamp.utc(5000))
    assert_equal(offset_a, period.offset)
    assert_nil(period.start_transition)
    assert_equal(10000, period.end_transition.timestamp_value)

    period = timezone.period_for(Timestamp.utc(14999))
    assert_equal(offset_b, period.offset)

    period = timezone.period_for(Timestamp.utc(15000))
    assert_equal(offset_c, period.offset)
    assert_equal(15000, period.start_transition.timestamp_value)
    assert_equal(25000, period.end_transition.timestamp_value)

    period = timezone.period_for(Timestamp.utc(24999))
    assert_equal(offset_c, period.offset)

    period = timezone.period_for(Timestamp.utc(25000))
    assert_equal(offset_d, period.offset)
    assert_equal(25000, period.start_transition.timestamp_value)
    assert_equal(35000, period.end_transition.timestamp_value)

    period = timezone.period_for(Timestamp.utc(34999))
    assert_equal(offset_d, period.offset)

    # The base rules are restored from the end of the window.
    period = timezone.period_for(Timestamp.utc(35000))
    assert_equal(offset_b, period.offset)
    assert_equal(35000, period.start_transition.timestamp_value)
    assert_equal(40000, period.end_transition.timestamp_value)

    period = timezone.period_for(Timestamp.utc(40000))
    assert_equal(offset_a, period.offset)
    assert_equal(40000, period.start_transition.timestamp_value)
    assert_nil(period.end_transition)
  end

  def test_periods_for_local
    timezone = create_standard_patched_timezone

    # The transition into the patch at 15000 moves the clocks forward from
    # B (UTC+2) to C (UTC+3), making local times [22200, 25800) invalid.
    assert_equal([], timezone.periods_for_local(Timestamp.new(22200)))
    assert_equal([], timezone.periods_for_local(Timestamp.new(23000)))

    # The transition within the patch at 25000 moves the clocks back from
    # C (UTC+3) to D (UTC+0:30), making local times [26800, 35800) ambiguous.
    periods = timezone.periods_for_local(Timestamp.new(30000))
    assert_equal(2, periods.length)
    assert_equal(offset_c, periods[0].offset)
    assert_equal(offset_d, periods[1].offset)

    # The transition restoring the base rules at 35000 moves the clocks
    # forward from D (UTC+0:30) to B (UTC+2), making local times
    # [36800, 42200) invalid.
    assert_equal([], timezone.periods_for_local(Timestamp.new(36800)))
    assert_equal([], timezone.periods_for_local(Timestamp.new(40000)))

    # The base transition at 40000 moves the clocks back from B (UTC+2) to
    # A (UTC+1), making local times [43600, 47200) ambiguous.
    periods = timezone.periods_for_local(Timestamp.new(45000))
    assert_equal(2, periods.length)
    assert_equal(offset_b, periods[0].offset)
    assert_equal(offset_a, periods[1].offset)

    # Unambiguous local times resolve to a single period.
    periods = timezone.periods_for_local(Timestamp.new(20000))
    assert_equal(1, periods.length)
    assert_equal(offset_b, periods[0].offset)
  end

  def test_period_for_local_in_gap
    timezone = create_standard_patched_timezone
    assert_raises(PeriodNotFound) { timezone.period_for_local(Timestamp.new(23000)) }
  end

  def test_local_to_utc_resolves_overlap_with_dst
    timezone = create_standard_patched_timezone

    # The overlap at 25000 is between C (dst) and D (standard).
    assert_equal(19200, timezone.local_to_utc(Timestamp.new(30000), true).value)
    assert_equal(28200, timezone.local_to_utc(Timestamp.new(30000), false).value)
  end

  def test_base_timezone_is_not_modified
    base = create_base_timezone
    transitions_before = transition_values(base, 50000)
    periods_before = [5000, 16000, 26000, 36000, 45000].map {|t| base.period_for(Timestamp.utc(t)).offset }

    create_standard_patched_timezone_with_base(base)

    assert_equal(transitions_before, transition_values(base, 50000))
    assert_equal(periods_before, [5000, 16000, 26000, 36000, 45000].map {|t| base.period_for(Timestamp.utc(t)).offset })
  end

  def create_standard_patched_timezone_with_base(base)
    patch = TimezonePatch.new(15000, 35000, offset_c, [TimezoneTransition.new(offset_d, offset_c, 25000)])
    PatchedTimezone.new(base, [patch])
  end

  def test_patch_window_aligned_with_base_transitions
    # The window starts and ends exactly on base transitions.
    patch = TimezonePatch.new(20000, 30000, offset_c)
    timezone = create_patched_timezone([patch])

    assert_equal(
      [
        [10000, offset_a, offset_b],
        [20000, offset_b, offset_c],
        [30000, offset_c, offset_b],
        [40000, offset_b, offset_a]
      ],
      transition_values(timezone, 50000))
  end

  def test_patch_with_no_effect
    # The patch offset matches the base offset at both ends of the window,
    # so no transitions are inserted.
    patch = TimezonePatch.new(11000, 19000, offset_b)
    timezone = create_patched_timezone([patch])

    assert_equal(transition_values(create_base_timezone, 50000), transition_values(timezone, 50000))
  end

  def test_patch_reproducing_base_transitions
    # The patch reproduces the base transition within the window exactly.
    patch = TimezonePatch.new(15000, 25000, offset_b, [TimezoneTransition.new(offset_a, offset_b, 20000)])
    timezone = create_patched_timezone([patch])

    assert_equal(transition_values(create_base_timezone, 50000), transition_values(timezone, 50000))
  end

  def test_multiple_patches
    p1 = TimezonePatch.new(11000, 19000, offset_c)
    p2 = TimezonePatch.new(21000, 29000, offset_d)
    timezone = create_patched_timezone([p1, p2])

    assert_equal(
      [
        [10000, offset_a, offset_b],
        [11000, offset_b, offset_c],
        [19000, offset_c, offset_b],
        [20000, offset_b, offset_a],
        [21000, offset_a, offset_d],
        [29000, offset_d, offset_a],
        [30000, offset_a, offset_b],
        [40000, offset_b, offset_a]
      ],
      transition_values(timezone, 50000))
  end

  def test_constant_offset_base
    base = DataTimezone.new(DataSources::ConstantOffsetDataTimezoneInfo.new('Test/Constant', offset_a))
    patch = TimezonePatch.new(10000, 20000, offset_c, [TimezoneTransition.new(offset_d, offset_c, 15000)])
    timezone = PatchedTimezone.new(base, [patch])

    assert_equal(
      [
        [10000, offset_a, offset_c],
        [15000, offset_c, offset_d],
        [20000, offset_d, offset_a]
      ],
      transition_values(timezone, 50000))

    assert_equal(offset_a, timezone.period_for(Timestamp.utc(5000)).offset)
    assert_equal(offset_c, timezone.period_for(Timestamp.utc(12000)).offset)
    assert_equal(offset_d, timezone.period_for(Timestamp.utc(17000)).offset)
    assert_equal(offset_a, timezone.period_for(Timestamp.utc(25000)).offset)
  end

  def test_noop_patch_on_constant_offset_base
    base = DataTimezone.new(DataSources::ConstantOffsetDataTimezoneInfo.new('Test/Constant', offset_a))
    patch = TimezonePatch.new(10000, 20000, offset_a)
    timezone = PatchedTimezone.new(base, [patch])

    assert_equal([], transition_values(timezone, 50000))
    assert_equal(offset_a, timezone.period_for(Timestamp.utc(15000)).offset)
  end
end
