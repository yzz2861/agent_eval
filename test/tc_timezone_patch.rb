# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCTimezonePatch < Minitest::Test
  include TZInfo

  def test_initialize
    o1 = TimezoneOffset.new(3600, 0, 'TEST1')
    o2 = TimezoneOffset.new(7200, 0, 'TEST2')
    t1 = TimezoneTransition.new(o2, o1, 1500)
    transitions = [t1]

    patch = TimezonePatch.new(1000, 2000, o1, transitions)

    assert_equal(1000, patch.starts_at_value)
    assert_equal(2000, patch.ends_at_value)
    assert_equal(Timestamp.utc(1000), patch.starts_at)
    assert_equal(Timestamp.utc(2000), patch.ends_at)
    assert_same(o1, patch.offset)
    assert_equal([t1], patch.transitions)
    assert(patch.transitions.frozen?)
    refute_same(transitions, patch.transitions)
  end

  def test_initialize_default_transitions
    patch = TimezonePatch.new(1000, 2000, TimezoneOffset.new(3600, 0, 'TEST'))
    assert_equal([], patch.transitions)
    assert(patch.transitions.frozen?)
  end

  def test_initialize_time_like_boundaries
    o = TimezoneOffset.new(3600, 0, 'TEST')

    patch = TimezonePatch.new(Time.utc(2020, 1, 1), DateTime.new(2020, 2, 1), o)
    assert_equal(Time.utc(2020, 1, 1).to_i, patch.starts_at_value)
    assert_equal(Time.utc(2020, 2, 1).to_i, patch.ends_at_value)

    patch = TimezonePatch.new(Timestamp.utc(1000), TimestampWithOffset.new(2000, 0, 3600), o)
    assert_equal(1000, patch.starts_at_value)
    assert_equal(2000, patch.ends_at_value)
  end

  def test_initialize_invalid_boundary_type
    o = TimezoneOffset.new(3600, 0, 'TEST')

    error = assert_raises(ArgumentError) { TimezonePatch.new('1000', 2000, o) }
    assert_match(/\bstarts_at\b/, error.message)

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, '2000', o) }
    assert_match(/\bends_at\b/, error.message)
  end

  def test_initialize_nil_starts_at
    error = assert_raises(ArgumentError) { TimezonePatch.new(nil, 2000, TimezoneOffset.new(3600, 0, 'TEST')) }
    assert_match(/\bstarts_at\b/, error.message)
  end

  def test_initialize_nil_ends_at
    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, nil, TimezoneOffset.new(3600, 0, 'TEST')) }
    assert_match(/\bends_at\b/, error.message)
  end

  def test_initialize_nil_offset
    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, nil) }
    assert_match(/\boffset\b/, error.message)
  end

  def test_initialize_offset_not_timezone_offset
    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, 3600) }
    assert_match(/\boffset\b/, error.message)
  end

  def test_initialize_transitions_not_array
    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, TimezoneOffset.new(3600, 0, 'TEST'), :invalid) }
    assert_match(/\btransitions\b/, error.message)
  end

  def test_initialize_ends_at_not_after_starts_at
    o = TimezoneOffset.new(3600, 0, 'TEST')

    error = assert_raises(ArgumentError) { TimezonePatch.new(2000, 1000, o) }
    assert_match(/\bends_at\b/, error.message)

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 1000, o) }
    assert_match(/\bends_at\b/, error.message)
  end

  def test_initialize_transition_not_timezone_transition
    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, TimezoneOffset.new(3600, 0, 'TEST'), [:invalid]) }
    assert_match(/\bTimezoneTransition\b/, error.message)
  end

  def test_initialize_transitions_out_of_order
    o1 = TimezoneOffset.new(3600, 0, 'TEST1')
    o2 = TimezoneOffset.new(7200, 0, 'TEST2')
    t1 = TimezoneTransition.new(o2, o1, 1800)
    t2 = TimezoneTransition.new(o1, o2, 1200)

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [t1, t2]) }
    assert_match(/\bordered\b/, error.message)
  end

  def test_initialize_transitions_with_equal_timestamps
    o1 = TimezoneOffset.new(3600, 0, 'TEST1')
    o2 = TimezoneOffset.new(7200, 0, 'TEST2')
    t1 = TimezoneTransition.new(o2, o1, 1500)
    t2 = TimezoneTransition.new(o1, o2, 1500)

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [t1, t2]) }
    assert_match(/\bordered\b/, error.message)
  end

  def test_initialize_transition_on_or_before_starts_at
    o1 = TimezoneOffset.new(3600, 0, 'TEST1')
    o2 = TimezoneOffset.new(7200, 0, 'TEST2')

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [TimezoneTransition.new(o2, o1, 1000)]) }
    assert_match(/\bordered\b/, error.message)

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [TimezoneTransition.new(o2, o1, 500)]) }
    assert_match(/\bordered\b/, error.message)
  end

  def test_initialize_transition_on_or_after_ends_at
    o1 = TimezoneOffset.new(3600, 0, 'TEST1')
    o2 = TimezoneOffset.new(7200, 0, 'TEST2')

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [TimezoneTransition.new(o2, o1, 2000)]) }
    assert_match(/\bends_at\b/, error.message)

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [TimezoneTransition.new(o2, o1, 2500)]) }
    assert_match(/\bends_at\b/, error.message)
  end

  def test_initialize_transition_previous_offset_mismatch
    o1 = TimezoneOffset.new(3600, 0, 'TEST1')
    o2 = TimezoneOffset.new(7200, 0, 'TEST2')
    o3 = TimezoneOffset.new(10800, 0, 'TEST3')

    # The previous_offset of the first transition must equal the patch offset.
    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [TimezoneTransition.new(o3, o2, 1500)]) }
    assert_match(/\bprevious_offset\b/, error.message)

    # The previous_offset of each subsequent transition must equal the offset
    # of the prior transition.
    t1 = TimezoneTransition.new(o2, o1, 1200)
    t2 = TimezoneTransition.new(o1, o3, 1500)

    error = assert_raises(ArgumentError) { TimezonePatch.new(1000, 2000, o1, [t1, t2]) }
    assert_match(/\bprevious_offset\b/, error.message)
  end

  def test_equality
    o1 = TimezoneOffset.new(3600, 0, 'TEST1')
    o2 = TimezoneOffset.new(7200, 0, 'TEST2')
    t1 = TimezoneTransition.new(o2, o1, 1500)

    p1 = TimezonePatch.new(1000, 2000, o1, [t1])
    p2 = TimezonePatch.new(1000, 2000, o1, [t1])
    p3 = TimezonePatch.new(1000, 2000, o1)
    p4 = TimezonePatch.new(1000, 3000, o1, [t1])

    assert_equal(p1, p2)
    assert(p1.eql?(p2))
    assert_equal(p1.hash, p2.hash)
    refute_equal(p1, p3)
    refute_equal(p1, p4)
    refute_equal(p1, o1)
  end
end

