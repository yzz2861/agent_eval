# encoding: UTF-8
# frozen_string_literal: true

require_relative 'test_utils'

class TCDataTimezone < Minitest::Test
  include TZInfo

  class TestTimezoneInfo < DataSources::TimezoneInfo
    attr_reader :timestamp
    attr_reader :local_timestamp
    attr_reader :to_timestamp
    attr_reader :from_timestamp

    def initialize(identifier, period_for_result, periods_for_local_result, transitions_up_to_result)
      super(identifier)
      @period_for_result = period_for_result
      @periods_for_local_result = periods_for_local_result || []
      @transitions_up_to_result = transitions_up_to_result
    end

    def period_for(timestamp)
      raise ArgumentError, 'timestamp must be specified' unless timestamp
      raise ArgumentError, 'timestamp must have a specified utc_offset' unless timestamp.utc_offset

      @timestamp = timestamp
      @period_for_result
    end

    def periods_for_local(local_timestamp)
      raise ArgumentError, 'local_timestamp must be specified' unless local_timestamp
      raise ArgumentError, 'local_timestamp must have an unspecified utc_offset' if local_timestamp.utc_offset

      @local_timestamp = local_timestamp
      @periods_for_local_result
    end

    def transitions_up_to(to_timestamp, from_timestamp = nil)
      raise ArgumentError, 'to_timestamp must be specified' unless to_timestamp
      raise ArgumentError, 'to_timestamp must have a specified utc_offset' unless to_timestamp.utc_offset

      if from_timestamp
        raise ArgumentError, 'from_timestamp must have a specified utc_offset' unless from_timestamp.utc_offset
        raise ArgumentError, 'to_timestamp must be greater than from_timestamp' if to_timestamp <= from_timestamp
      end

      @to_timestamp = to_timestamp
      @from_timestamp = from_timestamp
      @transitions_up_to_result
    end
  end

  def test_identifier
    tz = DataTimezone.new(TestTimezoneInfo.new('Test/Zone', nil, [], []))
    assert_equal('Test/Zone', tz.identifier)
  end

  def test_period_for
    time_types_test(:utc) do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      period = Object.new
      tti = TestTimezoneInfo.new('Test/Zone', period, [], [])
      tz = DataTimezone.new(tti)

      assert_same(period, tz.period_for(h.time(2006, 6, 27, 22, 50, 12, Rational(1,10), :utc)))
      assert_equal_with_offset(Timestamp.create(2006, 6, 27, 22, 50, 12, Rational(1,10), :utc), tti.timestamp)
    end
  end

  def test_period_for_zero_offset
    time_types_test do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      period = Object.new
      tti = TestTimezoneInfo.new('Test/Zone', period, [], [])
      tz = DataTimezone.new(tti)

      assert_same(period, tz.period_for(h.time(2006, 6, 27, 22, 50, 12, Rational(1,10), 0)))
      assert_equal_with_offset(Timestamp.create(2006, 6, 27, 22, 50, 12, Rational(1,10), h.expected_zero_offset), tti.timestamp)
    end
  end

  def test_period_for_offset
    time_types_test(:offset) do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      period = Object.new
      tti = TestTimezoneInfo.new('Test/Zone', period, [], [])
      tz = DataTimezone.new(tti)

      assert_same(period, tz.period_for(h.time(2006, 6, 27, 22, 50, 12, Rational(1,10), 3600)))
      assert_equal_with_offset(Timestamp.create(2006, 6, 27, 22, 50, 12, Rational(1,10), 3600), tti.timestamp)
    end
  end

  def test_period_for_unspecified
    time_types_test(:unspecified_offset) do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      tti = TestTimezoneInfo.new('Test/Zone', Object.new, [], [])
      tz = DataTimezone.new(tti)
      t = h.time(2006, 6, 27, 22, 50, 12, Rational(1,10))

      error = assert_raises(ArgumentError) { tz.period_for(t) }
      assert_match(/\btime\b/, error.message)
    end
  end

  def test_period_for_nil
    tti = TestTimezoneInfo.new('Test/Zone', Object.new, [], [])
    tz = DataTimezone.new(tti)

    error = assert_raises(ArgumentError) { tz.period_for(nil) }
    assert_match(/\btime\b/, error.message)
  end

  def test_period_for_unsupported_value
    tti = TestTimezoneInfo.new('Test/Zone', Object.new, [], [])
    tz = DataTimezone.new(tti)
    t = Time.utc(2006, 6, 27, 22, 50, 12).to_i

    error = assert_raises(ArgumentError) { tz.period_for(t) }
    assert_match(Regexp.new("\\b#{Regexp.escape(t.class.name)}\\b"), error.message)
  end

  def test_periods_for_local_unspecified
    time_types_test(:unspecified_offset) do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      periods = [Object.new, Object.new]
      tti = TestTimezoneInfo.new('Test/Zone', nil, periods, [])
      tz = DataTimezone.new(tti)

      assert_same(periods, tz.periods_for_local(h.time(2006, 6, 27, 22, 50, 12, Rational(1,10))))
      assert_equal_with_offset(Timestamp.create(2006, 6, 27, 22, 50, 12, Rational(1,10)), tti.local_timestamp)
    end
  end

  def test_periods_for_local_utc
    time_types_test(:utc) do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      periods = [Object.new, Object.new]
      tti = TestTimezoneInfo.new('Test/Zone', nil, periods, [])
      tz = DataTimezone.new(tti)

      assert_same(periods, tz.periods_for_local(h.time(2006, 6, 27, 22, 50, 12, Rational(1,10), :utc)))
      assert_equal_with_offset(Timestamp.create(2006, 6, 27, 22, 50, 12, Rational(1,10)), tti.local_timestamp)
    end
  end

  def test_periods_for_local_zero_offset
    time_types_test do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      periods = [Object.new, Object.new]
      tti = TestTimezoneInfo.new('Test/Zone', nil, periods, [])
      tz = DataTimezone.new(tti)

      assert_same(periods, tz.periods_for_local(h.time(2006, 6, 27, 22, 50, 12, Rational(1,10), 0)))
      assert_equal_with_offset(Timestamp.create(2006, 6, 27, 22, 50, 12, Rational(1,10)), tti.local_timestamp)
    end
  end

  def test_periods_for_local_with_offset
    time_types_test(:offset) do |h|
      # Don't need actual TimezonePeriods. DataTimezone isn't supposed to do
      # anything with them apart from return them.
      periods = [Object.new, Object.new]
      tti = TestTimezoneInfo.new('Test/Zone', nil, periods, [])
      tz = DataTimezone.new(tti)

      assert_same(periods, tz.periods_for_local(h.time(2006, 6, 27, 22, 50, 12, Rational(1,10), 3600)))
      assert_equal_with_offset(Timestamp.create(2006, 6, 27, 22, 50, 12, Rational(1,10)), tti.local_timestamp)
    end
  end

  def test_periods_for_local_not_found
    periods = []
    tti = TestTimezoneInfo.new('Test/Zone', nil, periods, [])
    tz = DataTimezone.new(tti)

    t = Time.utc(2006, 6, 27, 22, 50, 12 + Rational(1,10))
    assert_same(periods, tz.periods_for_local(t))
    assert_equal_with_offset(Timestamp.new(t.to_i, Rational(1,10)), tti.local_timestamp)
  end

  def test_periods_for_local_nil
    tti = TestTimezoneInfo.new('Test/Zone', Object.new, [], [])
    tz = DataTimezone.new(tti)

    error = assert_raises(ArgumentError) { tz.periods_for_local(nil) }
    assert_match(/\blocal_time\b/, error.message)
  end

  def test_periods_for_local_unsupported
    tti = TestTimezoneInfo.new('Test/Zone', Object.new, [], [])
    tz = DataTimezone.new(tti)
    t = Time.utc(2006, 6, 27, 22, 50, 12).to_i

    error = assert_raises(ArgumentError) { tz.periods_for_local(t) }
    assert_match(Regexp.new("\\b#{Regexp.escape(t.class.name)}\\b"), error.message)
  end

  def test_transitions_up_to_utc
    time_types_test(:utc) do |h|
      # Don't need actual TimezoneTransition instances. DataTimezone isn't
      # supposed to do anything with them apart from return them.
      transitions = [Object.new, Object.new]
      tti = TestTimezoneInfo.new('Test/Zone', nil, nil, transitions)
      tz = DataTimezone.new(tti)

      assert_same(transitions, tz.transitions_up_to(h.time(2013, 1, 1, 0, 0, 0, Rational(1,10), :utc), h.time(2012, 1, 1, 0, 0, 0, Rational(1,10), :utc)))
      assert_equal_with_offset(Timestamp.create(2013, 1, 1, 0, 0, 0, Rational(1,10), :utc), tti.to_timestamp)
      assert_equal_with_offset(Timestamp.create(2012, 1, 1, 0, 0, 0, Rational(1,10), :utc), tti.from_timestamp)
    end
  end

  def test_transitions_up_to_zero_offset
    time_types_test do |h|
      # Don't need actual TimezoneTransition instances. DataTimezone isn't
      # supposed to do anything with them apart from return them.
      transitions = [Object.new, Object.new]
      tti = TestTimezoneInfo.new('Test/Zone', nil, nil, transitions)
      tz = DataTimezone.new(tti)

      assert_same(transitions, tz.transitions_up_to(h.time(2013, 1, 1, 0, 0, 0, Rational(1,10), 0), h.time(2012, 1, 1, 0, 0, 0, Rational(1,10), 0)))
      assert_equal_with_offset(Timestamp.create(2013, 1, 1, 0, 0, 0, Rational(1,10), h.expected_zero_offset), tti.to_timestamp)
      assert_equal_with_offset(Timestamp.create(2012, 1, 1, 0, 0, 0, Rational(1,10), h.expected_zero_offset), tti.from_timestamp)
    end
  end

  def test_transitions_up_to_offset
    time_types_test(:offset) do |h|
      # Don't need actual TimezoneTransition instances. DataTimezone isn't
      # supposed to do anything with them apart from return them.
      transitions = [Object.new, Object.new]
      tti = TestTimezoneInfo.new('Test/Zone', nil, nil, transitions)
      tz = DataTimezone.new(tti)

      assert_same(transitions, tz.transitions_up_to(h.time(2013, 1, 1, 0, 0, 0, Rational(1,10), -3600), h.time(2012, 1, 1, 0, 0, 0, Rational(1,10), 3600)))
      assert_equal_with_offset(Timestamp.create(2013, 1, 1, 0, 0, 0, Rational(1,10), -3600), tti.to_timestamp)
      assert_equal_with_offset(Timestamp.create(2012, 1, 1, 0, 0, 0, Rational(1,10), 3600), tti.from_timestamp)
    end
  end

  def test_transitions_up_to_utc_to_not_greater_than_utc_from
    time_types_test do |h|
      tti = TestTimezoneInfo.new('Test/Zone', nil, nil, nil)
      tz = DataTimezone.new(tti)

      to = h.time(2013,1,1,0,0,0,0,0)
      from = h.time(2013,1,1,0,0,0,0,0)

      error = assert_raises(ArgumentError) { tz.transitions_up_to(to, from) }
      assert_equal('to must be greater than from', error.message)
    end
  end

  def test_transitions_up_to_unspecified_from
    time_types_test(:unspecified_offset) do |h|
      tti = TestTimezoneInfo.new('Test/Zone', nil, nil, nil)
      tz = DataTimezone.new(tti)

      to = h.time(2013, 1, 1, 0, 0, 0, Rational(1,10), 0)
      from = h.time(2012, 1, 1, 0, 0, 0, Rational(1,10))

      error = assert_raises(ArgumentError) { tz.transitions_up_to(to, from) }
      assert_equal('from must have a specified utc_offset', error.message)
    end
  end

  def test_transitions_up_to_unspecified_to
    time_types_test(:unspecified_offset) do |h|
      tti = TestTimezoneInfo.new('Test/Zone', nil, nil, nil)
      tz = DataTimezone.new(tti)

      to = h.time(2013, 1, 1, 0, 0, 0, Rational(1,10))

      error = assert_raises(ArgumentError) { tz.transitions_up_to(to) }
      assert_equal('to must have a specified utc_offset', error.message)
    end
  end

  def test_transitions_up_to_nil_from
    # Don't need actual TimezoneTransition instances. DataTimezone isn't
    # supposed to do anything with them apart from return them.
    transitions = [Object.new, Object.new]
    tti = TestTimezoneInfo.new('Test/Zone', nil, nil, transitions)
    tz = DataTimezone.new(tti)

    to = Time.utc(2013, 1, 1, 0, 0, Rational(1,10))
    assert_same(transitions, tz.transitions_up_to(to))
    assert_equal_with_offset(Timestamp.new(to.to_i, Rational(1,10), :utc), tti.to_timestamp)
    assert_nil(tti.from_timestamp)
  end

  def test_transitions_up_to_nil_to
    tti = TestTimezoneInfo.new('Test/Zone', nil, nil, nil)
    tz = DataTimezone.new(tti)

    error = assert_raises(ArgumentError) { tz.transitions_up_to(nil) }
    assert_equal('to must be specified', error.message)
  end

  def test_transitions_up_to_unsupported_to
    tti = TestTimezoneInfo.new('Test/Zone', nil, nil, nil)
    tz = DataTimezone.new(tti)
    to = Time.utc(2013, 1, 1, 0, 0, 0).to_i

    error = assert_raises(ArgumentError) { tz.transitions_up_to(to) }
    assert_match(Regexp.new("\\b#{Regexp.escape(to.class.name)}\\b"), error.message)
  end

  def test_transitions_up_to_unsupported_from
    tti = TestTimezoneInfo.new('Test/Zone', nil, nil, nil)
    tz = DataTimezone.new(tti)
    to = Time.utc(2013, 1, 1, 0, 0, 0)
    from = Time.utc(2012, 1, 1, 0, 0, 0).to_i

    error = assert_raises(ArgumentError) { tz.transitions_up_to(to, from) }
    assert_match(Regexp.new("\\b#{Regexp.escape(from.class.name)}\\b"), error.message)
  end

  def test_canonical_identifier
    tz = DataTimezone.new(TestTimezoneInfo.new('Test/Zone', nil, [], []))
    assert_equal('Test/Zone', tz.canonical_identifier)
  end

  def test_canonical_zone
    tz = DataTimezone.new(TestTimezoneInfo.new('Test/Zone', nil, [], []))
    assert_same(tz, tz.canonical_zone)
  end

  def test_inspect
    tz = DataTimezone.new(TestTimezoneInfo.new('Test/Zone', nil, [], []))
    assert_equal('#<TZInfo::DataTimezone: Test/Zone>', tz.inspect)
  end

  # Builds a DataTimezone backed by real transitions so the in-order cursor
  # exercises TransitionsDataTimezoneInfo#periods_for_in_order. The offsets
  # mimic America/New_York around its 2000 spring-forward/fall-back.
  def create_sequential_timezone
    eastern_standard = TimezoneOffset.new(-18000,    0, 'TESTEST')
    eastern_daylight = TimezoneOffset.new(-18000, 3600, 'TESTEDT')

    t1 = TimezoneTransition.new(eastern_daylight, eastern_standard, Time.utc(2000, 4, 2, 7, 0, 0).to_i)
    t2 = TimezoneTransition.new(eastern_standard, eastern_daylight, Time.utc(2000,10,29, 6, 0, 0).to_i)

    info = DataSources::TransitionsDataTimezoneInfo.new('Test/New_York', [t1, t2])
    DataTimezone.new(info)
  end

  def test_to_local_in_order_converts_all_time_types
    tz = create_sequential_timezone

    time_types_test(:utc) do |h|
      inputs = [
        h.time(2000, 4, 2, 6,59,59, 0, :utc),
        h.time(2000, 4, 2, 7, 0, 0, Rational(1,3), :utc),
        h.time(2000,10,29, 5,59,59, Rational(1,3), :utc),
        h.time(2000,10,29, 6, 0, 0, Rational(2,3), :utc)
      ]

      results = tz.to_local_in_order(inputs).to_a

      inputs.each_with_index do |input, index|
        expected = tz.to_local(input)
        assert_equal(expected, results[index])
        assert_equal(expected.class, results[index].class)
        assert_kind_of(h.output_time(2000,1,1,0,0,0,0,:utc).class, results[index])
      end

      # Sub-second precision is retained on the converted result.
      expected_subsecond = results[1].kind_of?(Timestamp) ? results[1].sub_second : results[1].subsec
      assert_equal(Rational(1,3), expected_subsecond)
      assert_equal(Rational(2,3), results[3].kind_of?(Timestamp) ? results[3].sub_second : results[3].subsec)
    end
  end

  def test_to_local_in_order_straddling_transition
    tz = create_sequential_timezone

    transition_utc = Time.utc(2000, 4, 2, 7, 0, 0)
    inputs = [
      transition_utc - 1,
      transition_utc,
      transition_utc + Rational(1,1000)
    ]

    results = tz.to_local_in_order(inputs).to_a

    assert_equal(-18000, results[0].utc_offset)
    assert_equal(-14400, results[1].utc_offset)
    assert_equal(-14400, results[2].utc_offset)
    assert_equal(tz.to_local(inputs[2]), results[2])

    # The record in the transition's second is the local time of the new
    # period (03:00 local), not 01:59:59.999 of the old period.
    assert_equal([2000, 4, 2, 3, 0, 0], [results[1].year, results[1].month, results[1].day, results[1].hour, results[1].min, results[1].sec])
  end

  def test_to_local_in_order_allows_equal_timestamps
    tz = create_sequential_timezone
    input = Time.utc(2000, 7, 1, 12, 0, 0)
    results = tz.to_local_in_order([input, input, input]).to_a

    assert_equal(3, results.length)
    assert(results.all? {|local| local == tz.to_local(input) })
  end

  def test_to_local_in_order_reports_index_on_unsorted_input
    tz = create_sequential_timezone
    inputs = [
      Time.utc(2000, 1, 1),
      Time.utc(2000, 2, 1),
      Time.utc(2000, 2, 1),
      Time.utc(2000, 1, 1),
      Time.utc(2000, 3, 1)
    ]

    error = assert_raises(ChronologicalOrderError) { tz.to_local_in_order(inputs).to_a }
    assert_kind_of(ArgumentError, error)
    assert_equal(3, error.index)
    assert_match(/\bindex\b/, error.message)
  end

  def test_to_local_in_order_does_not_sort_or_eagerly_consume
    tz = create_sequential_timezone

    pulled = []
    source = Enumerator.new do |yielder|
      [Time.utc(2000,1,1), Time.utc(2000,2,1), Time.utc(2000,3,1)].each do |t|
        pulled << t
        yielder.yield(t)
      end
    end

    enumerator = tz.to_local_in_order(source)
    assert_equal([], pulled)

    first = enumerator.next
    assert_equal(1, pulled.length)
    assert_equal(tz.to_local(Time.utc(2000,1,1)), first)

    assert_equal(tz.to_local(Time.utc(2000,2,1)), enumerator.next)
    assert_equal(2, pulled.length)
    assert_equal(tz.to_local(Time.utc(2000,3,1)), enumerator.next)
    assert_equal(3, pulled.length)

    # An out of order input is reported lazily while pulling; it is not
    # discovered up front (the preceding entries are still yielded first).
    unsorted = [Time.utc(2000,2,1), Time.utc(2000,1,1)]
    lazy_error_enumerator = tz.to_local_in_order(unsorted)
    assert_equal(tz.to_local(Time.utc(2000,2,1)), lazy_error_enumerator.next)
    error = assert_raises(ChronologicalOrderError) { lazy_error_enumerator.next }
    assert_equal(1, error.index)
  end

  def test_to_local_in_order_with_block_returns_nil
    tz = create_sequential_timezone
    yielded = []
    result = tz.to_local_in_order([Time.utc(2000,1,1), Time.utc(2000,7,1)]) {|local| yielded << local }
    assert_nil(result)
    assert_equal(2, yielded.length)
  end

  def test_to_local_in_order_can_stop_early_without_consuming_input
    tz = create_sequential_timezone

    # An infinite stream: conversion must stop pulling as soon as the
    # consumer stops (the sequence is never read to completion).
    stream = Enumerator.new do |yielder|
      value = Time.utc(2000, 1, 1).to_i
      loop do
        yielder.yield(Time.at(value).utc)
        value += 86400
      end
    end

    pulled = 0
    counting_stream = Enumerator.new do |yielder|
      stream.each do |time|
        pulled += 1
        yielder.yield(time)
      end
    end

    results = []
    tz.to_local_in_order(counting_stream).each do |local|
      results << local
      break if results.length == 5
    end

    assert_equal(5, results.length)
    assert_equal(5, pulled)
  end

  # A TransitionsDataTimezoneInfo that records calls to the binary search
  # used by period_for. The in-order conversion must never trigger it.
  class CountingTransitionsInfo < DataSources::TransitionsDataTimezoneInfo
    attr_reader :binary_search_calls

    def initialize(*args)
      super
      @binary_search_calls = 0
    end

    protected

    def find_minimum_transition
      @binary_search_calls += 1
      super
    end
  end

  def test_to_local_in_order_never_performs_independent_binary_searches
    standard = TimezoneOffset.new(-18000,    0, 'TESTEST')
    daylight = TimezoneOffset.new(-18000, 3600, 'TESTEDT')
    t1 = TimezoneTransition.new(daylight, standard, Time.utc(2000, 4, 2, 7, 0, 0).to_i)
    t2 = TimezoneTransition.new(standard, daylight, Time.utc(2000,10,29, 6, 0, 0).to_i)
    info = CountingTransitionsInfo.new('Test/New_York', [t1, t2])
    tz = DataTimezone.new(info)

    inputs = [
      Time.utc(1999,12,1),
      Time.utc(2000, 4, 2, 7, 0, 0),
      Time.utc(2000, 4, 2, 7, 0, 0),
      Time.utc(2000, 7, 1),
      Time.utc(2000,10,29, 6, 0, 0),
      Time.utc(2001, 1, 1)
    ]

    results = tz.to_local_in_order(inputs).to_a

    assert_equal(0, info.binary_search_calls)
    inputs.each_with_index do |input, index|
      assert_equal(tz.to_local(input), results[index])
    end
    # The independent comparisons above use period_for and would search, but
    # the batch conversion itself still performed none.
    assert_operator info.binary_search_calls, :>, 0
  end

  def test_utc_to_local_in_order_ignores_offsets
    tz = create_sequential_timezone
    inputs = [Time.new(2000, 4, 2, 6, 0, 0, 3600), Time.new(2000, 7, 1, 12, 0, 0, 3600)]
    results = tz.utc_to_local_in_order(inputs).to_a

    assert_equal([tz.utc_to_local(inputs[0]), tz.utc_to_local(inputs[1])], results)
    assert_equal(-18000, results[0].utc_offset)
    assert_equal(-14400, results[1].utc_offset)
  end

  def test_to_local_in_order_nil
    tz = create_sequential_timezone
    error = assert_raises(ArgumentError) { tz.to_local_in_order(nil) }
    assert_match(/\btimes\b/, error.message)
  end

  def test_to_local_in_order_constant_offset_zone
    standard = TimezoneOffset.new(0, 0, 'TESTUTC')
    info = DataSources::ConstantOffsetDataTimezoneInfo.new('Test/UTC', standard)
    tz = DataTimezone.new(info)

    inputs = [Time.utc(2000,1,1), Time.utc(2000,1,1), Time.utc(2050,1,1)]
    results = tz.to_local_in_order(inputs).to_a

    assert_equal(inputs, results)
    assert_equal(0, results.first.utc_offset)
  end

  def test_to_local_in_order_unspecified_offset
    tz = create_sequential_timezone
    timestamp = Timestamp.new(Time.utc(2000, 1, 1).to_i, 0, nil)
    error = assert_raises(ArgumentError) { tz.to_local_in_order([timestamp]).to_a }
    assert_match(/\butc_offset\b/, error.message)
  end
end
