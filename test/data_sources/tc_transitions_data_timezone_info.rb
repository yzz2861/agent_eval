# encoding: UTF-8
# frozen_string_literal: true

require_relative '../test_utils'

module DataSources
  class TCTransitionsDataTimezoneInfo < Minitest::Test
    include TZInfo
    include TZInfo::DataSources

    def test_initialize_transitions
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 3600, 'TESTD')
      o3 = TimezoneOffset.new(-18000,    0, 'TESTS')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000, 4,1,1,0,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2000,10,1,1,0,0).to_i)
      t3 = TimezoneTransition.new(o2, o3, Time.utc(2001, 3,1,1,0,0).to_i)

      transitions = [t1, t2, t3]
      identifier = 'Test/Zone'.dup
      refute(identifier.frozen?)

      i = TransitionsDataTimezoneInfo.new(identifier, transitions)

      assert_same(identifier, i.identifier)
      assert_same(transitions, i.transitions)
      assert_equal(true, i.identifier.frozen?)
      assert_equal(true, i.transitions.frozen?)
    end

    def test_initialize_empty_transitions
      error = assert_raises(ArgumentError) { TransitionsDataTimezoneInfo.new('Test/Zone', []) }
      assert_match(/\btransitions\b/, error.message)
    end

    def test_initialize_nil_identifier
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000,    0, 'TESTS')
      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000,10,1,1,0,0).to_i)
      transitions = [t1]

      error = assert_raises(ArgumentError) { TransitionsDataTimezoneInfo.new(nil, transitions) }
      assert_match(/\bidentifier\b/, error.message)
    end

    def test_initialize_nil_transitions
      error = assert_raises(ArgumentError) { TransitionsDataTimezoneInfo.new('Test/Zone', nil) }
      assert_match(/\btransitions\b/, error.message)
    end

    def test_period_for
      o1 = TimezoneOffset.new(-17900, 0,    'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 3600, 'TESTD')
      o3 = TimezoneOffset.new(-18000, 0,    'TESTS')
      o4 = TimezoneOffset.new(-21600, 3600, 'TESTD')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000, 4,1,1,0,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2000,10,1,1,0,0).to_i)
      t3 = TimezoneTransition.new(o2, o3, Time.utc(2001, 3,1,1,0,0).to_i)
      t4 = TimezoneTransition.new(o4, o2, Time.utc(2001, 4,1,1,0,0).to_i)
      t5 = TimezoneTransition.new(o3, o4, Time.utc(2001,10,1,1,0,0).to_i)
      t6 = TimezoneTransition.new(o3, o3, Time.utc(2002,10,1,1,0,0).to_i)
      t7 = TimezoneTransition.new(o2, o3, Time.utc(2003, 2,1,1,0,0).to_i)
      t8 = TimezoneTransition.new(o3, o2, Time.utc(2003, 3,1,1,0,0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1,t2,t3,t4,t5,t6,t7,t8])

      assert_equal(TransitionsTimezonePeriod.new(nil, t1), i.period_for(Timestamp.for(Time.utc(1960, 1,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(nil, t1), i.period_for(Timestamp.for(Time.utc(1999,12,1,0, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(nil, t1), i.period_for(Timestamp.for(Time.utc(2000, 4,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t1, t2),  i.period_for(Timestamp.for(Time.utc(2000, 4,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t1, t2),  i.period_for(Timestamp.for(Time.utc(2000,10,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t2, t3),  i.period_for(Timestamp.for(Time.utc(2000,10,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t2, t3),  i.period_for(Timestamp.for(Time.utc(2001, 3,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t3, t4),  i.period_for(Timestamp.for(Time.utc(2001, 3,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t3, t4),  i.period_for(Timestamp.for(Time.utc(2001, 4,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t4, t5),  i.period_for(Timestamp.for(Time.utc(2001, 4,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t4, t5),  i.period_for(Timestamp.for(Time.utc(2001,10,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t5, t6),  i.period_for(Timestamp.for(Time.utc(2001,10,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t5, t6),  i.period_for(Timestamp.for(Time.utc(2002, 2,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t5, t6),  i.period_for(Timestamp.for(Time.utc(2002,10,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t6, t7),  i.period_for(Timestamp.for(Time.utc(2002,10,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t6, t7),  i.period_for(Timestamp.for(Time.utc(2003, 2,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t7, t8),  i.period_for(Timestamp.for(Time.utc(2003, 2,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t7, t8),  i.period_for(Timestamp.for(Time.utc(2003, 3,1,0,59,59))))
      assert_equal(TransitionsTimezonePeriod.new(t8, nil), i.period_for(Timestamp.for(Time.utc(2003, 3,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t8, nil), i.period_for(Timestamp.for(Time.utc(2004, 1,1,1, 0, 0))))
      assert_equal(TransitionsTimezonePeriod.new(t8, nil), i.period_for(Timestamp.for(Time.utc(2050, 1,1,1, 0, 0))))
    end

    def test_period_for_timestamp_with_zero_utc_offset
      o1 = TimezoneOffset.new(-17900, 0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 0, 'TEST')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000,7,1,0,0,0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1])

      assert_equal(TransitionsTimezonePeriod.new(t1, nil), i.period_for(Timestamp.for(Time.new(2000,7,1,0,0,0,0))))
    end

    def test_period_for_timestamp_with_non_zero_utc_offset
      o1 = TimezoneOffset.new(-17900, 0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 0, 'TEST')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000,7,1,0,0,0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1])

      assert_equal(TransitionsTimezonePeriod.new(t1, nil), i.period_for(Timestamp.for(Time.new(2000,6,30,23, 0, 0,-3600))))
      assert_equal(TransitionsTimezonePeriod.new(nil, t1), i.period_for(Timestamp.for(Time.new(2000,7, 1, 0,59,59, 3600))))
    end

    def create_basic_info
      o1 = TimezoneOffset.new(-17900, 0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 0, 'TEST')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000,7,1,0,0,0).to_i)

      TransitionsDataTimezoneInfo.new('Test/Zone', [t1])
    end

    def test_period_for_timestamp_with_unspecified_offset
      i = create_basic_info
      error = assert_raises(ArgumentError) { i.period_for(Timestamp.for(Time.utc(2005,1,1,0,0,0), :ignore)) }
      assert_equal('timestamp must have a specified utc_offset', error.message)
    end

    def test_period_for_nil
      i = create_basic_info
      error = assert_raises(ArgumentError) { i.period_for(nil) }
      assert_equal('timestamp must be specified', error.message)
    end

    # A TimezoneTransition that counts how many times its timestamp_value is
    # examined while scanning for the applicable period. The transition is
    # built directly (rather than delegating) so that comparison operators
    # cannot be accidentally proxied.
    class CountingTransition < TimezoneTransition
      attr_reader :examinations

      def initialize(transition)
        super(transition.offset, transition.previous_offset, transition.timestamp_value)
        @examinations = 0
      end

      def timestamp_value
        @examinations += 1
        super
      end
    end

    # A TransitionsDataTimezoneInfo that records every call to the binary
    # search used by period_for. The in-order cursor must never trigger it.
    class CountingInfo < TransitionsDataTimezoneInfo
      attr_reader :find_minimum_transition_calls

      def initialize(identifier, transitions)
        super(identifier, transitions)
        @find_minimum_transition_calls = 0
      end

      protected

      def find_minimum_transition
        @find_minimum_transition_calls += 1
        super
      end
    end

    def create_ordered_info(transitions = nil)
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 3600, 'TESTD')
      o3 = TimezoneOffset.new(-18000,    0, 'TESTS')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000, 4,1,1,0,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2000,10,1,1,0,0).to_i)
      t3 = TimezoneTransition.new(o2, o3, Time.utc(2001, 3,1,1,0,0).to_i)
      t4 = TimezoneTransition.new(o3, o2, Time.utc(2001,10,1,1,0,0).to_i)

      all = [t1, t2, t3, t4]
      chosen = transitions || all
      TransitionsDataTimezoneInfo.new('Test/Zone', chosen)
    end

    def test_periods_for_in_order_matches_period_for
      info = create_ordered_info

      utc_times = [
        Time.utc(1999, 1, 1, 0, 0, 0),
        Time.utc(2000, 4, 1, 0,59,59),
        Time.utc(2000, 4, 1, 1, 0, 0, Rational(1,2)),
        Time.utc(2000,10, 1, 0,59,59),
        Time.utc(2000,10, 1, 1, 0, 0),
        Time.utc(2001, 3, 1, 1, 0, 0),
        Time.utc(2001,10, 1, 1, 0, 0),
        Time.utc(2050, 1, 1, 0, 0, 0)
      ]

      timestamps = utc_times.map {|t| Timestamp.for(t) }
      expected = timestamps.map {|t| info.period_for(t) }

      assert_equal(expected, info.periods_for_in_order(timestamps).to_a)
    end

    def test_periods_for_in_order_allows_equal_timestamps
      info = create_ordered_info

      transition_time = Time.utc(2000, 4, 1, 1, 0, 0).to_i
      timestamps = [
        Timestamp.utc(transition_time - 1, 0),
        Timestamp.utc(transition_time - 1, Rational(1,2)),
        Timestamp.utc(transition_time),
        Timestamp.utc(transition_time, 0),
        Timestamp.utc(transition_time, Rational(9,10)),
        Timestamp.utc(transition_time, Rational(9,10))
      ]

      expected = timestamps.map {|t| info.period_for(t) }
      assert_equal(expected, info.periods_for_in_order(timestamps).to_a)
    end

    def test_periods_for_in_order_record_on_transition_second_uses_new_period
      # A record in the same whole second as a transition belongs to the new
      # period, even with a non-zero sub-second. This is the same rule that
      # period_for applies (transitions only occur on whole seconds).
      info = create_ordered_info

      transition_time = Time.utc(2000,10,1,1,0,0).to_i

      just_before = Timestamp.utc(transition_time - 1, Rational(999,1000))
      on_transition = Timestamp.utc(transition_time, Rational(1,1000))

      assert_equal(info.period_for(just_before), info.periods_for_in_order([just_before]).first)
      assert_equal(info.period_for(on_transition), info.periods_for_in_order([on_transition]).first)
      refute_equal(info.period_for(just_before), info.period_for(on_transition))

      assert_equal(
        [info.period_for(just_before), info.period_for(on_transition)],
        info.periods_for_in_order([just_before, on_transition]).to_a)
    end

    def test_periods_for_in_order_never_uses_binary_search
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 3600, 'TESTD')
      o3 = TimezoneOffset.new(-18000,    0, 'TESTS')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000, 4,1,1,0,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2000,10,1,1,0,0).to_i)
      t3 = TimezoneTransition.new(o2, o3, Time.utc(2001, 3,1,1,0,0).to_i)
      t4 = TimezoneTransition.new(o3, o2, Time.utc(2001,10,1,1,0,0).to_i)

      counted = [t1, t2, t3, t4].map {|t| CountingTransition.new(t) }
      info = CountingInfo.new('Test/Zone', counted)

      timestamps = [
        Time.utc(1999, 1,1),
        Time.utc(2000, 4,1,1,0,0),
        Time.utc(2000, 4,1,1,0,0),
        Time.utc(2000,10,1,1,0,0),
        Time.utc(2001, 3,1,1,0,0),
        Time.utc(2001,10,1,1,0,0),
        Time.utc(2050, 1,1)
      ].map {|t| Timestamp.for(t) }

      results = info.periods_for_in_order(timestamps).to_a

      # The binary search that period_for relies on is never used.
      assert_equal(0, info.find_minimum_transition_calls)
      examinations = counted.map(&:examinations)

      # Every period agrees with an independent lookup.
      plain_info = TransitionsDataTimezoneInfo.new('Test/Zone', [t1,t2,t3,t4])
      timestamps.each_with_index do |timestamp, index|
        expected = plain_info.period_for(timestamp)
        actual = results[index]
        assert_equal(expected.base_utc_offset, actual.base_utc_offset)
        assert_equal(expected.std_offset, actual.std_offset)
        assert_equal(expected.observed_utc_offset, actual.observed_utc_offset)
        assert_equal(expected.start_transition && expected.start_transition.timestamp_value,
                     actual.start_transition && actual.start_transition.timestamp_value)
        assert_equal(expected.end_transition && expected.end_transition.timestamp_value,
                     actual.end_transition && actual.end_transition.timestamp_value)
      end

      # The cursor only ever moves forward. Each transition is advanced over
      # at most once in total and each input performs one boundary check,
      # so the number of examinations is at most the number of transitions
      # plus the number of inputs. Independent binary searches would cost
      # O(inputs * log(transitions)).
      # Each transition is advanced over at most once and each input performs
      # one boundary check, so the number of examinations is at most the
      # number of transitions plus the number of inputs. Independent binary
      # searches would cost O(inputs * log(transitions)).
      assert_operator examinations.sum, :<=, counted.length + timestamps.length
      assert_operator examinations.last, :>, 1
    end

    def test_periods_for_in_order_duplicates_do_not_advance_cursor
      info_unwrapped = create_ordered_info
      counted = info_unwrapped.transitions.map {|t| CountingTransition.new(t) }
      info = TransitionsDataTimezoneInfo.new('Test/Zone', counted)

      value = Time.utc(2000, 6, 1).to_i
      timestamps = Array.new(100) { Timestamp.utc(value) }

      results = info.periods_for_in_order(timestamps).to_a

      assert_equal(100, results.length)
      expected_period = info_unwrapped.period_for(Timestamp.utc(value))

      # The cursor advances past t1 on the first input (examined once), then
      # examines t2 once per input to confirm the cursor has not moved. t3
      # and t4 (later transitions) are never touched; no backwards scans
      # occur. These counts are captured before any independent period_for
      # lookups below.
      examinations = counted.map(&:examinations)
      assert_equal([1, 100, 0, 0], examinations)

      assert(results.all? {|period| period == expected_period })
    end

    def test_periods_for_in_order_empty
      info = create_ordered_info
      assert_equal([], info.periods_for_in_order([]).to_a)
    end

    def test_periods_for_in_order_consumes_lazily
      info = create_ordered_info
      pulled = 0

      source = Enumerator.new do |yielder|
        10.times do |i|
          pulled += 1
          yielder.yield(Timestamp.utc(Time.utc(2000 + i, 1, 1).to_i))
        end
      end

      enumerator = info.periods_for_in_order(source)
      assert_equal(0, pulled)

      assert_kind_of(TimezonePeriod, enumerator.next)
      assert_equal(1, pulled)

      enumerator.next
      assert_equal(2, pulled)
      enumerator.rewind

      info.periods_for_in_order(source).first(3)
      assert_equal(5, pulled)
    end

    def test_periods_for_in_order_with_block
      info = create_ordered_info
      timestamps = [Timestamp.for(Time.utc(2000, 6, 1)), Timestamp.for(Time.utc(2001, 6, 1))]
      yielded = []
      result = info.periods_for_in_order(timestamps) {|period| yielded << period }
      assert_nil(result)
      assert_equal(timestamps.map {|t| info.period_for(t) }, yielded)
    end

    def test_periods_for_in_order_unspecified_offset
      info = create_ordered_info
      timestamps = [Timestamp.for(Time.utc(2000,1,1), :ignore)]
      error = assert_raises(ArgumentError) { info.periods_for_in_order(timestamps).to_a }
      assert_equal('timestamp must have a specified utc_offset', error.message)
    end

    def test_periods_for_in_order_nil
      info = create_ordered_info
      error = assert_raises(ArgumentError) { info.periods_for_in_order([nil]).to_a }
      assert_equal('timestamp must be specified', error.message)
    end

    def test_periods_for_local
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 3600, 'TESTD')
      o3 = TimezoneOffset.new(-18000,    0, 'TESTS')
      o4 = TimezoneOffset.new(-21600, 3600, 'TESTD')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000, 4,2,1,0,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2000,10,2,1,0,0).to_i)
      t3 = TimezoneTransition.new(o2, o3, Time.utc(2001, 3,2,1,0,0).to_i)
      t4 = TimezoneTransition.new(o4, o2, Time.utc(2001, 4,2,1,0,0).to_i)
      t5 = TimezoneTransition.new(o3, o4, Time.utc(2001,10,2,1,0,0).to_i)
      t6 = TimezoneTransition.new(o3, o3, Time.utc(2002,10,2,1,0,0).to_i)
      t7 = TimezoneTransition.new(o2, o3, Time.utc(2003, 2,2,1,0,0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1,t2,t3,t4,t5,t6,t7])

      assert_equal([TransitionsTimezonePeriod.new(nil, t1)], i.periods_for_local(Timestamp.for(Time.utc(1960, 1, 1, 1, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(nil, t1)], i.periods_for_local(Timestamp.for(Time.utc(1999,12, 1, 0, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(nil, t1)], i.periods_for_local(Timestamp.for(Time.utc(2000, 1, 1,10, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(nil, t1)], i.periods_for_local(Timestamp.for(Time.utc(2000, 4, 1,20, 1,39), :ignore)))
      assert_equal([],                            i.periods_for_local(Timestamp.for(Time.utc(2000, 4, 1,20, 1,40), :ignore)))
      assert_equal([],                            i.periods_for_local(Timestamp.for(Time.utc(2000, 4, 1,20,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t1,  t2)], i.periods_for_local(Timestamp.for(Time.utc(2000, 4, 1,21, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t1,  t2)], i.periods_for_local(Timestamp.for(Time.utc(2000,10, 1,19,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t1,  t2),
                    TransitionsTimezonePeriod.new(t2,  t3)], i.periods_for_local(Timestamp.for(Time.utc(2000,10, 1,20, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t1,  t2),
                    TransitionsTimezonePeriod.new(t2,  t3)], i.periods_for_local(Timestamp.for(Time.utc(2000,10, 1,20,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t2,  t3)], i.periods_for_local(Timestamp.for(Time.utc(2000,10, 1,21, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t2,  t3)], i.periods_for_local(Timestamp.for(Time.utc(2001, 3, 1,19,59,59), :ignore)))
      assert_equal([],                            i.periods_for_local(Timestamp.for(Time.utc(2001, 3, 1,20, 0, 0), :ignore)))
      assert_equal([],                            i.periods_for_local(Timestamp.for(Time.utc(2001, 3, 1,20,30, 0), :ignore)))
      assert_equal([],                            i.periods_for_local(Timestamp.for(Time.utc(2001, 3, 1,20,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t3,  t4)], i.periods_for_local(Timestamp.for(Time.utc(2001, 3, 1,21, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t3,  t4)], i.periods_for_local(Timestamp.for(Time.utc(2001, 4, 1,19,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t3,  t4),
                    TransitionsTimezonePeriod.new(t4,  t5)], i.periods_for_local(Timestamp.for(Time.utc(2001, 4, 1,20, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t3,  t4),
                    TransitionsTimezonePeriod.new(t4,  t5)], i.periods_for_local(Timestamp.for(Time.utc(2001, 4, 1,20,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t4,  t5)], i.periods_for_local(Timestamp.for(Time.utc(2001, 4, 1,21, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t4,  t5)], i.periods_for_local(Timestamp.for(Time.utc(2001,10, 1,19,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t5,  t6)], i.periods_for_local(Timestamp.for(Time.utc(2001,10, 1,20, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t5,  t6)], i.periods_for_local(Timestamp.for(Time.utc(2002, 2, 1,20, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t5,  t6)], i.periods_for_local(Timestamp.for(Time.utc(2002,10, 1,19,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t6,  t7)], i.periods_for_local(Timestamp.for(Time.utc(2002,10, 1,20, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t6,  t7)], i.periods_for_local(Timestamp.for(Time.utc(2003, 2, 1,19,59,59), :ignore)))
      assert_equal([],                            i.periods_for_local(Timestamp.for(Time.utc(2003, 2, 1,20, 0, 0), :ignore)))
      assert_equal([],                            i.periods_for_local(Timestamp.for(Time.utc(2003, 2, 1,20,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t7, nil)], i.periods_for_local(Timestamp.for(Time.utc(2003, 2, 1,21, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t7, nil)], i.periods_for_local(Timestamp.for(Time.utc(2004, 2, 1,20, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t7, nil)], i.periods_for_local(Timestamp.for(Time.utc(2040, 2, 1,20, 0, 0), :ignore)))
    end

    def test_periods_for_local_warsaw
      o1 = TimezoneOffset.new(5040,    0, 'LMT')
      o2 = TimezoneOffset.new(5040,    0, 'WMT')
      o3 = TimezoneOffset.new(3600,    0, 'CET')
      o4 = TimezoneOffset.new(3600, 3600, 'CEST')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(1879,12,31,22,36,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(1915, 8, 4,22,36,0).to_i)
      t3 = TimezoneTransition.new(o4, o3, Time.utc(1916, 4,30,22, 0,0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Europe/Warsaw', [t1,t2,t3])

      assert_equal([TransitionsTimezonePeriod.new(t1, t2),
                    TransitionsTimezonePeriod.new(t2, t3)], i.periods_for_local(Timestamp.for(Time.utc(1915,8,4,23,40,0), :ignore)))
    end

    def test_periods_for_local_single_transition
      o1 = TimezoneOffset.new(-3600, 0, 'TESTD')
      o2 = TimezoneOffset.new(-3600, 0, 'TESTS')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000,7,1,0,0,0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1])

      assert_equal([TransitionsTimezonePeriod.new(nil, t1)], i.periods_for_local(Timestamp.for(Time.utc(2000,6,30,22,59,59), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t1, nil)], i.periods_for_local(Timestamp.for(Time.utc(2000,6,30,23, 0, 0), :ignore)))
      assert_equal([TransitionsTimezonePeriod.new(t1, nil)], i.periods_for_local(Timestamp.for(Time.utc(2000,7, 1, 0, 0, 0), :ignore)))
    end

    def test_periods_for_local_timestamp_with_specified_offset
      i = create_basic_info
      error = assert_raises(ArgumentError) { i.periods_for_local(Timestamp.for(Time.utc(2005,1,1,0,0,0))) }
      assert_equal('local_timestamp must have an unspecified utc_offset', error.message)
    end

    def test_periods_for_local_nil
      i = create_basic_info
      error = assert_raises(ArgumentError) { i.periods_for_local(nil) }
      assert_equal('local_timestamp must be specified', error.message)
    end

    def test_transitions_up_to
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 3600, 'TESTD')
      o3 = TimezoneOffset.new(-18000,    0, 'TESTS')
      o4 = TimezoneOffset.new(-21600, 3600, 'TESTD')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2010, 4,1,1,0,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2010,10,1,1,0,0).to_i)
      t3 = TimezoneTransition.new(o2, o3, Time.utc(2011, 3,1,1,0,0).to_i)
      t4 = TimezoneTransition.new(o4, o2, Time.utc(2011, 4,1,1,0,0).to_i)
      t5 = TimezoneTransition.new(o3, o4, Time.utc(2011,10,1,1,0,0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1,t2,t3,t4,t5])

      assert_equal([],               i.transitions_up_to(Timestamp.for(Time.utc(2010, 4,1,1,0,0))))
      assert_equal([],               i.transitions_up_to(Timestamp.for(Time.utc(2010, 4,1,1,0,0)), Timestamp.for(Time.utc(2000, 1,1,0,0,0))))
      assert_equal([t1],             i.transitions_up_to(Timestamp.for(Time.utc(2010, 4,1,1,0,1))))
      assert_equal([t1],             i.transitions_up_to(Timestamp.for(Time.utc(2010, 4,1,1,0,1)), Timestamp.for(Time.utc(2000, 1,1,0,0,0))))
      assert_equal([t2,t3,t4],       i.transitions_up_to(Timestamp.for(Time.utc(2011, 4,1,1,0,1)), Timestamp.for(Time.utc(2010,10,1,1,0,0))))
      assert_equal([t2,t3,t4],       i.transitions_up_to(Timestamp.for(Time.utc(2011,10,1,1,0,0)), Timestamp.for(Time.utc(2010, 4,1,1,0,1))))
      assert_equal([t3],             i.transitions_up_to(Timestamp.for(Time.utc(2011, 4,1,1,0,0)), Timestamp.for(Time.utc(2010,10,1,1,0,1))))
      assert_equal([],               i.transitions_up_to(Timestamp.for(Time.utc(2011, 3,1,1,0,0)), Timestamp.for(Time.utc(2010,10,1,1,0,1))))
      assert_equal([t1,t2,t3,t4],    i.transitions_up_to(Timestamp.for(Time.utc(2011,10,1,1,0,0))))
      assert_equal([t1,t2,t3,t4,t5], i.transitions_up_to(Timestamp.for(Time.utc(2011,10,1,1,0,1))))
      assert_equal([t1,t2,t3,t4,t5], i.transitions_up_to(Timestamp.for(Time.utc(2011,10,1,1,0,0,1))))
      assert_equal([t1,t2,t3,t4,t5], i.transitions_up_to(Timestamp.for(Time.utc(2011,10,1,1,0,1)), Timestamp.for(Time.utc(2010, 4,1,1,0,0))))
      assert_equal([t2,t3,t4,t5],    i.transitions_up_to(Timestamp.for(Time.utc(2011,10,1,1,0,1)), Timestamp.for(Time.utc(2010, 4,1,1,0,1))))
      assert_equal([t2,t3,t4,t5],    i.transitions_up_to(Timestamp.for(Time.utc(2011,10,1,1,0,1)), Timestamp.for(Time.utc(2010, 4,1,1,0,0,1))))
      assert_equal([t5],             i.transitions_up_to(Timestamp.for(Time.utc(2015, 1,1,0,0,0)), Timestamp.for(Time.utc(2011,10,1,1,0,0))))
      assert_equal([],               i.transitions_up_to(Timestamp.for(Time.utc(2015, 1,1,0,0,0)), Timestamp.for(Time.utc(2011,10,1,1,0,1))))
    end

    def test_transitions_up_to_timestamp_with_zero_utc_offset
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000,    0, 'TESTS')
      o3 = TimezoneOffset.new(-18000, 3600, 'TESTD')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2009,12,31,23,59,59).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2010, 7, 1, 0, 0, 0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1,t2])

      assert_equal([t1,t2], i.transitions_up_to(Timestamp.for(Time.new(2010,7,1,0,0,1,0))))
      assert_equal([t1,t2], i.transitions_up_to(Timestamp.for(Time.new(2011,1,1,0,0,0,0)), Timestamp.for(Time.new(2009,12,31,23,59,59,0))))
    end

    def test_transitions_up_to_timestamp_with_non_zero_utc_offset
      o1 = TimezoneOffset.new(-17900,    0, 'TESTLMT')
      o2 = TimezoneOffset.new(-18000,    0, 'TESTS')
      o3 = TimezoneOffset.new(-18000, 3600, 'TESTD')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2009,12,31,23,59,59).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2010, 7, 1, 0, 0, 0).to_i)

      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1,t2])

      assert_equal([t1,t2], i.transitions_up_to(Timestamp.for(Time.new(2010,6,30,23,0,1,-3600))))
      assert_equal([t1],    i.transitions_up_to(Timestamp.for(Time.new(2010,7, 1, 1,0,0, 3600))))
      assert_equal([t1,t2], i.transitions_up_to(Timestamp.for(Time.new(2011,1,1,0,0,0,0)), Timestamp.for(Time.new(2010, 1, 1, 0,59,59, 3600))))
      assert_equal([t2],    i.transitions_up_to(Timestamp.for(Time.new(2011,1,1,0,0,0,0)), Timestamp.for(Time.new(2009,12,31,23, 0, 0,-3600))))
    end

    def test_transitions_up_to_to_not_greater_than_from
      i = create_basic_info

      to = Timestamp.for(Time.utc(2012,8,1,0,0,0))
      from = Timestamp.for(Time.utc(2013,8,1,0,0,0))

      error = assert_raises(ArgumentError) { i.transitions_up_to(to, from) }
      assert_equal('to_timestamp must be greater than from_timestamp', error.message)
    end

    def test_transitions_up_to_to_not_greater_than_from_subsecond
      i = create_basic_info

      to = Timestamp.for(Time.utc(2012,8,1,0,0,0))
      from = Timestamp.for(Time.utc(2012,8,1,0,0,0,1))

      error = assert_raises(ArgumentError) { i.transitions_up_to(to, from) }
      assert_equal('to_timestamp must be greater than from_timestamp', error.message)
    end

    def test_transitions_up_to_to_timestamp_with_unspecified_offset
      i = create_basic_info

      to = Timestamp.for(Time.utc(2015,1,1,0,0,0), :ignore)

      error = assert_raises(ArgumentError) { i.transitions_up_to(to) }
      assert_equal('to_timestamp must have a specified utc_offset', error.message)
    end

    def test_transitions_up_to_from_timestamp_with_unspecified_offset
      i = create_basic_info

      to = Timestamp.for(Time.utc(2015,1,1,0,0,0))
      from = Timestamp.for(Time.utc(2014,1,1,0,0,0), :ignore)

      error = assert_raises(ArgumentError) { i.transitions_up_to(to, from) }
      assert_equal('from_timestamp must have a specified utc_offset', error.message)
    end

    def test_transitions_up_to_to_timestamp_nil
      i = create_basic_info
      error = assert_raises(ArgumentError) { i.transitions_up_to(nil) }
      assert_equal('to_timestamp must be specified', error.message)
    end

    def test_inspect
      i = create_basic_info
      assert_equal('#<TZInfo::DataSources::TransitionsDataTimezoneInfo: Test/Zone>', i.inspect)
    end
  end
end
