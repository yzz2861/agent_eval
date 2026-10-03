# encoding: UTF-8
# frozen_string_literal: true

require_relative '../test_utils'

module DataSources
  class TCTransitionsDataTimezoneInfo < Minitest::Test
    include TZInfo
    include TZInfo::DataSources

    # A {TransitionsDataTimezoneInfo} that records how many times the
    # sequential cursor examines a transition (`advance_checks`) and how many
    # times an independent binary-search lookup is performed
    # (`binary_search_count` via {#period_for} or the private
    # find_minimum_transition used by it).
    class CountingTransitionsDataTimezoneInfo < TransitionsDataTimezoneInfo
      attr_reader :period_for_count
      attr_reader :advance_checks
      attr_reader :binary_search_count

      def initialize(identifier, transitions)
        super
        @period_for_count = 0
        @advance_checks = 0
        @binary_search_count = 0
      end

      def period_for(timestamp)
        @period_for_count += 1
        super
      end

      def transition_precedes_timestamp?(transition, timestamp_value, sub_second)
        @advance_checks += 1
        super
      end

      private

      def find_minimum_transition
        @binary_search_count += 1
        super
      end
    end

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

    def create_sweep_transitions
      o1 = TimezoneOffset.new(-17900, 0,    'TESTLMT')
      o2 = TimezoneOffset.new(-18000, 3600, 'TESTD')
      o3 = TimezoneOffset.new(-18000, 0,    'TESTS')
      o4 = TimezoneOffset.new(-21600, 3600, 'TESTD')

      t1 = TimezoneTransition.new(o2, o1, Time.utc(2000, 4,1,1,0,0).to_i)
      t2 = TimezoneTransition.new(o3, o2, Time.utc(2000,10,1,1,0,0).to_i)
      t3 = TimezoneTransition.new(o2, o3, Time.utc(2001, 3,1,1,0,0).to_i)
      t4 = TimezoneTransition.new(o4, o2, Time.utc(2001, 4,1,1,0,0).to_i)
      t5 = TimezoneTransition.new(o3, o4, Time.utc(2001,10,1,1,0,0).to_i)

      [t1, t2, t3, t4, t5]
    end

    def test_period_for_all
      t1, t2, t3, t4, t5 = create_sweep_transitions
      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1, t2, t3, t4, t5])

      timestamps = [
        Time.utc(1999, 1, 1, 0, 0, 0),             # before first transition
        Time.utc(2000, 4, 1, 0,59,59),
        Time.utc(2000, 4, 1, 1, 0, 0),             # on t1 (new period)
        Time.utc(2000, 4, 1, 1, 0, 0),             # duplicate
        Time.utc(2000, 10,1, 0,59,59, Rational(999,1000)),
        Time.utc(2000, 10,1, 1, 0, 0),             # on t2 (new period)
        Time.utc(2001, 4, 1, 0,59,59),             # skips over t3
        Time.utc(2001, 4, 1, 1, 0, 0),             # on t4 (new period)
        Time.utc(2050, 1, 1, 0, 0, 0)              # after last transition
      ].map {|t| Timestamp.for(t) }

      expected = timestamps.map {|t| i.period_for(t) }

      assert_kind_of(Enumerator, i.period_for_all([]))
      assert_nil(i.period_for_all(timestamps) {})

      actual = i.period_for_all(timestamps).to_a
      assert_equal(expected, actual)
      assert_equal([
        TransitionsTimezonePeriod.new(nil, t1),
        TransitionsTimezonePeriod.new(nil, t1),
        TransitionsTimezonePeriod.new(t1, t2),
        TransitionsTimezonePeriod.new(t1, t2),
        TransitionsTimezonePeriod.new(t1, t2),
        TransitionsTimezonePeriod.new(t2, t3),
        TransitionsTimezonePeriod.new(t3, t4),
        TransitionsTimezonePeriod.new(t4, t5),
        TransitionsTimezonePeriod.new(t5, nil)
      ], actual)
    end

    def test_period_for_all_sub_second_within_transition_second
      t1, = create_sweep_transitions
      i = TransitionsDataTimezoneInfo.new('Test/Zone', [t1])

      # period_for treats both the exact transition second and later
      # sub-seconds within that same second as belonging to the new period.
      # The sequential sweep must match, including when both are processed
      # together in sorted order.
      exact = Timestamp.utc(t1.timestamp_value)
      within = Timestamp.utc(t1.timestamp_value, Rational(1,1000))

      assert_equal(TransitionsTimezonePeriod.new(t1, nil), i.period_for(exact))

      assert_equal(TransitionsTimezonePeriod.new(t1, nil), i.period_for_all([exact]).first)
      assert_equal(i.period_for(within), i.period_for_all([within]).first)
      assert_equal(TransitionsTimezonePeriod.new(t1, nil), i.period_for_all([within]).first)

      # The exact second sorts before a later sub-second of the same second.
      # Both resolve to the new period that starts on the transition.
      result = i.period_for_all([exact, within]).to_a
      assert_equal(TransitionsTimezonePeriod.new(t1, nil), result[0])
      assert_equal(TransitionsTimezonePeriod.new(t1, nil), result[1])

      # A sub-second immediately before the transition second still belongs
      # to the preceding period and, when followed by the exact second, the
      # cursor must land in the new period.
      just_before = Timestamp.utc(t1.timestamp_value - 1, Rational(999,1000))
      assert_equal(TransitionsTimezonePeriod.new(nil, t1), i.period_for_all([just_before]).first)
      assert_equal([TransitionsTimezonePeriod.new(nil, t1), TransitionsTimezonePeriod.new(t1, nil)],
        i.period_for_all([just_before, exact]).to_a)
    end

    def test_period_for_all_yields_lazily_and_does_not_consume_enumerator
      transitions = create_sweep_transitions
      i = TransitionsDataTimezoneInfo.new('Test/Zone', transitions)

      pulled = []
      source = Enumerator.new do |yielder|
        [Time.utc(2000,1,1), Time.utc(2000,6,1), Time.utc(2001,1,1)].each do |t|
          pulled << t
          yielder.yield Timestamp.for(t)
        end
      end

      enum = i.period_for_all(source)
      assert_equal([], pulled)

      first = enum.next
      assert_equal(1, pulled.length)
      assert_equal(TransitionsTimezonePeriod.new(nil, transitions[0]), first)

      second = enum.next
      assert_equal(2, pulled.length)
      assert_equal(TransitionsTimezonePeriod.new(transitions[0], transitions[1]), second)
    end

    def test_period_for_all_does_not_use_independent_period_lookups
      raw = create_sweep_transitions
      transitions = raw
      i = CountingTransitionsDataTimezoneInfo.new('Test/Zone', transitions)

      timestamps = [
        Time.utc(2000, 1, 1),
        Time.utc(2000, 4, 1, 1, 0, 0),
        Time.utc(2000, 4, 1, 1, 0, 0),
        Time.utc(2000, 6, 1),
        Time.utc(2000, 10,1, 1, 0, 0),
        Time.utc(2001, 12,1)
      ].map {|t| Timestamp.for(t) }

      results = i.period_for_all(timestamps).to_a

      # One period per timestamp, including the duplicate.
      assert_equal(6, results.length)

      # No independent period_for lookup and no binary search must happen.
      assert_equal(0, i.period_for_count)
      assert_equal(0, i.binary_search_count)

      # The cursor advances forward only. It crosses at most the 5
      # transitions plus one final boundary check, regardless of the 6 input
      # timestamps or the duplicate. An independent binary search for each
      # timestamp would instead perform 6 * ceil(log2(6)) = 18 comparisons
      # and would still perform work for the duplicate.
      assert_operator(i.advance_checks, :<=, transitions.length + 1)
    end

    def test_period_for_all_lookup_count_is_linear_and_caches_periods
      # Five transitions over a wide range, and many records that all fall
      # within a small number of periods (including repeated and adjacent
      # timestamps). The number of cursor advances must depend only on the
      # number of transitions crossed, not the number of records.
      o1 = TimezoneOffset.new(0, 0, 'TESTLMT')
      o2 = TimezoneOffset.new(0, 3600, 'TESTD')
      transitions = (1..5).map do |n|
        TimezoneTransition.new(o2, o1, n * 1_000_000)
      end
      i = CountingTransitionsDataTimezoneInfo.new('Test/Zone', transitions)

      record_count = 10_000
      timestamps = Array.new(record_count) {|n| Timestamp.utc(100 + n) }

      results = i.period_for_all(timestamps).to_a

      assert_equal(record_count, results.length)
      assert_equal(0, i.period_for_count)
      assert_equal(0, i.binary_search_count)

      # 10,000 records cross no transition at all (all before the first at
      # 1,000,000). The cursor performs a single boundary comparison and then
      # reuses the period for every subsequent record.
      assert_equal(1, i.advance_checks)

      # Repeated identical timestamps do not advance the cursor at all beyond
      # the first record.
      i2 = CountingTransitionsDataTimezoneInfo.new('Test/Zone', transitions)
      repeated = [Timestamp.utc(50)] * 1000
      i2.period_for_all(repeated).to_a
      assert_equal(1, i2.advance_checks)
      assert_equal(0, i2.binary_search_count)
    end

    def test_period_for_all_out_of_order
      transitions = create_sweep_transitions
      i = TransitionsDataTimezoneInfo.new('Test/Zone', transitions)

      ordered = [Time.utc(2000,1,1), Time.utc(2000,6,1), Time.utc(2000,3,1)].map {|t| Timestamp.for(t) }

      error = assert_raises(OutOfOrderTimestampError) { i.period_for_all(ordered).to_a }
      assert_equal(2, error.index)
      assert_kind_of(ArgumentError, error)

      # Equal timestamps are allowed, including with differing sub-seconds in
      # non-decreasing order.
      timestamps = [
        Timestamp.utc(transitions[0].timestamp_value),
        Timestamp.utc(transitions[0].timestamp_value),
        Timestamp.utc(transitions[0].timestamp_value, Rational(1,2))
      ]
      assert_equal(3, i.period_for_all(timestamps).to_a.length)

      # A decrease in sub_second alone is also out of order.
      error = assert_raises(OutOfOrderTimestampError) do
        i.period_for_all([
          Timestamp.utc(transitions[0].timestamp_value, Rational(2,3)),
          Timestamp.utc(transitions[0].timestamp_value, Rational(1,3))
        ]).to_a
      end
      assert_equal(1, error.index)
    end

    def test_period_for_all_out_of_order_raised_lazily_with_index
      transitions = create_sweep_transitions
      i = TransitionsDataTimezoneInfo.new('Test/Zone', transitions)

      yielded = []
      source = Enumerator.new do |yielder|
        yielder.yield Timestamp.for(Time.utc(2000,1,1))
        yielder.yield Timestamp.for(Time.utc(2001,1,1))
        yielder.yield Timestamp.for(Time.utc(2000,6,1))
      end

      error = assert_raises(OutOfOrderTimestampError) do
        i.period_for_all(source) {|period| yielded << period }
      end

      assert_equal(2, error.index)
      assert_equal(2, yielded.length)
    end

    def test_period_for_all_validates_arguments
      i = create_basic_info

      error = assert_raises(ArgumentError) { i.period_for_all(nil).to_a }
      assert_equal('timestamps must be specified', error.message)

      error = assert_raises(ArgumentError) { i.period_for_all([nil]).to_a }
      assert_equal('timestamp must be specified', error.message)

      error = assert_raises(ArgumentError) { i.period_for_all([Timestamp.for(Time.utc(2005,1,1), :ignore)]).to_a }
      assert_equal('timestamp must have a specified utc_offset', error.message)
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
