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

  def create_batch_timezone
    o1 = TimezoneOffset.new(0, 0, 'GMT')
    o2 = TimezoneOffset.new(0, 3600, 'BST')
    o3 = TimezoneOffset.new(0, 0, 'GMT')

    t1 = TimezoneTransition.new(o2, o1, Time.utc(2000, 4, 1, 1).to_i)
    t2 = TimezoneTransition.new(o3, o2, Time.utc(2000, 10, 1, 1).to_i)

    info = DataSources::TransitionsDataTimezoneInfo.new('Test/Zone', [t1, t2])
    DataTimezone.new(info)
  end

  def test_utc_to_local_all
    tz = create_batch_timezone

    time_types_test do |h|
      times = [
        h.time(2000, 3, 1, 0, 0, 0, 0, :utc),
        h.time(2000, 4, 1, 0,59,59, 0, :utc),
        h.time(2000, 4, 1, 1, 0, 0, 0, :utc),
        h.time(2000, 6, 1, 0, 0, 0, Rational(567,1000), :utc),
        h.time(2000, 10,1, 1, 0, 0, 0, :utc),
        h.time(2001, 1, 1, 0, 0, 0, Rational(1,3), :utc)
      ]

      results = tz.utc_to_local_all(times).to_a
      expected = times.map {|t| tz.utc_to_local(t) }

      results.each_with_index do |result, n|
        assert_equal_with_offset_and_timezone_offset(expected[n], result)
        assert_equal(expected[n].class, result.class)
      end

      precision_result = results[3]
      precision = precision_result.is_a?(Timestamp) ? precision_result.sub_second : (precision_result.respond_to?(:subsec) ? precision_result.subsec : precision_result.sec_fraction)
      assert_equal(Rational(567,1000), precision)

      assert_equal(Rational(1,3), results[5].is_a?(Timestamp) ? results[5].sub_second : (results[5].respond_to?(:subsec) ? results[5].subsec : results[5].sec_fraction))
    end
  end

  def test_utc_to_local_all_timestamp_input
    tz = create_batch_timezone

    results = tz.utc_to_local_all([
      Timestamp.utc(Time.utc(2000,6,1).to_i, Rational(123456789,1000000000)),
      Timestamp.utc(Time.utc(2001,1,1).to_i, Rational(7,8))
    ]).to_a

    results.each {|r| assert_kind_of(TimestampWithOffset, r) }
    assert_equal(Rational(123456789,1000000000), results[0].sub_second)
    assert_equal(Rational(7,8), results[1].sub_second)
    assert_equal(3600, results[0].utc_offset)
    assert_equal(0, results[1].utc_offset)
  end

  def test_utc_to_local_all_duplicates_and_transition_record
    tz = create_batch_timezone

    # The exact transition UTC instant belongs to the new period. Duplicate
    # timestamps are allowed and return identical results.
    transition = Time.utc(2000, 4, 1, 1).utc
    results = tz.utc_to_local_all([transition, transition, transition]).to_a

    assert_equal(3, results.length)
    results.each do |result|
      assert_equal_with_offset_and_timezone_offset(tz.utc_to_local(transition), result)
      assert_equal(3600, result.utc_offset)
    end
  end

  def test_utc_to_local_all_block_form
    tz = create_batch_timezone
    collected = []
    returned = tz.utc_to_local_all([Time.utc(2000,6,1).utc, Time.utc(2001,1,1).utc]) do |local|
      collected << local
    end

    assert_nil(returned)
    assert_equal(2, collected.length)
    assert_equal_with_offset_and_timezone_offset(tz.utc_to_local(Time.utc(2000,6,1).utc), collected[0])
    assert_equal_with_offset_and_timezone_offset(tz.utc_to_local(Time.utc(2001,1,1).utc), collected[1])
  end

  def test_utc_to_local_all_returns_enumerator
    tz = create_batch_timezone
    enum = tz.utc_to_local_all([Time.utc(2000,6,1).utc])
    assert_kind_of(Enumerator, enum)
  end

  def test_utc_to_local_all_lazy_does_not_consume_enumerator
    tz = create_batch_timezone

    pulled = []
    source = Enumerator.new do |yielder|
      [Time.utc(2000,3,1).utc, Time.utc(2000,6,1).utc, Time.utc(2001,1,1).utc].each do |t|
        pulled << t
        yielder.yield t
      end
    end

    enum = tz.utc_to_local_all(source)
    assert_equal(0, pulled.length)

    first = enum.next
    assert_equal(1, pulled.length)
    assert_equal_with_offset_and_timezone_offset(tz.utc_to_local(Time.utc(2000,3,1).utc), first)

    enum.next
    assert_equal(2, pulled.length)
  end

  def test_utc_to_local_all_out_of_order_raises_with_index
    tz = create_batch_timezone

    error = assert_raises(DataSources::OutOfOrderTimestampError) do
      tz.utc_to_local_all([
        Time.utc(2000,6,1).utc,
        Time.utc(2001,1,1).utc,
        Time.utc(2000,5,1).utc
      ]).to_a
    end

    assert_equal(2, error.index)
    assert_kind_of(ArgumentError, error)
  end

  def test_utc_to_local_all_out_of_order_raised_lazily
    tz = create_batch_timezone

    enum = tz.utc_to_local_all(Enumerator.new do |yielder|
      yielder.yield Time.utc(2000,3,1).utc
      yielder.yield Time.utc(2000,5,1).utc
      yielder.yield Time.utc(2000,1,1).utc
    end)

    enum.next
    enum.next
    error = assert_raises(DataSources::OutOfOrderTimestampError) { enum.next }
    assert_equal(2, error.index)
  end

  def test_utc_to_local_all_nil
    tz = create_batch_timezone
    error = assert_raises(ArgumentError) { tz.utc_to_local_all(nil).to_a }
    assert_match(/\butc_times\b/, error.message)
  end

  def test_utc_to_local_all_nil_element
    tz = create_batch_timezone
    error = assert_raises(ArgumentError) { tz.utc_to_local_all([nil]).to_a }
    assert_equal('value must be specified', error.message)
  end

  def test_utc_to_local_all_unsupported_element
    tz = create_batch_timezone
    t = Time.utc(2000,6,1).to_i
    error = assert_raises(ArgumentError) { tz.utc_to_local_all([t]).to_a }
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
end
