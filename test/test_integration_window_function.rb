require "helper"

class IntegrationWindowFunctionTestCase < SQLite3::TestCase
  # Moving weighted average over a sliding frame. Tracks callback counts on
  # the class so tests can prove that sqlite maintains the window
  # incrementally (step/inverse) instead of recomputing every frame.
  class WeightedAverageHandler
    class << self
      attr_accessor :steps, :inverses, :values, :finalizes

      def name
        "wavg"
      end

      def arity
        2
      end

      def reset!
        self.steps = self.inverses = self.values = self.finalizes = 0
      end
    end
    reset!

    def initialize
      @weighted_sum = 0.0
      @weight_sum = 0
    end

    def step(value, weight)
      self.class.steps += 1
      @weighted_sum += value * weight
      @weight_sum += weight
    end

    def inverse(value, weight)
      self.class.inverses += 1
      @weighted_sum -= value * weight
      @weight_sum -= weight
    end

    def value
      self.class.values += 1
      @weight_sum.zero? ? nil : @weighted_sum / @weight_sum
    end

    def finalize
      self.class.finalizes += 1
      @weight_sum.zero? ? nil : @weighted_sum / @weight_sum
    end
  end

  # Multiset statistic: number of distinct values inside the frame. Without a
  # working inverse the counts of rows leaving the frame would never be
  # decremented, so this only computes the right thing incrementally.
  class DistinctCountHandler
    def self.name
      "dcount"
    end

    def self.arity
      1
    end

    def initialize
      @counts = Hash.new(0)
    end

    def step(value)
      @counts[value] += 1
    end

    def inverse(value)
      @counts[value] -= 1
      @counts.delete(value) if @counts[value].zero?
    end

    def value
      @counts.size
    end

    def finalize
      value
    end
  end

  class CustomException < RuntimeError
  end

  def setup
    @db = SQLite3::Database.new(":memory:")
    @db.execute("create table metrics ( grp text, seq integer, v integer, w integer )")
    @rows = (1..12).map do |i|
      grp = (i % 3).zero? ? "b" : "a"
      v = ((i * 37) % 11) - 5
      w = ((i * 13) % 4) + 1
      [grp, i, v, w]
    end
    stmt = @db.prepare("insert into metrics values ( ?, ?, ?, ? )")
    @rows.each { |row| stmt.execute(*row) }
    stmt.close
    WeightedAverageHandler.reset!
  end

  def teardown
    @db.close
  end

  def frame_rows(rows, i, preceding, following)
    lo = (preceding == :unbounded) ? 0 : [i - preceding, 0].max
    hi = (following == :unbounded) ? rows.length - 1 : [i + following, rows.length - 1].min
    return [] if lo > hi

    rows[lo..hi]
  end

  def reference_wavg(rows, preceding, following)
    rows.each_index.map do |i|
      frame = frame_rows(rows, i, preceding, following)
      weight_sum = frame.sum { |r| r[3] }
      weight_sum.zero? ? nil : frame.sum { |r| r[2] * r[3] }.to_f / weight_sum
    end
  end

  def reference_dcount(rows, preceding, following)
    rows.each_index.map do |i|
      frame_rows(rows, i, preceding, following).map { |r| r[2] }.uniq.size
    end
  end

  def assert_float_column(expected, actual, message = nil)
    assert_equal expected.length, actual.length
    expected.zip(actual).each_with_index do |(exp, got), i|
      if exp.nil?
        assert_nil got, "#{message} row #{i}: expected nil, got #{got.inspect}"
      else
        assert_in_delta exp, got, 1e-9, "#{message} row #{i}"
      end
    end
  end

  def test_sliding_frame_is_maintained_incrementally
    @db.create_window_function_handler(WeightedAverageHandler)

    results = @db.execute(<<~SQL)
      select seq, wavg(v, w) over (order by seq rows between 2 preceding and current row)
      from metrics order by seq
    SQL

    assert_float_column reference_wavg(@rows, 2, 0), results.map { |r| r[1] }, "wavg"

    # every row enters the frame exactly once ...
    assert_equal 12, WeightedAverageHandler.steps
    # ... and the 9 rows that scroll out of the 3-row frame are removed via
    # inverse instead of recomputing the frame from scratch
    assert_equal 9, WeightedAverageHandler.inverses
    # one xValue per output row, one xFinal for the single partition
    assert_equal 12, WeightedAverageHandler.values
    assert_equal 1, WeightedAverageHandler.finalizes
  end

  def test_multiple_invocations_partitions_and_frames_in_one_query
    @db.create_window_function_handler(WeightedAverageHandler)
    @db.create_window_function_handler(DistinctCountHandler)

    results = @db.execute(<<~SQL)
      select seq,
        wavg(v, w) over (partition by grp order by seq rows between 1 preceding and current row),
        wavg(v, w) over (order by seq rows between 3 preceding and 2 preceding),
        dcount(v) over (partition by grp order by seq rows between unbounded preceding and current row)
      from metrics order by seq
    SQL

    group_a = @rows.select { |r| r[0] == "a" }
    group_b = @rows.select { |r| r[0] == "b" }
    wavg_a = reference_wavg(group_a, 1, 0)
    wavg_b = reference_wavg(group_b, 1, 0)
    dcount_a = reference_dcount(group_a, :unbounded, 0)
    dcount_b = reference_dcount(group_b, :unbounded, 0)

    expected_wavg_by_seq = {}
    group_a.each_with_index { |row, i| expected_wavg_by_seq[row[1]] = wavg_a[i] }
    group_b.each_with_index { |row, i| expected_wavg_by_seq[row[1]] = wavg_b[i] }

    expected_dcount_by_seq = {}
    group_a.each_with_index { |row, i| expected_dcount_by_seq[row[1]] = dcount_a[i] }
    group_b.each_with_index { |row, i| expected_dcount_by_seq[row[1]] = dcount_b[i] }

    assert_float_column reference_wavg(@rows, 3, -2), results.map { |r| r[2] }, "offset frame wavg"
    results.each do |seq, partitioned_wavg, _, partitioned_dcount|
      exp = expected_wavg_by_seq[seq]
      if exp.nil?
        assert_nil partitioned_wavg, "seq #{seq}"
      else
        assert_in_delta exp, partitioned_wavg, 1e-9, "seq #{seq}"
      end
      assert_equal expected_dcount_by_seq[seq], partitioned_dcount, "seq #{seq}"
    end
  end

  def test_value_reads_without_destroying_the_aggregator
    @db.create_window_function_handler(WeightedAverageHandler)

    # duplicate ordering keys create peer groups, so sqlite reads the value of
    # several output rows from the same frame without any step/inverse in
    # between; the aggregator must survive every read
    results = @db.execute(<<~SQL)
      select seq, wavg(v, w) over (
        order by seq % 3 groups between 1 preceding and 1 following
      ) from metrics order by seq
    SQL

    keys = @rows.map { |r| r[1] % 3 }
    sorted_keys = keys.uniq.sort
    expected = @rows.each_with_index.map do |_, i|
      gi = sorted_keys.index(keys[i])
      lo = [gi - 1, 0].max
      hi = [gi + 1, sorted_keys.length - 1].min
      frame = @rows.select { |r| sorted_keys[lo..hi].include?(r[1] % 3) }
      frame.sum { |r| r[2] * r[3] }.to_f / frame.sum { |r| r[3] }
    end

    assert_float_column expected, results.map { |r| r[1] }, "groups frame wavg"
    # sqlite may cache the value across rows of a peer group, but it must
    # evaluate the frame at least once per peer group
    assert_operator WeightedAverageHandler.values, :>=, 3
    assert_equal 12, WeightedAverageHandler.steps
    assert_equal 4, WeightedAverageHandler.inverses
    assert_equal 1, WeightedAverageHandler.finalizes
  end

  def test_multiset_statistic_with_inverse
    @db.create_window_function_handler(DistinctCountHandler)

    results = @db.execute(<<~SQL)
      select seq, dcount(v) over (order by seq rows between 3 preceding and current row)
      from metrics order by seq
    SQL

    assert_equal reference_dcount(@rows, 3, 0), results.map { |r| r[1] }
  end

  def test_create_window_function_with_block_dsl
    @db.create_window_function("running_sum", 1) do
      step { |v| @sum = (@sum || 0) + v }
      inverse { |v| @sum -= v }
      value { @sum }
      finalize { value }
    end

    results = @db.execute(<<~SQL)
      select seq, running_sum(v) over (order by seq rows between 1 preceding and current row)
      from metrics order by seq
    SQL

    expected = @rows.each_index.map do |i|
      frame_rows(@rows, i, 1, 0).sum { |r| r[2] }
    end
    assert_equal expected, results.map { |r| r[1] }
  end

  def test_create_window_function_requires_a_block
    assert_raise(ArgumentError) { @db.create_window_function("nope", 1) }
  end

  def test_create_window_function_requires_all_callbacks
    error = assert_raise(ArgumentError) do
      @db.create_window_function("incomplete", 1) do
        step { |v| }
        value { 0 }
      end
    end
    assert_match(/inverse/, error.message)
    assert_match(/finalize/, error.message)
  end

  def test_create_window_function_with_invalid_arity
    assert_raise(ArgumentError) do
      @db.create_window_function("toomany", 1000) do
        step { |v| }
        inverse { |v| }
        value { 0 }
        finalize { 0 }
      end
    end
  end

  def test_window_function_with_exception_in_step_cleans_up
    handler = Class.new do
      def self.name
        "raiser"
      end

      def self.arity
        1
      end

      def step(v)
        raise CustomException, "bogus window handler" if v == 999
      end

      def inverse(v)
      end

      def value
        0
      end

      def finalize
        0
      end
    end
    @db.create_window_function_handler(handler)
    @db.execute("insert into metrics values ( 'a', 13, 999, 1 )")

    assert_raise(CustomException) do
      @db.execute("select raiser(v) over (order by seq) from metrics")
    end

    GC.start(full_mark: true, immediate_sweep: true)
    assert_equal 0, ObjectSpace.each_object(handler).count

    # the connection is still usable afterwards
    @db.create_window_function_handler(WeightedAverageHandler)
    assert_equal 13, @db.get_first_value("select count(*) from metrics")
    results = @db.execute("select wavg(v, w) over (order by seq) from metrics where v <> 999")
    assert_equal 12, results.length
  end

  def test_window_function_instances_released_when_statement_closed_early
    @db.create_window_function_handler(WeightedAverageHandler)

    stmt = @db.prepare("select wavg(v, w) over (order by seq) from metrics")
    2.times { stmt.step }
    assert_equal 0, WeightedAverageHandler.finalizes

    stmt.close
    # sqlite finalizes the in-flight aggregate context when the statement is
    # destroyed, which must release the handler instance
    assert_equal 1, WeightedAverageHandler.finalizes

    GC.start(full_mark: true, immediate_sweep: true)
    assert_equal 0, ObjectSpace.each_object(WeightedAverageHandler).count
  end

  def test_window_function_instances_are_released_after_each_query
    @db.create_window_function_handler(WeightedAverageHandler)

    5.times do
      @db.execute("select wavg(v, w) over (partition by grp order by seq) from metrics")
    end
    assert_equal 10, WeightedAverageHandler.finalizes # 2 partitions per query

    GC.start(full_mark: true, immediate_sweep: true)
    assert_equal 0, ObjectSpace.each_object(WeightedAverageHandler).count
  end
end
