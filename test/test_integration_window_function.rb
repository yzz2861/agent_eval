require "helper"

class IntegrationWindowFunctionTestCase < SQLite3::TestCase
  class CustomException < StandardError; end

  # Recency-weighted moving average over the window frame. The newest row in
  # the frame gets the highest weight. This cannot be expressed as a plain
  # aggregate and only works incrementally because +inverse+ undoes +step+:
  #
  #   step(x):    existing rows keep their position, the new row is appended
  #               with weight (count + 1)
  #   inverse(x): the oldest row (weight 1) leaves, every remaining row
  #               shifts one position towards the front, so the weighted sum
  #               decreases by the current total
  class WeightedMovingAverage
    def self.name
      "wma"
    end

    def self.arity
      1
    end

    def initialize
      @count = 0
      @total = 0.0    # sum of the values in the frame
      @weighted = 0.0 # sum of position * value, oldest row has position 1
    end

    def step(x)
      @weighted += (@count + 1) * x
      @total += x
      @count += 1
    end

    def inverse(x)
      @weighted -= @total
      @total -= x
      @count -= 1
    end

    def value
      @count.zero? ? nil : @weighted / (@count * (@count + 1) / 2.0)
    end

    def finalize
      value
    end
  end

  # Multiset statistics: number of distinct values inside the frame.
  # Order-independent, so it is also well defined for RANGE frames with
  # peer rows.
  class DistinctCount
    def self.name
      "dcount"
    end

    def self.arity
      1
    end

    def initialize
      @seen = Hash.new(0)
    end

    def step(x)
      @seen[x] += 1
    end

    def inverse(x)
      @seen[x] -= 1
      @seen.delete(x) if @seen[x].zero?
    end

    def value
      @seen.length
    end

    def finalize
      value
    end
  end

  # WMA instrumented with lifecycle counters.
  class TrackingWma < WeightedMovingAverage
    class << self
      attr_accessor :created, :finalized, :value_calls
    end

    def self.name
      "twma"
    end

    def self.reset!
      self.created = 0
      self.finalized = 0
      self.value_calls = 0
    end

    def initialize
      self.class.created += 1
      super
    end

    def value
      self.class.value_calls += 1
      super
    end

    def finalize
      self.class.finalized += 1
      super
    end
  end

  def setup
    @db = SQLite3::Database.new(":memory:")
    @db.create_window_function_handler(WeightedMovingAverage)
    @db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, g TEXT, v REAL)")
    rng = Random.new(42)
    @rows = (1..24).map do |id|
      [id, %w[a b c][(id - 1) % 3], (rng.rand * 20 - 10).round(3)]
    end
    @rows.each do |row|
      @db.execute("INSERT INTO t (id, g, v) VALUES (?, ?, ?)", row)
    end
  end

  def teardown
    @db.close
  end

  # Reference implementation: recomputes the weighted moving average from
  # scratch for every window frame, without any incremental state.
  def reference_wma(values, preceding, following)
    values.each_index.map do |i|
      from = [0, i - preceding].max
      to = i + following
      frame = (from <= to && from < values.length) ? values[from..to] : []
      if frame.empty?
        nil
      else
        n = frame.length
        frame.each_with_index.sum { |v, j| (j + 1) * v } / (n * (n + 1) / 2.0)
      end
    end
  end

  def partitioned_values
    @rows.group_by { |_, g, _| g }.to_h do |g, rows|
      [g, rows.sort_by(&:first).map { |_, _, v| v }]
    end
  end

  # Number of handler instances the C extension currently considers
  # in-flight. Must return to zero once a statement is done, whatever the
  # reason it ended.
  def live_window_instance_count
    @db.send(:aggregate_instance_count)
  end

  def assert_float_array_in_delta(expected, actual, delta = 1e-9)
    assert_equal expected.length, actual.length
    expected.zip(actual) do |e, a|
      if e.nil?
        assert_nil a
      else
        assert_in_delta e, a, delta
      end
    end
  end

  def test_sliding_frames_match_reference
    [[0, 0], [2, 0], [1, 1], [0, 2], [3, 1], [5, 0]].each do |preceding, following|
      sql = "SELECT g, id, wma(v) OVER ("
      sql += "PARTITION BY g ORDER BY id "
      sql += "ROWS BETWEEN #{preceding} PRECEDING AND #{following} FOLLOWING"
      sql += ") FROM t ORDER BY g, id"
      result = @db.execute(sql)

      expected_by_group = partitioned_values.transform_values do |values|
        reference_wma(values, preceding, following)
      end
      expected = result.map do |g, id, _|
        expected_by_group[g][(id - 1) / 3]
      end
      assert_float_array_in_delta expected, result.map { |row| row[2] }
    end
    assert_equal 0, live_window_instance_count
  end

  def test_multiple_windows_in_one_query_have_independent_state
    sql = "SELECT g, id,"
    sql += " wma(v) OVER (PARTITION BY g ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW),"
    sql += " wma(v) OVER (PARTITION BY g ORDER BY id ROWS BETWEEN CURRENT ROW AND 2 FOLLOWING),"
    sql += " wma(v) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING)"
    sql += " FROM t ORDER BY g, id"
    result = @db.execute(sql)

    by_group = partitioned_values
    expected_a = by_group.transform_values { |values| reference_wma(values, 2, 0) }
    expected_b = by_group.transform_values { |values| reference_wma(values, 0, 2) }
    expected_c = reference_wma(@rows.map { |_, _, v| v }, 1, 1)

    result.each do |(g, id, wa, wb, wc)|
      i = (id - 1) / 3
      assert_in_delta expected_a[g][i], wa, 1e-9
      assert_in_delta expected_b[g][i], wb, 1e-9
      # global window follows id order, not the output order
      assert_in_delta expected_c[id - 1], wc, 1e-9
    end
    assert_equal 0, live_window_instance_count
  end

  def test_multiset_distinct_count_with_range_frame_and_peers
    @db.create_window_function_handler(DistinctCount)
    @db.execute("CREATE TABLE m (id INTEGER PRIMARY KEY, v REAL)")
    data = [nil, 1.0, 1.0, 2.0, 2.0, 3.0, 5.0, 8.0, 8.0, 8.0, 13.0, 21.0]
    data.each_with_index do |v, i|
      @db.execute("INSERT INTO m (id, v) VALUES (?, ?)", [i + 1, v])
    end

    sql = "SELECT id, v, dcount(v) OVER ("
    sql += "ORDER BY v RANGE BETWEEN 2 PRECEDING AND CURRENT ROW"
    sql += ") FROM m ORDER BY v, id"
    result = @db.execute(sql)

    sorted = data.each_with_index.map { |v, i| [i + 1, v] }.sort_by { |id, v| [v.nil? ? 0 : 1, v || 0, id] }
    expected = sorted.map do |_, v|
      frame = sorted.select do |_, w|
        v.nil? ? w.nil? : (!w.nil? && w >= v - 2 && w <= v)
      end
      frame.map { |_, w| w }.uniq.length
    end

    assert_equal expected, result.map { |row| row[2] }
    assert_equal 0, live_window_instance_count
  end

  def test_empty_frame_yields_nil
    values = partitioned_values["a"]
    result = @db.execute(
      "SELECT id, wma(v) OVER (ORDER BY id ROWS BETWEEN 3 PRECEDING AND 2 PRECEDING) " \
      "FROM t WHERE g = 'a' ORDER BY id"
    )
    assert_float_array_in_delta reference_wma(values, 3, -2), result.map { |row| row[1] }
  end

  def test_value_does_not_destroy_state_and_finalize_runs_once_per_partition
    @db.create_window_function_handler(TrackingWma)
    TrackingWma.reset!

    result = @db.execute(
      "SELECT g, id, twma(v) OVER (" \
      "PARTITION BY g ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW" \
      ") FROM t ORDER BY g, id"
    )

    # one handler instance per partition, finalized exactly once
    assert_equal 3, TrackingWma.created
    assert_equal 3, TrackingWma.finalized
    # value was read once per emitted row without destroying the instance;
    # had it destroyed the state, the results would not match the reference
    assert_operator TrackingWma.value_calls, :>=, @rows.length

    expected_by_group = partitioned_values.transform_values do |values|
      reference_wma(values, 1, 0)
    end
    expected = result.map { |g, id, _| expected_by_group[g][(id - 1) / 3] }
    assert_float_array_in_delta expected, result.map { |row| row[2] }
    assert_equal 0, live_window_instance_count
  end

  def test_exception_in_step
    klass = Class.new(WeightedMovingAverage) do
      def self.name
        "boom_step"
      end

      def step(x)
        raise CustomException, "boom in step" if x > 100

        super
      end
    end
    @db.create_window_function_handler(klass)
    @db.execute("INSERT INTO t (id, g, v) VALUES (100, 'a', 1000.0)")

    error = assert_raise(CustomException) do
      @db.execute("SELECT boom_step(v) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t")
    end
    assert_equal "boom in step", error.message

    assert_cleanup_and_usable
  end

  def test_exception_in_inverse
    klass = Class.new(WeightedMovingAverage) do
      def self.name
        "boom_inverse"
      end

      def inverse(x)
        raise CustomException, "boom in inverse" if x > 100

        super
      end
    end
    @db.create_window_function_handler(klass)
    # the boom row must be followed by at least two rows: it only leaves
    # the frame (calling inverse) once the frame start slides past it
    @db.execute("UPDATE t SET v = 1000.0 WHERE id = 5")

    error = assert_raise(CustomException) do
      @db.execute("SELECT boom_inverse(v) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t")
    end
    assert_equal "boom in inverse", error.message

    assert_cleanup_and_usable
  end

  def test_exception_in_value
    klass = Class.new(WeightedMovingAverage) do
      def self.name
        "boom_value"
      end

      def value
        raise CustomException, "boom in value" if @count >= 2

        super
      end
    end
    @db.create_window_function_handler(klass)

    error = assert_raise(CustomException) do
      @db.execute("SELECT boom_value(v) OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM t")
    end
    assert_equal "boom in value", error.message

    assert_cleanup_and_usable
  end

  def test_statement_closed_early_cleans_up
    @db.create_window_function_handler(TrackingWma)
    TrackingWma.reset!

    stmt = @db.prepare("SELECT twma(v) OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM t")
    2.times { stmt.step }
    assert_operator TrackingWma.created, :>=, 1
    assert_equal 0, TrackingWma.finalized

    stmt.close
    assert_equal TrackingWma.created, TrackingWma.finalized
    assert_equal 0, live_window_instance_count
  ensure
    stmt&.close unless stmt&.closed?
  end

  def test_arity_is_enforced
    assert_raise(SQLite3::SQLException) do
      @db.execute("SELECT wma(v, v) OVER (ORDER BY id) FROM t")
    end
  end

  private

  # After an exception the poisoned instances must be cleaned up and the
  # database must keep working with fresh instances.
  def assert_cleanup_and_usable
    assert_equal 0, live_window_instance_count

    result = @db.execute(
      "SELECT wma(v) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t ORDER BY id"
    )
    values = @db.execute("SELECT v FROM t ORDER BY id").map(&:first)
    expected = reference_wma(values, 1, 0)
    assert_float_array_in_delta expected, result.map { |row| row[0] }
    assert_equal 0, live_window_instance_count
  end
end
