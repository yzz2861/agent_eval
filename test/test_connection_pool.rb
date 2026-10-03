require_relative "helper"

class TestConnectionPool < Minitest::Test
  def teardown
    # wipe the `:INSTANCES` const to avoid cross test contamination
    ConnectionPool.reset_instances
  end

  class NetworkConnection
    SLEEP_TIME = 0.02

    def initialize
      @x = 0
    end

    def pass
      Thread.pass
    end

    def do_something(*_args, increment: 1)
      @x += increment
      sleep 0.02
      @x
    end

    def do_something_with_positional_hash(options)
      @x += options[:increment] || 1
      pass
      @x
    end

    def fast
      @x += 1
    end

    def do_something_with_block
      @x += yield
      pass
      @x
    end

    def respond_to?(method_id, *args)
      method_id == :do_magic || super
    end
  end

  class Recorder
    def initialize
      @calls = []
    end

    attr_reader :calls

    def do_work(label)
      @calls << label
    end
  end

  def use_pool(pool, size)
    Array.new(size) {
      Thread.new do
        pool.with { sleep }
      end
    }.each do |thread|
      Thread.pass until thread.status == "sleep"
    end
  end

  def kill_threads(threads)
    threads.each(&:kill)
    threads.each(&:join)
  end

  def refute_joinable(thread, timeout = 1)
    assert_nil thread.join(timeout), "expected #{thread.inspect} to still be blocked"
  end

  def assert_join(thread, timeout = 5)
    refute_nil thread.join(timeout), "expected #{thread.inspect} to finish within #{timeout}s"
    thread
  end

  def wait_for_stop(thread, timeout = 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    sleep 0.001 while thread.alive? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    refute thread.alive?, "expected #{thread.inspect} to stop within #{timeout}s"
  end

  def assert_join_error(thread, timeout = 5)
    wait_for_stop(thread, timeout)
    begin
      thread.value
    rescue StandardError => e
      return e
    end
    flunk "expected #{thread.inspect} to raise but it succeeded"
  end

  def test_basic_multithreaded_usage
    pool_size = 5
    pool = ConnectionPool.new(size: pool_size) { NetworkConnection.new }
    generations = 3

    result = Array.new(pool_size * generations) {
      Thread.new do
        pool.with do |net|
          net.do_something
        end
      end
    }.map(&:value)

    assert_equal((1..generations).cycle(pool_size).sort, result.sort)
  end

  def test_timeout
    pool = ConnectionPool.new(timeout: 0, size: 1) { NetworkConnection.new }
    thread = Thread.new {
      pool.with do |net|
        net.do_something
        sleep 0.01
      end
    }

    Thread.pass while thread.status == "run"

    assert_raises Timeout::Error do
      pool.with { |net| net.do_something }
    end

    thread.join

    pool.with do |conn|
      refute_nil conn
    end
  end

  def test_with
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }

    pool.with do
      Thread.new {
        assert_raises Timeout::Error do
          pool.checkout
        end
      }.join
    end

    assert Thread.new { pool.checkout }.join
  end

  def test_then
    pool = ConnectionPool.new { Object.new }

    assert_equal pool.method(:then), pool.method(:with)
  end

  def test_with_timeout
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }

    assert_raises Timeout::Error do
      Timeout.timeout(0.01) do
        pool.with do |obj|
          assert_equal 0, pool.available
          sleep 0.015
        end
      end
    end
    assert_equal 1, pool.available
    # Timeout.timeout creates a watcher thread and does not provide a way to
    # shut it down so we have to disable maxitest's extra thread paranoia or
    # else it will trigger a test failure.
    skip_maxitest_extra_threads
  end

  def skip_maxitest_extra_threads
    @maxitest_threads_before = Thread.list
  end

  def test_invalid_size
    assert_raises ArgumentError, TypeError do
      ConnectionPool.new(timeout: 0, size: nil) { Object.new }
    end
    assert_raises ArgumentError, TypeError do
      ConnectionPool.new(timeout: 0, size: "") { Object.new }
    end
  end

  def test_handle_interrupt_ensures_checkin
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }
    def pool.checkout(**options)
      sleep 0.015
      super
    end

    action = lambda do
      Timeout.timeout(0.01) do
        pool.with do |obj|
          # Timeout::Error will be triggered by any non-trivial Ruby code
          # executed here since it couldn't be raised during checkout.
          # It looks like setting a local variable does not trigger
          # the Timeout check in MRI 2.2.1.
          obj.tap { obj.hash }
        end
      end
    end

    assert_raises Timeout::Error, &action
    assert_equal 1, pool.available
  end

  def test_explicit_return
    pool = ConnectionPool.new(timeout: 0, size: 1) {
      mock = Minitest::Mock.new
      def mock.disconnect!
        raise "should not disconnect upon explicit return"
      end

      mock
    }

    pool.with do |conn|
      return true
    end
  end

  def test_with_timeout_override
    pool = ConnectionPool.new(timeout: 0, size: 1) { NetworkConnection.new }

    t = Thread.new {
      pool.with do |net|
        net.do_something
        sleep 0.01
      end
    }

    Thread.pass while t.status == "run"

    assert_raises Timeout::Error do
      pool.with { |net| net.do_something }
    end

    pool.with(timeout: 2 * NetworkConnection::SLEEP_TIME) do |conn|
      refute_nil conn
    end
  end

  def test_with_options
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }
    stack = pool.instance_variable_get(:@available)

    def stack.connection_stored?(opts)
      raise opts.to_s
    end

    options = {foo: 123}
    e = assert_raises do
      pool.with(**options) {}
    end

    assert_equal e.message, options.to_s
  end

  def test_with_options_on_checkin
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }
    stack = pool.instance_variable_get(:@available)
    stored_options = []

    stack.define_singleton_method(:store_connection) do |connection, **options|
      stored_options << options
      super(connection, **options)
    end

    pool.with(role: :replica) do
      pool.with(role: :primary) {}
    end

    assert_equal [{role: :replica}], stored_options
  end

  def test_checkin
    pool = ConnectionPool.new(timeout: 0, size: 1) { NetworkConnection.new }
    conn = pool.checkout

    Thread.new {
      assert_raises Timeout::Error do
        pool.checkout
      end
    }.join

    pool.checkin

    assert_same conn, Thread.new { pool.checkout }.value
  end

  def test_discard
    pool = ConnectionPool.new(timeout: 0, size: 1) { NetworkConnection.new }
    pool.checkout

    Thread.new {
      assert_raises Timeout::Error do
        pool.checkout
      end
    }.join

    pool.discard_current_connection
    pool.checkin

    assert_equal 1, pool.size
    assert_equal 0, pool.idle
    assert_equal 1, pool.available
  end

  def test_discard_with_argument
    pool = ConnectionPool.new(timeout: 0, size: 1) { NetworkConnection.new }
    pool.checkout

    Thread.new {
      assert_raises Timeout::Error do
        pool.checkout
      end
    }.join

    pool.discard_current_connection { |conn| assert_kind_of NetworkConnection, conn }
    pool.checkin

    assert_equal 1, pool.size
    assert_equal 0, pool.idle
    assert_equal 1, pool.available
  end

  def test_discard_with_argument_and_error
    pool = ConnectionPool.new(timeout: 0, size: 1) { NetworkConnection.new }
    pool.checkout

    Thread.new {
      assert_raises Timeout::Error do
        pool.checkout
      end
    }.join

    pool.discard_current_connection { |conn| raise "boom" }
    pool.checkin

    assert_equal 1, pool.size
    assert_equal 0, pool.idle
    assert_equal 1, pool.available
  end

  def test_returns_value
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }
    assert_equal 1, pool.with { |o| 1 }
  end

  def test_checkin_never_checkout
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }

    e = assert_raises(ConnectionPool::Error) { pool.checkin }
    assert_equal "no connections are checked out", e.message
  end

  def test_checkin_no_current_checkout
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }

    pool.checkout
    pool.checkin

    assert_raises ConnectionPool::Error do
      pool.checkin
    end
  end

  def test_checkin_twice
    pool = ConnectionPool.new(timeout: 0, size: 1) { Object.new }

    pool.checkout
    pool.checkout

    pool.checkin

    Thread.new {
      assert_raises Timeout::Error do
        pool.checkout
      end
    }.join

    pool.checkin

    assert Thread.new { pool.checkout }.join
  end

  def test_checkout
    pool = ConnectionPool.new(size: 1) { NetworkConnection.new }

    conn = pool.checkout

    assert_kind_of NetworkConnection, conn

    assert_same conn, pool.checkout
  end

  def test_checkout_multithread
    pool = ConnectionPool.new(size: 2) { NetworkConnection.new }
    conn = pool.checkout

    t = Thread.new {
      pool.checkout
    }

    refute_same conn, t.value
  end

  def test_checkout_timeout
    pool = ConnectionPool.new(timeout: 0, size: 0) { Object.new }

    assert_raises Timeout::Error do
      pool.checkout
    end
  end

  def test_checkout_timeout_override
    pool = ConnectionPool.new(timeout: 0, size: 1) { NetworkConnection.new }

    thread = Thread.new {
      pool.with do |net|
        net.do_something
        sleep 0.01
      end
    }

    Thread.pass while thread.status == "run"

    assert_raises Timeout::Error do
      pool.checkout
    end

    assert pool.checkout(timeout: 2 * NetworkConnection::SLEEP_TIME)
  end

  def test_passthru
    pool = ConnectionPool.wrap(timeout: 2 * NetworkConnection::SLEEP_TIME, size: 1) { NetworkConnection.new }
    assert_equal 1, pool.do_something
    assert_equal 2, pool.do_something
    assert_equal 5, pool.do_something_with_block { 3 }
    assert_equal 6, pool.with { |net| net.fast }
    assert_equal 8, pool.do_something(increment: 2)
    assert_equal 10, pool.do_something_with_positional_hash({:increment => 2, :symbol_key => 3, "string_key" => 4})
  end

  def test_passthru_respond_to
    pool = ConnectionPool.wrap(timeout: 2 * NetworkConnection::SLEEP_TIME, size: 1) { NetworkConnection.new }
    assert pool.respond_to?(:with)
    assert pool.respond_to?(:do_something)
    assert pool.respond_to?(:do_magic)
    refute pool.respond_to?(:do_lots_of_magic)
  end

  def test_return_value
    pool = ConnectionPool.new(timeout: 2 * NetworkConnection::SLEEP_TIME, size: 1) { NetworkConnection.new }
    result = pool.with { |net|
      net.fast
    }
    assert_equal 1, result
  end

  def test_heavy_threading
    pool = ConnectionPool.new(timeout: 0.5, size: 3) { NetworkConnection.new }

    threads = Array.new(20) {
      Thread.new do
        pool.with do |net|
          sleep 0.01
        end
      end
    }

    threads.map { |thread| thread.join }
  end

  def test_reuses_objects_when_pool_not_saturated
    pool = ConnectionPool.new(size: 5) { NetworkConnection.new }

    ids = 10.times.map {
      pool.with { |c| c.object_id }
    }

    assert_equal 1, ids.uniq.size
  end

  def test_nested_checkout
    recorder = Recorder.new
    pool = ConnectionPool.new(size: 1) { recorder }
    pool.with do |r_outer|
      @other = Thread.new { |t|
        pool.with do |r_other|
          r_other.do_work("other")
        end
      }

      pool.with do |r_inner|
        r_inner.do_work("inner")
      end

      Thread.pass

      r_outer.do_work("outer")
    end

    @other.join

    assert_equal ["inner", "outer", "other"], recorder.calls
  end

  def test_nested_discard
    recorder = Recorder.new
    pool = ConnectionPool.new(size: 1, timeout: 0.01) { {recorder: recorder} }
    pool.with do |r_outer|
      @other = Thread.new { |t|
        pool.with do |r_other|
          r_other[:recorder].do_work("other")
        end
      }

      pool.with do |r_inner|
        @inner = r_inner
        r_inner[:recorder].do_work("inner")
        pool.discard_current_connection
      end

      Thread.pass

      r_outer[:recorder].do_work("outer")
    end

    @other.join

    assert_equal ["inner", "outer", "other"], recorder.calls
    refute_same @inner, pool.checkout
  end

  def test_shutdown_is_executed_for_all_connections
    recorders = []

    pool = ConnectionPool.new(size: 3) {
      Recorder.new.tap { |r| recorders << r }
    }

    threads = use_pool pool, 3

    pool.shutdown do |recorder|
      recorder.do_work("shutdown")
    end

    kill_threads(threads)

    assert_equal %w[shutdown shutdown shutdown], recorders.map { |r| r.calls }.flatten
  end

  def test_checkout_after_reload_cannot_create_new_connections_beyond_size
    pool = ConnectionPool.new(size: 1, name: "bob") { Object.new }
    threads = use_pool pool, 1
    pool.reload {}
    assert_raises ConnectionPool::TimeoutError do
      pool.checkout(timeout: 0)
    end
  ensure
    kill_threads(threads) if threads
  end

  def test_raises_error_after_shutting_down
    pool = ConnectionPool.new(size: 1) { true }

    pool.shutdown {}

    assert_raises ConnectionPool::PoolShuttingDownError do
      pool.checkout
    end
  end

  def test_runs_shutdown_block_asynchronously_if_connection_was_in_use
    recorders = []

    pool = ConnectionPool.new(size: 3) {
      Recorder.new.tap { |r| recorders << r }
    }

    threads = use_pool pool, 2

    pool.checkout

    pool.shutdown do |recorder|
      recorder.do_work("shutdown")
    end

    kill_threads(threads)

    assert_equal [["shutdown"], ["shutdown"], []], recorders.map { |r| r.calls }

    pool.checkin

    assert_equal [["shutdown"], ["shutdown"], ["shutdown"]], recorders.map { |r| r.calls }
  end

  def test_raises_an_error_if_shutdown_is_called_without_a_block
    pool = ConnectionPool.new(size: 1) {}

    assert_raises ArgumentError do
      pool.shutdown
    end
  end

  def test_shutdown_is_executed_for_all_connections_in_wrapped_pool
    recorders = []

    wrapper = ConnectionPool::Wrapper.new(size: 3) {
      Recorder.new.tap { |r| recorders << r }
    }

    threads = use_pool wrapper, 3

    wrapper.pool_shutdown do |recorder|
      recorder.do_work("shutdown")
    end

    kill_threads(threads)

    assert_equal [["shutdown"]] * 3, recorders.map { |r| r.calls }
  end

  def test_quiesce_block_runs_with_zero_checked_out_connections
    pool = ConnectionPool.new(size: 2) { Object.new }

    ready = Queue.new
    release = Queue.new
    checked_out_inside = nil
    available_inside = nil
    main_entered = Queue.new
    release_main = Queue.new

    workers = Array.new(2) do
      Thread.new do
        pool.with do |_conn|
          ready << true
          release.pop
        end
      end
    end

    2.times { ready.pop }

    main = Thread.new do
      pool.quiesce do
        checked_out_inside = pool.checked_out_count
        available_inside = pool.available
        main_entered << true
        release_main.pop
      end
    end

    2.times { release << true }
    main_entered.pop

    assert_equal 0, checked_out_inside
    assert_equal pool.size, available_inside

    # While maintenance is still running, a new external checkout is blocked.
    late = Thread.new { pool.with { |conn| conn } }
    refute_joinable late

    release_main << true
    assert_join main
    assert_join late
    workers.each { |thread| assert_join thread }
  end

  def test_quiesce_nested_with_for_existing_holder_is_not_blocked
    pool = ConnectionPool.new(size: 1) { Recorder.new }

    pool.with do |recorder|
      pool.with do |inner|
        inner.do_work("nested")
      end
      recorder.do_work("outer")
    end

    recorder = pool.checkout
    assert_equal %w[nested outer], recorder.calls
    pool.checkin
  end

  def test_quiesce_rejected_from_thread_holding_a_connection
    pool = ConnectionPool.new(size: 1) { Object.new }

    pool.with do
      error = assert_raises ConnectionPool::Error do
        pool.quiesce {}
      end
      assert_match(/holds a connection/, error.message)
    end

    pool.quiesce {}
  end

  def test_quiesce_times_out_when_a_connection_stays_checked_out
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    ready = Queue.new
    release = Queue.new
    holder = Thread.new do
      pool.with do |_conn|
        ready << true
        release.pop
      end
    end
    ready.pop

    error = assert_raises ConnectionPool::TimeoutError do
      pool.quiesce(timeout: 0.02) {}
    end
    assert_match(/1 connection/, error.message)

    release << true
    assert_join holder
    pool.quiesce(timeout: 1) {}
  end

  def test_quiesce_checkout_waiter_times_out_while_barrier_is_active
    pool = ConnectionPool.new(size: 1, timeout: 0.02) { Object.new }
    entered = Queue.new
    release = Queue.new
    maintenance = Thread.new do
      pool.quiesce do
        entered << true
        release.pop
      end
    end
    entered.pop

    waiter = Thread.new { Thread.current.report_on_exception = false; pool.with { |conn| conn } }
    error = assert_join_error waiter
    assert_kind_of ConnectionPool::TimeoutError, error
    assert_match(/quiescing/, error.message)

    release << true
    assert_join maintenance
  end

  def test_quiesce_succeeds_once_holder_returns_connection
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    ready = Queue.new
    release = Queue.new
    holder = Thread.new do
      pool.with do |_conn|
        ready << true
        release.pop
      end
    end
    ready.pop

    release << true
    assert_join holder
    pool.quiesce(timeout: 1) {}

    pool.with { |conn| refute_nil conn }
  end

  def test_quiesce_releases_barrier_when_block_raises
    pool = ConnectionPool.new(size: 1) { Object.new }

    assert_raises RuntimeError do
      pool.quiesce { raise "maintenance failed" }
    end

    pool.with { |conn| refute_nil conn }
  end

  def test_quiesce_shutdown_race_while_waiting_for_checkins
    pool = ConnectionPool.new(size: 1) { Object.new }

    ready = Queue.new
    release = Queue.new
    holder = Thread.new do
      pool.with do |_conn|
        ready << true
        release.pop
      end
    end
    ready.pop

    maintenance = Thread.new do
      Thread.current.report_on_exception = false
      pool.quiesce { flunk "maintenance block must not run" }
    end
    refute_joinable maintenance

    pool.shutdown {}

    error = assert_join_error maintenance
    assert_kind_of ConnectionPool::PoolShuttingDownError, error

    release << true
    assert_join holder

    assert_raises ConnectionPool::PoolShuttingDownError do
      pool.checkout(timeout: 0.02)
    end
  end

  def test_quiesce_shutdown_race_while_block_runs_releases_waiters
    pool = ConnectionPool.new(size: 2) { Object.new }

    ready = Queue.new
    release_holder = Queue.new
    block_started = Queue.new
    release_block = Queue.new

    # The holder must check out first: a lazy pool with no connections yet
    # would otherwise look already quiescent.
    holder = Thread.new do
      pool.with do |_conn|
        ready << true
        release_holder.pop
      end
    end
    ready.pop

    maintenance = Thread.new do
      pool.quiesce do
        block_started << true
        release_block.pop
      end
    end
    refute_joinable maintenance

    release_holder << true
    block_started.pop
    refute_joinable maintenance

    waiter = Thread.new { Thread.current.report_on_exception = false; pool.with { |conn| conn } }
    refute_joinable waiter

    # reload races with the active maintenance block; waiters must not hang.
    pool.reload {}
    wait_for_stop waiter
    waiter_error = begin
      waiter.value
      nil
    rescue StandardError => e
      e
    end
    assert_kind_of ConnectionPool::PoolShuttingDownError, waiter_error

    release_block << true
    assert_join maintenance
    assert_join holder

    # After the barrier is released and reload completes, service resumes.
    pool.with { |conn| refute_nil conn }
  end

  def test_quiesce_serializes_concurrent_maintenance_blocks
    pool = ConnectionPool.new(size: 1) { Object.new }
    events = []
    events_mutex = Thread::Mutex.new
    entered = Queue.new
    release = Queue.new

    first = Thread.new do
      pool.quiesce do
        events_mutex.synchronize { events << :first }
        entered << true
        release.pop
      end
    end
    entered.pop

    second = Thread.new do
      pool.quiesce { events_mutex.synchronize { events << :second } }
    end
    refute_joinable second

    release << true
    assert_join first
    assert_join second
    assert_equal [:first, :second], events
  end

  def test_quiesce_requires_a_block
    pool = ConnectionPool.new(size: 1) { Object.new }

    assert_raises ArgumentError do
      pool.quiesce
    end
  end

  def test_wrapped_pool_quiesce
    wrapper = ConnectionPool::Wrapper.new(size: 1) { Object.new }
    ran = false
    wrapper.pool_quiesce { ran = true }
    assert ran
  end

  def test_reap_removes_idle_connections
    recorders = []
    pool = ConnectionPool.new(size: 1) do
      Recorder.new.tap { |r| recorders << r }
    end

    pool.with { |conn| conn }

    assert_equal 1, pool.idle

    pool.reap(idle_seconds: 0) { |recorder| recorder.do_work("reap") }

    assert_equal 0, pool.idle
    assert_equal [["reap"]], recorders.map(&:calls)
  end

  def test_reap_removes_all_idle_connections
    recorders = []
    pool = ConnectionPool.new(size: 3) do
      Recorder.new.tap { |r| recorders << r }
    end
    threads = use_pool(pool, 3)
    kill_threads(threads)

    assert_equal 3, pool.idle

    pool.reap(idle_seconds: 0) { |recorder| recorder.do_work("reap") }

    assert_equal 0, pool.idle
    assert_equal [["reap"]] * 3, recorders.map(&:calls)
  end

  def test_reap_does_not_remove_connections_if_outside_idle_time
    pool = ConnectionPool.new(size: 1) { Object.new }

    pool.with { |conn| conn }

    pool.reap(idle_seconds: 1000) { |conn| flunk "should not reap active connection" }
  end

  def test_idle_returns_number_of_idle_connections
    pool = ConnectionPool.new(size: 1) { Object.new }

    assert_equal 0, pool.idle

    pool.checkout

    assert_equal 0, pool.idle

    pool.checkin

    assert_equal 1, pool.idle
  end

  def test_idle_with_multiple_connections
    pool = ConnectionPool.new(size: 3) { Object.new }

    assert_equal 0, pool.idle

    threads = use_pool(pool, 3)

    assert_equal 0, pool.idle

    kill_threads(threads)

    assert_equal 3, pool.idle
  end

  def test_reap_raises_error_after_shutting_down
    pool = ConnectionPool.new(size: 1) { true }

    pool.shutdown {}

    assert_raises ConnectionPool::PoolShuttingDownError do
      pool.reap(idle_seconds: 0) {}
    end
  end

  def test_wrapper_wrapped_pool
    wrapper = ConnectionPool::Wrapper.new { NetworkConnection.new }
    assert_equal ConnectionPool, wrapper.wrapped_pool.class
  end

  def test_wrapper_method_missing
    wrapper = ConnectionPool::Wrapper.new { NetworkConnection.new }

    assert_equal 1, wrapper.fast
  end

  def test_wrapper_respond_to_eh
    wrapper = ConnectionPool::Wrapper.new { NetworkConnection.new }

    assert_respond_to wrapper, :with

    assert_respond_to wrapper, :fast
    refute_respond_to wrapper, :"nonexistent method"
  end

  def test_wrapper_with
    wrapper = ConnectionPool::Wrapper.new(timeout: 0, size: 1) { Object.new }

    wrapper.with do
      Thread.new {
        assert_raises Timeout::Error do
          wrapper.with { flunk "connection checked out :(" }
        end
        assert_raises Timeout::Error do
          wrapper.with(timeout: 0.1) { flunk "connection checked out :(" }
        end
      }.join
    end

    assert Thread.new { wrapper.with {} }.join
  end

  class ConnWithEval
    def eval(arg)
      "eval'ed #{arg}"
    end
  end

  def test_wrapper_kernel_methods
    wrapper = ConnectionPool::Wrapper.new(timeout: 0, size: 1) { ConnWithEval.new }

    assert_equal "eval'ed 1", wrapper.eval(1)
  end

  def test_wrapper_with_connection_pool
    recorder = Recorder.new
    pool = ConnectionPool.new(size: 1) { recorder }
    wrapper = ConnectionPool::Wrapper.new(pool: pool)

    pool.with { |r| r.do_work("with") }
    wrapper.do_work("wrapped")

    assert_equal ["with", "wrapped"], recorder.calls
  end

  def test_stats_without_active_connection
    pool = ConnectionPool.new(size: 2) { NetworkConnection.new }

    assert_equal(2, pool.size)
    assert_equal(2, pool.available)
  end

  def test_stats_with_active_connection
    pool = ConnectionPool.new(size: 2) { NetworkConnection.new }

    pool.with do
      assert_equal(1, pool.available)
    end
  end

  def test_stats_with_string_size
    pool = ConnectionPool.new(size: "2") { NetworkConnection.new }

    pool.with do
      assert_equal(2, pool.size)
      assert_equal(1, pool.available)
    end
  end

  def test_after_fork_callback
    skip("MRI feature") unless Process.respond_to?(:fork)
    GC.start # cleanup instances created by other tests

    pool = ConnectionPool.new(size: 2, auto_reload_after_fork: true) { NetworkConnection.new }
    prefork_connection = pool.with { |c| c }
    assert_equal(prefork_connection, pool.with { |c| c })
    ConnectionPool.after_fork
    refute_equal(prefork_connection, pool.with { |c| c })
  end

  def test_after_fork_callback_being_skipped
    skip("MRI feature") unless Process.respond_to?(:fork)
    GC.start # cleanup instances created by other tests

    pool = ConnectionPool.new(size: 2, auto_reload_after_fork: false) { NetworkConnection.new }
    prefork_connection = pool.with { |c| c }
    assert_equal(prefork_connection, pool.with { |c| c })
    ConnectionPool.after_fork
    assert_equal(prefork_connection, pool.with { |c| c })
  end

  def test_after_fork_callback_checkin
    skip("MRI feature") unless Process.respond_to?(:fork)
    GC.start # cleanup instances created by other tests

    pool = ConnectionPool.new(size: 2, auto_reload_after_fork: true) { NetworkConnection.new }
    prefork_connection = pool.checkout
    assert_equal(prefork_connection, pool.checkout)
    ConnectionPool.after_fork
    refute_equal(prefork_connection, pool.checkout)
  end

  def test_automatic_after_fork_callback
    skip("MRI 3.1 feature") unless Process.respond_to?(:_fork)
    GC.start # cleanup instances created by other tests

    pool = ConnectionPool.new(size: 2, auto_reload_after_fork: true) { NetworkConnection.new }
    prefork_connection = pool.with { |c| c }
    assert_equal(prefork_connection, pool.with { |c| c })
    pid = fork do
      refute_equal(prefork_connection, pool.with { |c| c })
      exit!(0)
    end
    assert_equal(prefork_connection, pool.with { |c| c })
    _, status = Process.waitpid2(pid)
    assert_predicate(status, :success?)
  end

  def test_ractors_pool_usage
    begin
      Ractor
    rescue NameError
      skip("Ractor not available")
    end

    silence_warnings do
      obj = "mike"
      r = Ractor.new(obj) do |copy|
        # verify we can create a pool in a Ractor and that we can
        pool = ConnectionPool.new(auto_reload_after_fork: false) { copy }
        checkedout = nil
        pool.with { |y| checkedout = y }
        checkedout
      end

      result = (RUBY_VERSION < "4") ? r.take : r.value
      assert_equal obj, result # same string but different String instance
      refute_equal obj.object_id, result.object_id # was copied across Ractor boundary
    end
  end
end
