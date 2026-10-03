require_relative "helper"

class TestConnectionPoolCancellation < Minitest::Test
  # Two-party rendezvous used to force concurrent execution of two actions.
  class Barrier
    def initialize(parties = 2)
      @parties = parties
      @waiting = 0
      @mutex = Mutex.new
      @cv = ConditionVariable.new
    end

    def wait
      @mutex.synchronize do
        @waiting += 1
        if @waiting == @parties
          @waiting = 0
          @cv.broadcast
        else
          @cv.wait(@mutex) until @waiting == 0
        end
      end
    end
  end

  def teardown
    ConnectionPool.reset_instances
  end

  def created_count(pool)
    pool.instance_variable_get(:@available).instance_variable_get(:@created)
  end

  def wait_until_sleeping(thread)
    Thread.pass until thread.status == "sleep"
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def test_cancelled_waiter_wakes_promptly_without_waiting_for_timeout
    pool = ConnectionPool.new(size: 1, timeout: 30) { Object.new }
    pool.checkout
    token = ConnectionPool::CancellationToken.new

    waiter = Thread.new do
      begin
        pool.checkout(cancel_token: token)
      rescue => e
        e
      end
    end
    wait_until_sleeping(waiter)

    started = monotonic
    token.cancel
    result = waiter.value

    assert_operator monotonic - started, :<, 5, "cancelled wait must not linger until the pool timeout"
    assert_instance_of ConnectionPool::CancelledError, result
    assert_equal 1, created_count(pool)
    pool.checkin
    assert_equal 1, pool.available
  end

  def test_token_cancelled_before_checkout_raises_immediately
    pool = ConnectionPool.new(size: 1) { Object.new }
    token = ConnectionPool::CancellationToken.new
    token.cancel

    assert_raises(ConnectionPool::CancelledError) { pool.checkout(cancel_token: token) }
    assert_raises(ConnectionPool::CancelledError) { pool.with(cancel_token: token) { } }
    assert_equal 0, created_count(pool)
    assert_equal 1, pool.available
  end

  def test_cancel_after_checkout_does_not_reclaim_the_connection
    pool = ConnectionPool.new(size: 1) { Object.new }
    token = ConnectionPool::CancellationToken.new

    pool.with(cancel_token: token) do |conn|
      token.cancel
      assert_equal 0, pool.available, "cancellation must not check the connection back in"
      assert_same conn, pool.checkout, "nested checkout still borrows the same connection"
      pool.checkin
    end

    assert_equal 1, pool.available
    assert_equal 1, created_count(pool)
  end

  def test_nested_with_ignores_cancelled_token_and_preserves_borrow_semantics
    pool = ConnectionPool.new(size: 1) { Object.new }
    token = ConnectionPool::CancellationToken.new
    token.cancel

    pool.with do |outer|
      pool.with(cancel_token: token) do |inner|
        assert_same outer, inner
      end
    end

    assert_equal 1, pool.available
    assert_equal 1, created_count(pool)
  end

  def test_uncancelled_token_keeps_timeout_and_success_behavior
    pool = ConnectionPool.new(size: 1, timeout: 0.1) { Object.new }
    token = ConnectionPool::CancellationToken.new

    conn = pool.checkout(cancel_token: token)
    assert_raises(ConnectionPool::TimeoutError) do
      Thread.new { pool.checkout(cancel_token: token) }
        .tap { |t| t.report_on_exception = false }
        .value
    end
    pool.checkin
    assert_same conn, pool.checkout(cancel_token: token)
    pool.checkin
    assert_equal 1, created_count(pool)
  end

  def test_cancel_racing_checkin_has_exactly_one_outcome
    50.times do
      pool = ConnectionPool.new(size: 1, timeout: 30) { Object.new }
      pool.checkout
      token = ConnectionPool::CancellationToken.new
      barrier = Barrier.new

      waiter = Thread.new do
        begin
          conn = pool.checkout(cancel_token: token)
          pool.checkin # the waiter returns what it borrowed, if anything
          conn
        rescue => e
          e
        end
      end
      wait_until_sleeping(waiter)

      canceller = Thread.new do
        barrier.wait
        token.cancel
      end
      barrier.wait
      pool.checkin # races with token.cancel
      canceller.join
      result = waiter.value

      # exactly one outcome: cancelled, or the waiter borrowed (and returned) the connection
      if result.is_a?(ConnectionPool::CancelledError)
        # cancel won; the connection stayed in / returned to the pool
      else
        refute_kind_of Exception, result
      end
      assert_equal 1, created_count(pool)
      assert_equal 1, pool.available
    end
  end

  def test_cancel_racing_creation_completion_has_exactly_one_outcome
    50.times do
      entered = Queue.new
      release = Queue.new
      pool = ConnectionPool.new(size: 1, timeout: 30) do
        entered << true
        release.pop
        Object.new
      end
      token = ConnectionPool::CancellationToken.new

      t = Thread.new do
        begin
          conn = pool.checkout(cancel_token: token)
          pool.checkin
          conn
        rescue => e
          e
        end
      end

      entered.pop # creation is in progress, holding the pool mutex
      canceller = Thread.new { token.cancel } # callback blocks until creation completes
      release << true # let creation finish
      result = t.value
      canceller.join

      # creation completed before the cancel could take effect: exactly one
      # outcome, the caller owned the connection and returned it itself
      refute_kind_of Exception, result
      assert_equal 1, created_count(pool)
      assert_equal 1, pool.available
    end
  end

  def test_cancel_racing_shutdown_has_exactly_one_outcome
    50.times do
      pool = ConnectionPool.new(size: 1, timeout: 30) { Object.new }
      pool.checkout
      token = ConnectionPool::CancellationToken.new
      barrier = Barrier.new
      reaped = []

      waiter = Thread.new do
        begin
          pool.checkout(cancel_token: token)
        rescue => e
          e
        end
      end
      wait_until_sleeping(waiter)

      canceller = Thread.new do
        barrier.wait
        token.cancel
      end
      barrier.wait
      pool.shutdown { |c| reaped << c } # races with token.cancel
      canceller.join
      result = waiter.value

      assert_includes [ConnectionPool::CancelledError, ConnectionPool::PoolShuttingDownError], result.class

      # return the still-checked-out connection; shutdown consumes it exactly once
      pool.checkin
      assert_equal 1, reaped.size
      assert_equal 0, created_count(pool)
    end
  end
end
