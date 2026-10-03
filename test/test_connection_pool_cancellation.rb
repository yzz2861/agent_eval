require_relative "helper"

class TestConnectionPoolCancellation < Minitest::Test
  # A one-shot, controllable barrier used to force specific thread
  # interleavings in the race tests below.
  class Barrier
    def initialize
      @mutex = Thread::Mutex.new
      @cv = Thread::ConditionVariable.new
      @open = false
    end

    def open!
      @mutex.synchronize do
        @open = true
        @cv.broadcast
      end
    end

    def await
      @mutex.synchronize do
        @cv.wait(@mutex) until @open
      end
    end
  end

  def teardown
    ConnectionPool.reset_instances
  end

  # Waits until +thread+ is blocked inside the pool's condition variable.
  def wait_until_blocked(thread)
    Thread.pass until thread.status == "sleep" || !thread.alive?
    assert thread.alive?, "waiter thread died unexpectedly"
    sleep 0.01 # let the thread actually enter ConditionVariable#wait
  end

  # Every connection created by the pool factory is either idle in the pool
  # or checked out exactly once: nothing leaked, nothing duplicated.
  def assert_resources_conserved(pool, created, checked_out: 0)
    assert_equal created.uniq, created, "factory handed out the same connection twice"
    assert_equal created.size, pool.idle + checked_out
  end

  def test_cancel_wakes_waiter_promptly_instead_of_timing_out
    created = []
    pool = ConnectionPool.new(size: 1, timeout: 30) { (created << Object.new).last }
    conn = pool.checkout
    token = ConnectionPool::CancellationToken.new

    error = nil
    waiter = Thread.new do
      begin
        pool.checkout(cancel_token: token)
      rescue => e
        error = e
      end
    end
    wait_until_blocked(waiter)

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    token.cancel!
    waiter.join(5)

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    assert_instance_of ConnectionPool::CancelledError, error
    assert_operator elapsed, :<, 5, "cancellation must not wait for the pool timeout"

    pool.checkin
    assert_same conn, pool.checkout
    pool.checkin
    assert_resources_conserved(pool, created)
  end

  def test_cancelled_token_raises_immediately_even_when_connection_available
    created = []
    pool = ConnectionPool.new(size: 1) { (created << Object.new).last }
    token = ConnectionPool::CancellationToken.new
    token.cancel!

    assert_raises(ConnectionPool::CancelledError) do
      pool.checkout(cancel_token: token)
    end
    assert_empty created, "cancelled checkout must not create a connection"
    assert_resources_conserved(pool, created)
  end

  def test_token_does_not_reclaim_connection_already_checked_out
    created = []
    pool = ConnectionPool.new(size: 1) { (created << Object.new).last }
    token = ConnectionPool::CancellationToken.new

    pool.with(cancel_token: token) do |conn|
      token.cancel!
      assert token.cancelled?
      # The connection is in use by the caller; the token must not touch it.
      assert_same conn, created.first
    end

    # The connection was checked back in normally after the block.
    assert_equal 1, pool.idle
    pool.with { |conn| assert_same conn, created.first }
    assert_resources_conserved(pool, created)
  end

  def test_nested_with_keeps_borrow_semantics_with_cancelled_token
    created = []
    pool = ConnectionPool.new(size: 1) { (created << Object.new).last }
    token = ConnectionPool::CancellationToken.new

    pool.with(cancel_token: token) do |outer|
      token.cancel!
      # Nested checkout reuses the already-borrowed connection and never
      # waits, so the cancelled token must not raise here.
      pool.with(cancel_token: token) do |inner|
        assert_same outer, inner
      end
      assert_equal 0, pool.idle
    end

    assert_equal 1, created.size
    assert_equal 1, pool.idle
    assert_resources_conserved(pool, created)
  end

  def test_cancel_racing_checkin_has_exactly_one_outcome
    50.times do
      created = []
      pool = ConnectionPool.new(size: 1, timeout: 30) { (created << Object.new).last }
      conn = pool.checkout
      token = ConnectionPool::CancellationToken.new
      gate = Barrier.new

      result = nil
      waiter = Thread.new do
        begin
          conn = pool.checkout(cancel_token: token)
          result = conn
          pool.checkin
        rescue => e
          result = e
        end
      end
      wait_until_blocked(waiter)

      canceller = Thread.new do
        gate.await
        token.cancel!
      end
      gate.open! # release cancel! and the racing checkin together
      pool.checkin
      canceller.join
      waiter.join(5)

      case result
      when ConnectionPool::CancelledError
        # Cancel won: the checked-in connection stays in the pool.
        assert_equal 1, pool.idle
      else
        # Checkin won: the waiter got the connection and returned it.
        assert_same conn, result
      end
      assert_equal 1, pool.idle
      assert_resources_conserved(pool, created)
    end
  end

  def test_cancel_during_connection_creation_still_delivers_connection
    created = []
    factory_entered = Barrier.new
    factory_release = Barrier.new
    pool = ConnectionPool.new(size: 1, timeout: 30) do
      factory_entered.open!
      factory_release.await
      (created << Object.new).last
    end
    token = ConnectionPool::CancellationToken.new

    result = nil
    waiter = Thread.new do
      begin
        result = pool.checkout(cancel_token: token)
        pool.checkin
      rescue => e
        result = e
      end
    end
    factory_entered.await

    # Cancellation lands while the factory is mid-construction. The creation
    # already started, so exactly one outcome is allowed: the finished
    # connection is delivered to the caller (the token never discards it).
    token.cancel!
    factory_release.open!
    waiter.join(5)

    assert_same created.first, result
    assert_equal 1, created.size
    assert_equal 1, pool.idle
    assert_resources_conserved(pool, created)
  end

  def test_cancel_before_creation_means_factory_never_runs
    created = []
    pool = ConnectionPool.new(size: 1, timeout: 30) { (created << Object.new).last }
    token = ConnectionPool::CancellationToken.new
    token.cancel!

    assert_raises(ConnectionPool::CancelledError) do
      pool.checkout(cancel_token: token)
    end
    assert_empty created
    assert_resources_conserved(pool, created)
  end

  def test_cancel_racing_shutdown_has_exactly_one_outcome
    50.times do
      created = []
      pool = ConnectionPool.new(size: 1, timeout: 30) { (created << Object.new).last }
      conn = pool.checkout # exhaust the pool so the waiter blocks
      token = ConnectionPool::CancellationToken.new
      gate = Barrier.new

      error = nil
      waiter = Thread.new do
        begin
          pool.checkout(cancel_token: token)
        rescue => e
          error = e
        end
      end
      wait_until_blocked(waiter)

      canceller = Thread.new do
        gate.await
        token.cancel!
      end
      gate.open! # release cancel! and shutdown together
      pool.shutdown { |c| c }
      canceller.join
      waiter.join(5)

      assert_includes [ConnectionPool::CancelledError, ConnectionPool::PoolShuttingDownError], error.class

      # Returning the connection to a shut-down pool discards it through the
      # shutdown block; no resource leaks either way.
      pool.checkin
      assert_equal 0, pool.idle
      assert_equal 1, created.size
    end
  end

  def test_shutdown_then_cancel_raises_shutdown_error_deterministically
    pool = ConnectionPool.new(size: 1, timeout: 30) { Object.new }
    pool.checkout
    token = ConnectionPool::CancellationToken.new

    error = nil
    waiter = Thread.new do
      begin
        pool.checkout(cancel_token: token)
      rescue => e
        error = e
      end
    end
    wait_until_blocked(waiter)

    pool.shutdown { |c| c }
    token.cancel!
    waiter.join(5)

    assert_instance_of ConnectionPool::PoolShuttingDownError, error
  end

  def test_listener_is_removed_after_checkout_completes
    pool = ConnectionPool.new(size: 1) { Object.new }
    token = ConnectionPool::CancellationToken.new

    pool.with(cancel_token: token) { |conn| conn }

    listeners = token.instance_variable_get(:@listeners)
    assert_empty listeners, "checkout must not leak listeners into a reused token"

    # A stale listener would broadcast into the pool long after checkout;
    # cancelling now must be a no-op for the pool.
    token.cancel!
    pool.with { |conn| assert conn }
  end

  def test_one_token_cancels_a_batch_of_waiters
    created = []
    pool = ConnectionPool.new(size: 1, timeout: 30) { (created << Object.new).last }
    conn = pool.checkout
    token = ConnectionPool::CancellationToken.new

    errors = []
    waiters = Array.new(3) do
      Thread.new do
        begin
          pool.checkout(cancel_token: token)
        rescue => e
          errors << e
        end
      end
    end
    waiters.each { |t| wait_until_blocked(t) }

    token.cancel!
    waiters.each { |t| t.join(5) }

    assert_equal 3, errors.size
    assert(errors.all? { |e| e.is_a?(ConnectionPool::CancelledError) })

    pool.checkin
    assert_equal 1, pool.idle
    assert_resources_conserved(pool, created)
  end

  def test_uncancelled_token_still_times_out_normally
    pool = ConnectionPool.new(size: 1, timeout: 0.1) { Object.new }
    pool.checkout
    token = ConnectionPool::CancellationToken.new

    error = nil
    waiter = Thread.new do
      begin
        pool.checkout(cancel_token: token)
      rescue => e
        error = e
      end
    end
    waiter.join(5)

    assert_instance_of ConnectionPool::TimeoutError, error
    refute token.cancelled?
  end
end
