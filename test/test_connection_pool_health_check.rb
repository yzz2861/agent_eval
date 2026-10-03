require_relative "helper"

class TestConnectionPoolHealthCheck < Minitest::Test
  def teardown
    # wipe the `:INSTANCES` const to avoid cross test contamination
    ConnectionPool.reset_instances
  end

  class FakeConnection
    attr_reader :id

    def initialize(id)
      @id = id
    end
  end

  # Factory producing numbered fake connections, safe for concurrent use.
  def numbered_factory
    mutex = Mutex.new
    count = 0
    -> {
      id = mutex.synchronize { count += 1 }
      FakeConnection.new(id)
    }
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def test_healthy_connection_is_delivered
    checked = Queue.new
    pool = ConnectionPool.new(size: 1, timeout: 1,
      checkout_health_check: ->(conn) { checked << conn; true },
      &numbered_factory)

    conn = pool.checkout
    assert_same conn, checked.pop
    pool.checkin
    assert_equal 1, pool.available
  end

  def test_unhealthy_connection_is_destroyed_and_never_delivered
    destroyed = Queue.new
    bad = nil
    checker = ->(conn) { conn != bad }
    pool = ConnectionPool.new(size: 1, timeout: 1,
      checkout_health_check: checker,
      on_connection_destroy: ->(conn) { destroyed << conn },
      &numbered_factory)

    first = pool.checkout
    pool.checkin

    bad = first
    conn = pool.checkout
    refute_same first, conn
    assert_same first, destroyed.pop
    pool.checkin
    assert_equal 1, pool.available
  end

  def test_with_returns_healthy_connection
    bad = nil
    checker = ->(conn) { conn != bad }
    pool = ConnectionPool.new(size: 1, timeout: 1,
      checkout_health_check: checker,
      &numbered_factory)

    first = pool.checkout
    pool.checkin

    bad = first
    pool.with do |conn|
      refute_same first, conn
    end
    assert_equal 1, pool.available
  end

  def test_slow_health_check_does_not_block_checkin
    entered = Queue.new
    gate = Queue.new
    # Block the check only for the first connection ever created.
    checker = ->(conn) {
      if conn.id == 1
        entered << true
        gate.pop
      end
      true
    }
    pool = ConnectionPool.new(size: 2, timeout: 2,
      checkout_health_check: checker,
      &numbered_factory)

    blocker = Thread.new do
      pool.checkout
      pool.checkin
    end
    # Wait until the blocker thread is stuck inside the slow health check.
    Timeout.timeout(2) { entered.pop }

    checkedin = Queue.new
    main = Thread.new do
      pool.checkout
      pool.checkin
      checkedin << true
    end

    # Checkin must complete while the other thread is still inside its check.
    assert_equal true, Timeout.timeout(2) { checkedin.pop }
    main.join
  ensure
    gate << :go
    blocker.join
  end

  def test_attempts_share_the_original_checkout_deadline
    destroyed = []
    mutex = Mutex.new
    pool = ConnectionPool.new(size: 1, timeout: 0.2,
      checkout_health_check: ->(conn) { false },
      on_connection_destroy: ->(conn) { mutex.synchronize { destroyed << conn } },
      &numbered_factory)

    start = monotonic
    assert_raises(ConnectionPool::TimeoutError) { pool.checkout }
    elapsed = monotonic - start

    assert_operator elapsed, :>=, 0.2
    assert_operator elapsed, :<, 2
    refute_empty destroyed
  end

  def test_capacity_is_recovered_after_timeout
    healthy = false
    pool = ConnectionPool.new(size: 1, timeout: 0.2,
      checkout_health_check: ->(conn) { healthy },
      &numbered_factory)

    assert_raises(ConnectionPool::TimeoutError) { pool.checkout }
    assert_equal 1, pool.available

    # The pool can create fresh connections after the failed checkout.
    healthy = true
    conn = pool.checkout
    assert_instance_of FakeConnection, conn
    pool.checkin
  end

  def test_health_check_exception_destroys_connection_and_recovers_capacity
    destroyed = Queue.new
    pool = ConnectionPool.new(size: 1, timeout: 1,
      checkout_health_check: ->(conn) { raise "boom" },
      on_connection_destroy: ->(conn) { destroyed << conn },
      &numbered_factory)

    error = assert_raises(RuntimeError) { pool.checkout }
    assert_equal "boom", error.message
    assert_equal 1, destroyed.size
    assert_equal 1, pool.available
  end

  def test_max_checkout_replacements_gives_up_instead_of_spinning
    destroyed = []
    mutex = Mutex.new
    pool = ConnectionPool.new(size: 1, timeout: 30, max_checkout_replacements: 2,
      checkout_health_check: ->(conn) { false },
      on_connection_destroy: ->(conn) { mutex.synchronize { destroyed << conn } },
      &numbered_factory)

    start = monotonic
    error = assert_raises(ConnectionPool::Error) { pool.checkout }
    assert_operator monotonic - start, :<, 5
    assert_includes error.message, "health check"
    assert_equal 2, destroyed.size
    assert_equal 1, pool.available
  end

  def test_concurrent_unhealthy_discovery_recovers_capacity
    destroyed = []
    mutex = Mutex.new
    pool = ConnectionPool.new(size: 2, timeout: 0.2,
      checkout_health_check: ->(conn) { false },
      on_connection_destroy: ->(conn) { mutex.synchronize { destroyed << conn } },
      &numbered_factory)

    errors = Queue.new
    threads = Array.new(2) do
      Thread.new do
        pool.checkout
      rescue ConnectionPool::TimeoutError => e
        errors << e
      end
    end
    threads.each(&:join)

    assert_equal 2, errors.size
    assert_equal 2, pool.available
  end

  def test_checkout_after_shutdown_raises_and_does_not_leak_capacity
    pool = ConnectionPool.new(size: 1, timeout: 0.2,
      checkout_health_check: ->(conn) { true },
      &numbered_factory)
    pool.shutdown { |conn| }

    assert_raises(ConnectionPool::PoolShuttingDownError) { pool.checkout }
  end

  def test_negative_max_checkout_replacements_is_rejected
    assert_raises(ArgumentError) do
      ConnectionPool.new(size: 1, max_checkout_replacements: -1) { FakeConnection.new(0) }
    end
  end
end
