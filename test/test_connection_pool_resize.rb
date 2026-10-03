require_relative "helper"

class TestConnectionPoolResize < Minitest::Test
  # A fake connection whose lifecycle (creation, closing) can be tracked.
  class TrackableConnection
    attr_reader :id
    attr_accessor :closed

    def initialize(id)
      @id = id
      @closed = false
    end

    def close
      @closed = true
    end
  end

  # Creates TrackableConnections and records every creation and
  # destruction so tests can assert on the exact sequence of events.
  class ConnectionTracker
    attr_reader :created, :destroyed

    def initialize
      @created = []
      @destroyed = []
      @mutex = Mutex.new
    end

    def create
      conn = TrackableConnection.new(@created.size)
      @mutex.synchronize { @created << conn }
      conn
    end

    def destroy(conn)
      conn.close
      @mutex.synchronize { @destroyed << conn }
    end

    def created_count
      @mutex.synchronize { @created.size }
    end

    def destroyed_count
      @mutex.synchronize { @destroyed.size }
    end

    def alive_count
      @mutex.synchronize { @created.count { |conn| !conn.closed } }
    end
  end

  def teardown
    ConnectionPool.reset_instances
  end

  # Checks out +count+ connections in background threads and hands them to
  # the caller via the returned queue. Call +release+ on the returned queue
  # to make each holder check its connection back in and finish.
  def checkout_in_background(pool, count)
    checked_out = Queue.new
    release = Queue.new
    threads = Array.new(count) do
      Thread.new do
        conn = pool.checkout
        checked_out << conn
        release.pop
        pool.checkin
      end
    end
    conns = Array.new(count) { checked_out.pop }
    release_all = -> { conns.size.times { release << true } }
    [conns, threads, release_all]
  end

  def test_resize_grow_wakes_waiters_with_new_capacity
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 1, timeout: 5) { tracker.create }

    first = pool.checkout
    handed_out = nil
    waiter = Thread.new { pool.with { |conn| handed_out = conn } }
    sleep 0.05
    assert_nil handed_out

    pool.resize(2)

    assert waiter.join(2), "resize should wake threads waiting for a connection"
    refute_nil handed_out
    refute_same first, handed_out
    assert_equal 2, tracker.created_count

    pool.checkin
    assert_equal 2, pool.size
    assert_equal({size: 2, created: 2, idle: 2, checked_out: 0, pending_reap: 0}, pool.stats)
  end

  def test_resize_shrink_reaps_idle_connections_first
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 3) { tracker.create }

    3.times.map { Thread.new { pool.with { |conn| sleep 0.02 } } }.each(&:join)
    assert_equal 3, tracker.created_count
    assert_equal 3, pool.idle

    pool.resize(1) { |conn| tracker.destroy(conn) }

    assert_equal 2, tracker.destroyed_count
    assert_equal 1, tracker.alive_count
    assert_equal 1, pool.size
    assert_equal({size: 1, created: 1, idle: 1, checked_out: 0, pending_reap: 0}, pool.stats)
  end

  def test_resize_shrink_reaps_checked_out_connections_on_checkin
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 3) { tracker.create }

    _held, holders, release_all = checkout_in_background(pool, 2)
    pool.with { |conn| conn } # third connection, returned to the pool
    assert_equal 3, tracker.created_count
    assert_equal 1, pool.idle

    pool.resize(1) { |conn| tracker.destroy(conn) }

    # the idle connection is reaped immediately, checked out ones keep working
    assert_equal 1, tracker.destroyed_count
    assert_equal 2, pool.stats[:checked_out]
    assert_equal 1, pool.stats[:pending_reap]
    assert_equal 0, pool.available

    # one returned connection is reaped, the other becomes the new idle one
    release_all.call
    holders.each(&:join)

    assert_equal 2, tracker.destroyed_count
    assert_equal 1, tracker.alive_count
    assert_equal({size: 1, created: 1, idle: 1, checked_out: 0, pending_reap: 0}, pool.stats)
  end

  def test_resize_to_zero_drains_the_pool
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 2, timeout: 0.1) { tracker.create }

    _held, holders, release_all = checkout_in_background(pool, 1)
    pool.with { |conn| conn }
    assert_equal 2, tracker.created_count

    pool.resize(0) { |conn| tracker.destroy(conn) }

    assert_equal 1, tracker.destroyed_count
    assert_equal 0, pool.size
    assert_equal 1, pool.stats[:checked_out]
    assert_equal 1, pool.stats[:pending_reap]
    assert_raises(ConnectionPool::TimeoutError) { pool.checkout }

    release_all.call
    holders.each(&:join)

    assert_equal 2, tracker.destroyed_count
    assert_equal 0, tracker.alive_count
    assert_equal({size: 0, created: 0, idle: 0, checked_out: 0, pending_reap: 0}, pool.stats)
  end

  def test_consecutive_resizes_converge_to_latest_target
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 2, timeout: 0.1) { tracker.create }

    pool.resize(5)
    assert_equal 5, pool.size
    pool.resize(1)
    assert_equal 1, pool.size
    pool.resize(3)
    assert_equal 3, pool.size

    _held, holders, release_all = checkout_in_background(pool, 3)
    assert_equal 3, tracker.created_count
    assert_equal 3, pool.stats[:checked_out]
    assert_raises(ConnectionPool::TimeoutError) { pool.checkout }

    release_all.call
    holders.each(&:join)

    assert_equal 0, tracker.destroyed_count
    assert_equal({size: 3, created: 3, idle: 3, checked_out: 0, pending_reap: 0}, pool.stats)
  end

  def test_resize_destroy_callback_errors_do_not_corrupt_pool_state
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 3, timeout: 0.5) { tracker.create }

    _held, holders, release_all = checkout_in_background(pool, 2)
    pool.with { |conn| conn }
    assert_equal 3, tracker.created_count

    attempts = 0
    pool.resize(1) do |conn|
      attempts += 1
      raise "boom"
    end

    # the idle connection was dropped from the counts despite the callback raising
    assert_equal 1, attempts
    assert_equal 2, pool.stats[:created]
    assert_equal 1, pool.stats[:pending_reap]

    # errors while reaping a checked-in connection are swallowed too
    release_all.call
    holders.each(&:join)
    assert_equal 2, attempts
    assert_equal({size: 1, created: 1, idle: 1, checked_out: 0, pending_reap: 0}, pool.stats)

    # the pool is still fully usable
    pool.resize(2)
    2.times.map { Thread.new { pool.with { |conn| sleep 0.02 } } }.each(&:join)
    assert_equal 2, pool.stats[:created]
    assert_equal 2, pool.stats[:idle]
  end

  def test_resize_while_connections_are_being_created_never_exceeds_capacity
    tracker = ConnectionTracker.new
    create_gate = Queue.new
    pool = ConnectionPool.new(size: 2, timeout: 0.1) do
      create_gate.pop
      tracker.create
    end

    creator = Thread.new { pool.checkout }
    sleep 0.05 # creator is now blocked inside the create block
    resizer = Thread.new { pool.resize(1) }
    sleep 0.05 # resizer waits for the in-progress creation to finish

    create_gate << true
    creator.join
    resizer.join

    assert_equal 1, tracker.created_count
    assert_equal 1, pool.stats[:size]
    assert_equal 1, pool.stats[:created]
    assert_raises(ConnectionPool::TimeoutError) { pool.checkout }
  end

  def test_resize_and_shutdown_do_not_corrupt_counts
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 4) { tracker.create }
    4.times.map { Thread.new { pool.with { |conn| sleep 0.02 } } }.each(&:join)
    assert_equal 4, pool.idle

    shutdown_done = Queue.new
    Thread.new do
      pool.shutdown { |conn| tracker.destroy(conn) }
      shutdown_done << true
    end
    pool.resize(2) { |conn| tracker.destroy(conn) }
    shutdown_done.pop

    assert_equal 4, tracker.destroyed_count
    assert_equal 0, tracker.alive_count
    stats = pool.stats
    assert_equal 0, stats[:created]
    assert_equal 0, stats[:idle]
    assert_equal 0, stats[:pending_reap]
    assert_raises(ConnectionPool::PoolShuttingDownError) { pool.checkout }
  end

  def test_resize_rejects_negative_sizes
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 2) { tracker.create }

    assert_raises(ArgumentError) { pool.resize(-1) }
    assert_equal 2, pool.size
    assert_equal 2, pool.stats[:size]
  end

  def test_stats_distinguishes_capacity_checked_out_and_pending_reap
    tracker = ConnectionTracker.new
    pool = ConnectionPool.new(size: 3) { tracker.create }
    assert_equal({size: 3, created: 0, idle: 0, checked_out: 0, pending_reap: 0}, pool.stats)

    _held, holders, release_all = checkout_in_background(pool, 2)
    assert_equal({size: 3, created: 2, idle: 0, checked_out: 2, pending_reap: 0}, pool.stats)

    pool.resize(1)
    assert_equal({size: 1, created: 2, idle: 0, checked_out: 2, pending_reap: 1}, pool.stats)

    release_all.call
    holders.each(&:join)
    assert_equal({size: 1, created: 1, idle: 1, checked_out: 0, pending_reap: 0}, pool.stats)
  end
end
