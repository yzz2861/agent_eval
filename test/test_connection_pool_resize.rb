require_relative "helper"

class TestConnectionPoolResize < Minitest::Test
  class TrackedConnection
    attr_reader :id

    def initialize(id, state)
      @id = id
      @state = state
    end

    def close
      raise "close failed for #{@id}" if @state.fetch(:fail_close).include?(@id)

      @state.fetch(:mutex).synchronize do
        @state.fetch(:events) << [:close, @id]
      end
    end
  end

  def setup
    @mutex = Thread::Mutex.new
    @events = []
    @next_id = 0
    @state = {
      mutex: @mutex,
      events: @events,
      fail_close: []
    }
  end

  def wait_until
    deadline = Time.now + 2

    loop do
      result = yield
      return result if result
      raise "timed out waiting for condition" if Time.now >= deadline

      Thread.pass
    end
  end

  def tracked_factory
    proc do
      id = @mutex.synchronize { @next_id += 1 }
      TrackedConnection.new(id, @state)
    end
  end

  def tracked_pool(size: 2, timeout: 1, factory: nil, **options)
    ConnectionPool.new(size: size, timeout: timeout, **options, &(factory || tracked_factory))
  end

  def events
    @mutex.synchronize { @events.dup }
  end

  def closed_ids
    events.filter_map { |event, id| id if event == :close }
  end

  def borrow(pool, **kwargs)
    loan = start_borrow(pool, **kwargs)
    loan[:connection] = loan[:ready].pop
    loan
  end

  def start_borrow(pool, **kwargs)
    ready = Thread::Queue.new
    release = Thread::Queue.new
    errors = Thread::Queue.new
    thread = Thread.new do
      begin
        pool.with(**kwargs) do |connection|
          ready << connection
          release.pop
        end
      rescue => error
        errors << error
      end
    end

    {
      thread: thread,
      ready: ready,
      connection: nil,
      release: release,
      errors: errors
    }
  end

  def give_back(loan)
    loan[:release] << true
    loan[:thread].join
  end

  def test_resize_up_wakes_waiter
    pool = tracked_pool(size: 1)
    first = borrow(pool)
    waiter = start_borrow(pool, timeout: 2)
    wait_until { waiter[:thread].status == "sleep" }

    assert_equal({target_size: 1, checked_out: 1, pending_reaping: 0}, pool.stats)

    assert_equal 2, pool.resize(2) { |connection| connection.close }
    second = waiter[:ready].pop

    assert_equal 2, pool.size
    assert_equal 2, pool.checked_out
    assert_equal 0, pool.pending_reaping
    assert_equal 0, pool.available
    assert_equal [], closed_ids

    give_back(first)
    waiter[:release] << true
    waiter[:thread].join

    assert_equal 2, pool.idle
    refute_same first[:connection], second
  end

  def test_resize_up_wakes_multiple_waiters
    creation_started = Thread::Queue.new
    allow_creation = Thread::Queue.new
    creation_mutex = Thread::Mutex.new
    created_count = 0
    factory = proc do
      creation_mutex.synchronize { created_count += 1 }
      creation_started << true
      allow_creation.pop
      tracked_factory.call
    end
    stack = ConnectionPool::TimedStack.new(size: 0, &factory)

    threads = Array.new(3) do
      Thread.new { stack.pop(timeout: 2) }
    end
    wait_until { threads.all? { |thread| thread.status == "sleep" } }

    stack.resize(3) { |connection| connection.close }

    creation_started.pop
    assert_equal 1, created_count

    3.times { allow_creation << true }
    connections = threads.map(&:value)

    2.times { creation_started.pop }

    assert_equal 3, connections.uniq.size
    assert_equal 3, connections.size

    connections.each { |connection| stack.push(connection) }

    assert_equal 3, stack.idle
    assert_equal 0, stack.pending_reaping
  end

  def test_resize_down_removes_idle_now_and_borrowed_on_return
    pool = tracked_pool(size: 2)
    first = borrow(pool)
    second = borrow(pool)
    pool.resize(3) { |connection| connection.close }
    third = borrow(pool)

    assert_raises(ArgumentError) do
      pool.resize(-1) { |connection| connection.close }
    end

    pool.resize(1) { |connection| connection.close }

    assert_equal 3, pool.checked_out
    assert_equal 2, pool.pending_reaping
    assert_equal 0, pool.idle

    give_back(third)
    assert_equal [third[:connection].id], closed_ids
    assert_equal 2, pool.checked_out
    assert_equal 1, pool.pending_reaping

    give_back(second)
    assert_equal [third[:connection].id, second[:connection].id], closed_ids

    assert_equal 1, pool.checked_out
    assert_equal 0, pool.pending_reaping

    give_back(first)

    assert_equal 0, pool.checked_out
    assert_equal 0, pool.pending_reaping
    assert_equal(
      [third[:connection].id, second[:connection].id],
      closed_ids
    )

    replacement = pool.checkout
    assert_same first[:connection], replacement
    pool.checkin
  end

  def test_resize_to_zero_reclaims_connections_on_checkin
    pool = tracked_pool(size: 2)
    first = borrow(pool)
    second = borrow(pool)

    pool.resize(0) { |connection| connection.close }

    assert_equal 0, pool.size
    assert_equal 2, pool.checked_out
    assert_equal 2, pool.pending_reaping
    assert_raises(ConnectionPool::TimeoutError) { pool.checkout(timeout: 0) }

    give_back(second)

    assert_equal 1, pool.checked_out
    assert_equal 1, pool.pending_reaping
    assert_equal [second[:connection].id], closed_ids

    give_back(first)

    assert_equal 0, pool.checked_out
    assert_equal 0, pool.pending_reaping
    assert_equal [second[:connection].id, first[:connection].id], closed_ids

    pool.resize(1)
    replacement = pool.checkout
    refute_equal first[:connection].id, replacement.id
    pool.checkin
  end

  def test_repeated_resize_keeps_counts_consistent
    pool = tracked_pool(size: 3)
    first = borrow(pool)
    second = borrow(pool)
    third = borrow(pool)

    pool.resize(0) { |connection| connection.close }
    assert_equal({target_size: 0, checked_out: 3, pending_reaping: 3}, pool.stats)

    pool.resize(3) { |connection| connection.close }
    assert_equal({target_size: 3, checked_out: 3, pending_reaping: 0}, pool.stats)

    pool.resize(1) { |connection| connection.close }
    assert_equal({target_size: 1, checked_out: 3, pending_reaping: 2}, pool.stats)

    give_back(third)
    assert_equal [third[:connection].id], closed_ids
    assert_equal 2, pool.checked_out
    assert_equal 1, pool.pending_reaping

    pool.resize(0) { |connection| connection.close }
    assert_equal 2, pool.pending_reaping

    give_back(second)
    assert_equal [third[:connection].id, second[:connection].id], closed_ids

    waiter = start_borrow(pool, timeout: 2)
    wait_until { waiter[:thread].status == "sleep" }

    pool.resize(2) { |connection| connection.close }
    replacement = waiter[:ready].pop
    assert_equal 0, pool.pending_reaping

    give_back(first)
    waiter[:release] << true
    waiter[:thread].join
    assert_equal 2, pool.idle
    refute_same first[:connection], replacement
  end

  def test_connection_being_created_during_shutdown_is_reclaimed
    creation_started = Thread::Queue.new
    allow_creation = Thread::Queue.new
    checkout_errors = Thread::Queue.new
    factory = proc do
      creation_started << true
      allow_creation.pop
      tracked_factory.call
    end
    pool = tracked_pool(size: 1, factory: factory)

    checkout_thread = Thread.new do
      begin
        pool.checkout
      rescue => error
        checkout_errors << error
      end
    end
    creation_started.pop

    pool.resize(0) { |connection| connection.close }
    assert_equal 0, pool.size
    assert_equal 0, pool.checked_out
    assert_equal 1, pool.pending_reaping

    shutdown_thread = Thread.new do
      pool.shutdown { |connection| connection.close }
    end
    wait_until { shutdown_thread.status == "sleep" }

    allow_creation << true

    assert_kind_of ConnectionPool::PoolShuttingDownError, checkout_errors.pop
    shutdown_thread.join

    assert_equal [1], closed_ids
    assert_equal 0, pool.idle
    assert_equal 0, pool.checked_out
    assert_equal 0, pool.pending_reaping
    assert_raises(ConnectionPool::PoolShuttingDownError) { pool.checkout }
  end

  def test_connection_created_after_resize_to_zero_is_destroyed_even_when_close_raises
    creation_started = Thread::Queue.new
    allow_creation = Thread::Queue.new
    second_creation = false
    factory = proc do
      creation_started << true
      if second_creation
        tracked_factory.call
      else
        second_creation = true
        allow_creation.pop
        tracked_factory.call
      end
    end
    pool = tracked_pool(size: 1, factory: factory)

    checkout_errors = Thread::Queue.new
    checkout_thread = Thread.new do
      begin
        pool.checkout
      rescue => error
        checkout_errors << error
      end
    end
    creation_started.pop

    pool.resize(0) { |connection| connection.close }
    assert_equal 1, pool.pending_reaping

    @state[:fail_close] = [1]
    allow_creation << true

    error = checkout_errors.pop
    assert_equal "close failed for 1", error.message

    assert_equal 0, pool.size
    assert_equal 0, pool.checked_out
    assert_equal 0, pool.pending_reaping

    pool.resize(1)
    replacement = pool.checkout
    assert_equal 2, replacement.id
    pool.checkin
  end

  def test_resize_remains_usable_after_immediate_close_error
    pool = tracked_pool(size: 2)
    first = borrow(pool)
    second = borrow(pool)
    give_back(second)
    give_back(first)

    @state[:fail_close] = [first[:connection].id]

    error = assert_raises(RuntimeError) do
      pool.resize(1) { |connection| connection.close }
    end
    assert_match(/close failed for \d/, error.message)

    assert_equal 1, pool.size
    assert_equal 0, pool.checked_out
    assert_equal 0, pool.pending_reaping
    assert_equal 1, pool.idle

    replacement = pool.checkout
    assert_equal second[:connection].id, replacement.id
    pool.checkin

    pool.resize(3)
    assert_equal 1, pool.idle
  end

  def test_resize_remains_usable_after_checkin_close_error
    pool = tracked_pool(size: 2)
    first = borrow(pool)
    second = borrow(pool)

    pool.resize(0) { |connection| connection.close }
    @state[:fail_close] = [second[:connection].id]

    give_back(second)
    assert_kind_of RuntimeError, second[:errors].pop

    assert_equal 0, pool.size
    assert_equal 1, pool.checked_out
    assert_equal 1, pool.pending_reaping

    @state[:fail_close] = []
    give_back(first)
    assert_empty first[:errors]

    assert_equal 0, pool.checked_out
    assert_equal 0, pool.pending_reaping

    pool.resize(1)
    replacement = pool.checkout
    refute_equal first[:connection].id, replacement.id
    pool.checkin
  end

  def test_wrapper_exposes_runtime_resize_and_stats
    pool = tracked_pool(size: 1)
    wrapper = ConnectionPool::Wrapper.new(pool: pool)

    assert_equal({target_size: 1, checked_out: 0, pending_reaping: 0}, wrapper.pool_stats)
    assert_equal 2, wrapper.pool_resize(2)
    assert_equal 2, wrapper.pool_stats.fetch(:target_size)
  end
end
