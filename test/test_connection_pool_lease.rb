require_relative "helper"

class TestConnectionPoolLease < Minitest::Test
  def teardown
    ConnectionPool.reset_instances
  end

  def wait_until
    Timeout.timeout(2) { Thread.pass until yield }
  end

  def start_owner(pool, **lease_options)
    release = Thread::Queue.new
    lease_ref = Thread::Queue.new
    owner = Thread.new do
      pool.with do |conn|
        lease_ref << pool.lease(**lease_options)
        release.pop
        conn
      end
    end
    lease = lease_ref.pop
    wait_until { owner.status == "sleep" }
    [owner, release, lease]
  end

  def receive_in_thread(pool, lease)
    result = Thread::Queue.new
    thread = Thread.new do
      begin
        pool.accept(lease) { |conn| result << [:ok, conn] }
      rescue Exception => e # rubocop:disable Lint/SuppressedException
        result << [:error, e]
      end
    end
    [thread, result]
  end

  def test_lease_transfers_connection_to_receiver
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    owner, release, lease = start_owner(pool, timeout: 1)

    receiver = Thread.new do
      pool.accept(lease) { |conn| conn }
    end
    release << :go

    leased = owner.value
    assert_same leased, receiver.value
    assert_equal 1, pool.available

    pool.with { |conn| assert_same leased, conn }
  end

  def test_pool_remains_usable_after_receiver_finishes
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }

    3.times do
      owner, release, lease = start_owner(pool, timeout: 1)
      receiver = Thread.new { pool.accept(lease) { |conn| conn } }
      release << :go
      leased = owner.value
      assert_same leased, receiver.value
      receiver.join
      assert_equal 1, pool.available
    end

    pool.with { |conn| refute_nil conn }
  end

  def test_owner_block_returns_after_handoff
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    owner, release, lease = start_owner(pool, timeout: 1)
    receiver = Thread.new { pool.accept(lease) { :receiver_result } }

    release << :go
    assert_same owner.value, owner.value # owner joined via value
    assert_equal :receiver_result, receiver.value
  end

  def test_accept_without_block_supports_manual_checkin
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    owner, release, lease = start_owner(pool, timeout: 1)
    leased = nil
    thread = Thread.new do
      conn = pool.accept(lease)
      leased = conn
      pool.checkin
      :done
    end
    wait_until { thread.status == "sleep" }
    release << :go
    owner.join
    assert_equal :done, thread.value
    refute_nil leased
    assert_equal 1, pool.available
  end

  def test_old_owner_cannot_checkin_again_after_handoff
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    release = Thread::Queue.new
    lease_ref = Thread::Queue.new
    error_ref = Thread::Queue.new
    owner = Thread.new do
      pool.with do
        lease = pool.lease(timeout: 1)
        lease_ref << lease
        release.pop
      end
      # The handoff completed above: the former owner must not be able to
      # return (or otherwise check in) the connection a second time.
      pool.checkin
    rescue ConnectionPool::Error => e
      error_ref << e
    end
    lease = lease_ref.pop
    receiver, _result = receive_in_thread(pool, lease)
    release << :go
    owner.join
    receiver.join

    error = error_ref.pop(true)
    assert_kind_of ConnectionPool::Error, error
    assert_equal "no connections are checked out", error.message
    assert_equal 1, pool.available
  end

  def test_old_owner_loses_pool_level_access_immediately
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    key = pool.instance_variable_get(:@key)
    detached = Thread::Queue.new
    release = Thread::Queue.new
    lease_ref = Thread::Queue.new

    owner = Thread.new do
      pool.with do
        lease = pool.lease(timeout: 1)
        detached << Thread.current[key].nil?
        lease_ref << lease
        release.pop
      end
    end

    wait_until { detached.length == 1 }
    assert_equal true, detached.pop
    lease = lease_ref.pop
    receiver, _ = receive_in_thread(pool, lease)
    release << :go
    owner.join
    receiver.join
  end

  def test_lease_expires_if_not_received_and_returns_connection_once
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    leased = nil

    lease = pool.with do |conn|
      leased = conn
      pool.lease(timeout: 0.1)
    end

    wait_until { pool.available == 1 }
    assert_raises(ConnectionPool::TimeoutError) { pool.accept(lease) {} }
    pool.with { |conn| assert_same leased, conn }
  end

  def test_owner_checkin_blocks_until_offer_deadline_without_receiver
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    leased = pool.with { |c| pool.lease(timeout: 0.1); c }
    wait_until { pool.available == 1 }
    assert_equal 1, pool.available
    pool.with { |c| assert_same leased, c }
  end

  def test_owner_raising_cancels_pending_lease
    pool = ConnectionPool.new(size: 1, timeout: 2) { Object.new }
    owner, _release, lease = start_owner(pool, timeout: 2)
    wait_until { owner.status == "sleep" }

    owner.raise(RuntimeError, "boom")
    assert_raises(RuntimeError) { owner.join }

    assert_raises(ConnectionPool::Error) { pool.accept(lease) {} }
    assert_equal 1, pool.available
  end

  def test_owner_killed_cancels_pending_lease
    pool = ConnectionPool.new(size: 1, timeout: 2) { Object.new }
    owner, _release, lease = start_owner(pool, timeout: 2)
    wait_until { owner.status == "sleep" }

    owner.kill
    owner.join

    assert_raises(ConnectionPool::Error) { pool.accept(lease) {} }
    assert_equal 1, pool.available
  end

  def test_lease_can_only_be_received_once
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    owner, release, lease = start_owner(pool, timeout: 1)
    receiver, result = receive_in_thread(pool, lease)
    wait_until { receiver.status == "sleep" }

    release << :go
    receiver.join
    assert_equal :ok, result.pop.first

    assert_raises(ConnectionPool::LeaseError) { pool.accept(lease) {} }
    assert_equal 1, pool.available
    owner.join
  end

  def test_concurrent_receivers_only_one_wins
    pool = ConnectionPool.new(size: 1, timeout: 2) { Object.new }
    owner, release, lease = start_owner(pool, timeout: 2)
    outcomes = Thread::Queue.new
    started = Thread::Queue.new

    threads = Array.new(4) do
      Thread.new do
        started << :ready
        pool.accept(lease) { outcomes << :win }
      rescue ConnectionPool::Error
        outcomes << :lose
      end
    end
    4.times { started.pop }
    release << :go
    threads.each(&:join)
    owner.join

    results = Array.new(4) { outcomes.pop }
    assert_equal [:win], results.grep(:win)
    assert_equal 3, results.count(:lose)
    assert_equal 1, pool.available
  end

  def test_owner_thread_cannot_receive_its_own_lease
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }

    pool.with do
      lease = pool.lease(timeout: 0.1)
      assert_raises(ConnectionPool::LeaseError) { pool.accept(lease) {} }
    end
  end

  def test_lease_without_checkout_raises
    pool = ConnectionPool.new(size: 1) { Object.new }
    assert_raises(ConnectionPool::LeaseError) { pool.lease }
  end

  def test_lease_forbidden_inside_nested_checkout
    pool = ConnectionPool.new(size: 1) { Object.new }
    pool.with do
      pool.with do
        assert_raises(ConnectionPool::LeaseError) { pool.lease }
      end
    end
  end

  def test_cannot_offer_second_pending_lease
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    release = Thread::Queue.new
    pool.with do
      pool.lease(timeout: 1)
      assert_raises(ConnectionPool::LeaseError) { pool.lease(timeout: 1) }
      release << :done
    end
  end

  def test_accept_rejects_lease_from_another_pool
    pool_a = ConnectionPool.new(size: 1) { Object.new }
    pool_b = ConnectionPool.new(size: 1) { Object.new }
    owner, release, lease = start_owner(pool_a, timeout: 1)

    assert_raises(ConnectionPool::LeaseError) { pool_b.accept(lease) {} }
    release << :go
    owner.join
  end

  def test_receiver_discard_is_honored
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    owner, release, lease = start_owner(pool, timeout: 1)
    receiver = Thread.new do
      pool.accept(lease) { pool.discard_current_connection }
    end
    wait_until { receiver.status == "sleep" }

    release << :go
    owner.join
    receiver.join

    assert_equal 0, pool.idle
    assert_equal 1, pool.available
  end

  def test_expired_lease_honors_owner_discard_marker
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }

    pool.with do
      pool.discard_current_connection
      pool.lease(timeout: 0.05)
    end

    assert_equal 0, pool.idle
    assert_equal 1, pool.available
  end
end
