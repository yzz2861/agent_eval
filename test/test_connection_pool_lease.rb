require_relative "helper"

class TestConnectionPoolLease < Minitest::Test
  def teardown
    ConnectionPool.reset_instances
  end

  def wait_until(timeout = 2)
    deadline = Time.now + timeout
    Thread.pass until yield || Time.now > deadline
    assert yield, "condition not met within #{timeout}s"
  end

  def test_lease_returns_a_lease
    pool = ConnectionPool.new(size: 1) { Object.new }
    lease = pool.lease

    assert_kind_of ConnectionPool::Lease, lease
    assert_same pool, lease.pool
  end

  def test_transfer_moves_ownership_to_new_thread
    pool = ConnectionPool.new(size: 1, timeout: 2) { Object.new }
    lease = pool.lease
    received = Queue.new
    returned = Queue.new

    receiver = Thread.new do
      lease.receive do |conn|
        received << conn
        returned.pop
      end
    end

    handed = pool.with do |conn|
      pool.transfer(lease)
      conn
    end

    assert_same handed, received.pop
    assert_equal 0, pool.available

    returned << :done
    receiver.join

    assert_equal 1, pool.available
    pool.with { |conn| assert_same handed, conn }
  end

  def test_owner_first_then_receiver
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    ready = Queue.new
    result = Queue.new

    owner = Thread.new do
      pool.with do |conn|
        ready << :ready
        pool.transfer(lease)
        result << conn
      end
    end

    ready.pop
    got = Queue.new
    receiver = Thread.new { lease.receive { |conn| got << conn } }

    assert_same result.pop, got.pop
    owner.join
    receiver.join
    assert_equal 1, pool.available
  end

  def test_receive_without_block_checkout_and_checkin
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    connection = pool.checkout

    got = Queue.new
    receiver = Thread.new do
      conn = lease.receive
      got << conn
      sleep 0.02
      pool.checkin
    end

    pool.transfer(lease)
    assert_same connection, got.pop
    assert_raises ConnectionPool::LeaseError do
      pool.checkin
    end
    receiver.join
    assert_equal 1, pool.available
  end

  def test_old_owner_cannot_checkin_after_transfer
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    receiver = Thread.new { lease.receive { |_| sleep 0.1 } }

    pool.with do
      pool.transfer(lease)
      assert_raises ConnectionPool::LeaseError do
        pool.checkin
      end
    end

    receiver.join
    assert_equal 1, pool.available
  end

  def test_old_owner_checkout_is_gone_after_transfer
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    receiver = Thread.new { lease.receive { |_| } }

    pool.with do
      pool.transfer(lease)
      assert_nil Thread.current[pool.instance_variable_get(:@key)]
      assert_nil Thread.current[pool.instance_variable_get(:@key_count)]
    end

    receiver.join
  end

  def test_resource_returned_exactly_once
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    returned = Queue.new
    receiver = Thread.new do
      lease.receive { returned << :received }
    end

    pool.with { pool.transfer(lease) }
    receiver.join

    assert_equal 1, pool.available
    20.times { pool.with { |_| } }
    assert_equal 1, pool.available
  end

  def test_receiver_timeout
    pool = ConnectionPool.new(size: 1, timeout: 0.05) { Object.new }
    lease = pool.lease(timeout: 0.05)
    error = Queue.new
    receiver = Thread.new do
      begin
        lease.receive
      rescue => e
        error << e
      end
    end

    assert_kind_of ConnectionPool::TimeoutError, error.pop
    receiver.join
    assert_equal 1, pool.available

    owner_error = Queue.new
    pool.with do
      begin
        pool.transfer(lease, timeout: 0.01)
      rescue => e
        owner_error << e
      end
    end
    # The receiver already timed the lease out; the owner observes a failure
    # (its own timeout or the abandoned lease) and keeps the connection.
    error = owner_error.pop
    assert(error.is_a?(ConnectionPool::TimeoutError) || error.is_a?(ConnectionPool::LeaseError))
    assert_equal 1, pool.available
  end

  def test_owner_timeout_retains_connection
    pool = ConnectionPool.new(size: 1, timeout: 0.05) { Object.new }
    lease = pool.lease

    assert_raises ConnectionPool::TimeoutError do
      pool.with { pool.transfer(lease, timeout: 0.02) }
    end

    assert_equal 1, pool.available
    pool.with { |conn| refute_nil conn }
  end

  def test_owner_killed_after_checkout_before_transfer
    pool = ConnectionPool.new(size: 1, timeout: 0.2) { Object.new }
    lease = pool.lease(timeout: 0.2)
    error = Queue.new
    receiver = Thread.new do
      begin
        lease.receive
      rescue => e
        error << e
      end
    end

    owner = Thread.new { pool.with { sleep 1 } }
    wait_until { pool.available == 0 }
    owner.kill
    owner.join

    # The owner never offered the connection, so the receiver times out.
    assert_kind_of ConnectionPool::TimeoutError, error.pop
    receiver.join
  end

  def test_owner_interrupted_during_transfer_keeps_connection
    pool = ConnectionPool.new(size: 1, timeout: 2) { Object.new }
    lease = pool.lease
    owner_error = Queue.new
    owner = Thread.new do
      begin
        pool.with { pool.transfer(lease, timeout: 2) }
      rescue => e
        owner_error << e
      end
    end

    wait_until { lease.instance_variable_get(:@owner) == owner }
    owner.raise(RuntimeError, "boom")
    assert_equal "boom", owner_error.pop.message
    owner.join
    assert_equal 1, pool.available
  end

  def test_receiver_killed_during_wait_fails_hand_off
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    receiver = Thread.new { lease.receive }
    wait_until { lease.instance_variable_get(:@receiver) == receiver }

    owner_error = Queue.new
    owner = Thread.new do
      begin
        pool.with { pool.transfer(lease, timeout: 1) }
      rescue => e
        owner_error << e
      end
    end

    receiver.kill
    receiver.join
    error = owner_error.pop
    assert_kind_of ConnectionPool::Error, error
    owner.join
    assert_equal 1, pool.available
  end

  def test_receiver_raised_during_wait_fails_hand_off
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease(timeout: 1)
    receiver_error = Queue.new
    receiver = Thread.new do
      begin
        lease.receive
      rescue => e
        receiver_error << e
      end
    end
    wait_until { lease.instance_variable_get(:@receiver) == receiver }

    owner_error = Queue.new
    owner = Thread.new do
      begin
        pool.with { pool.transfer(lease, timeout: 1) }
      rescue => e
        owner_error << e
      end
    end

    receiver.raise(RuntimeError, "receiver boom")
    assert_equal "receiver boom", receiver_error.pop.message
    assert_kind_of ConnectionPool::LeaseError, owner_error.pop
    owner.join
    assert_equal 1, pool.available
  end

  def test_duplicate_receive_fails_immediately
    pool = ConnectionPool.new(size: 1, timeout: 2) { Object.new }
    lease = pool.lease
    first = Thread.new { lease.receive { |_| } }
    wait_until { lease.instance_variable_get(:@receiver) == first }

    second_error = Thread.new do
      begin
        lease.receive
      rescue => e
        e
      end
    end.value
    assert_kind_of ConnectionPool::LeaseError, second_error

    pool.with { pool.transfer(lease) }
    first.join
    assert_equal 1, pool.available
  end

  def test_receive_twice_from_same_receiver_fails
    pool = ConnectionPool.new(size: 1, timeout: 2) { Object.new }
    lease = pool.lease(timeout: 2)
    receiver = Thread.new do
      lease.receive do
        assert_raises ConnectionPool::LeaseError do
          lease.receive
        end
      end
    end
    wait_until { lease.instance_variable_get(:@receiver) == receiver }
    pool.with { pool.transfer(lease) }
    receiver.join
  end

  def test_transfer_with_nested_checkout_forbidden
    pool = ConnectionPool.new(size: 1, timeout: 0.05) { Object.new }
    lease = pool.lease
    error = nil
    pool.with do
      pool.with do
        error = assert_raises ConnectionPool::LeaseError do
          pool.transfer(lease, timeout: 0.01)
        end
      end
    end
    assert_match(/owned/, error.message)
    assert_equal 1, pool.available
  end

  def test_transfer_without_checkout_raises
    pool = ConnectionPool.new(size: 1) { Object.new }
    lease = pool.lease

    assert_raises ConnectionPool::LeaseError do
      pool.transfer(lease)
    end
  end

  def test_transfer_lease_from_other_pool_raises
    pool_a = ConnectionPool.new(size: 1) { Object.new }
    pool_b = ConnectionPool.new(size: 1) { Object.new }
    lease = pool_b.lease

    pool_a.with do
      assert_raises ConnectionPool::LeaseError do
        pool_a.transfer(lease)
      end
    end
  end

  def test_receive_lease_from_other_pool_raises
    pool_a = ConnectionPool.new(size: 1) { Object.new }
    pool_b = ConnectionPool.new(size: 1) { Object.new }
    lease = pool_b.lease

    error = Thread.new do
      begin
        pool_a.send(:accept_lease, lease, 0.01)
      rescue => e
        e
      end
    end.value
    assert_kind_of ConnectionPool::LeaseError, error
  end

  def test_transfer_twice_fails
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    receiver = Thread.new { lease.receive { |_| } }

    pool.with do
      pool.transfer(lease)
      assert_raises ConnectionPool::LeaseError do
        pool.transfer(lease)
      end
    end
    receiver.join
  end

  def test_pool_reusable_after_lease_completes
    pool = ConnectionPool.new(size: 2, timeout: 1) { Object.new }

    5.times do
      lease = pool.lease
      got = Queue.new
      receiver = Thread.new { lease.receive { |c| got << c } }
      pool.with { |conn| pool.transfer(lease) }
      assert got.pop
      receiver.join
    end

    assert_equal 2, pool.available
  end

  def test_with_block_continues_to_work_normally
    pool = ConnectionPool.new(size: 1) { Object.new }
    result = pool.with { |c| c }
    refute_nil result
    pool.with do |c|
      pool.with { |inner| assert_same c, inner }
    end
    assert_equal 1, pool.available
  end

  def test_discard_intent_transfers_with_connection
    pool = ConnectionPool.new(size: 1, timeout: 1) { Object.new }
    lease = pool.lease
    discarded = Queue.new
    release = Queue.new
    receiver = Thread.new do
      lease.receive do
        release.pop
      end
    end

    pool.with do
      pool.discard_current_connection { |_| discarded << :discarded }
      pool.transfer(lease)
    end
    release << :done
    receiver.join

    assert_equal :discarded, discarded.pop
    assert_equal 0, pool.idle
    assert_equal 1, pool.available
  end
end
