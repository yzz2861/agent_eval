require "timeout"
require_relative "connection_pool/version"

class ConnectionPool
  class Error < ::RuntimeError; end

  class PoolShuttingDownError < ::ConnectionPool::Error; end

  class TimeoutError < ::Timeout::Error; end
end

# Generic connection pool class for sharing a limited number of objects or network connections
# among many threads.  Note: pool elements are lazily created.
#
# Example usage with block (faster):
#
#    @pool = ConnectionPool.new { Redis.new }
#    @pool.with do |redis|
#      redis.lpop('my-list') if redis.llen('my-list') > 0
#    end
#
# Using optional timeout override (for that single invocation)
#
#    @pool.with(timeout: 2.0) do |redis|
#      redis.lpop('my-list') if redis.llen('my-list') > 0
#    end
#
# Example usage replacing an existing connection (slower):
#
#    $redis = ConnectionPool.wrap { Redis.new }
#
#    def do_work
#      $redis.lpop('my-list') if $redis.llen('my-list') > 0
#    end
#
# Accepts the following options:
# - :size - number of connections to pool, defaults to 5
# - :timeout - amount of time to wait for a connection if none currently available, defaults to 5 seconds
# - :auto_reload_after_fork - automatically drop all connections after fork, defaults to true
#
class ConnectionPool
  def self.wrap(**kwargs, &block)
    Wrapper.new(**kwargs, &block)
  end

  attr_reader :size

  def initialize(timeout: 5, size: 5, auto_reload_after_fork: true, name: nil, &block)
    raise ArgumentError, "Connection pool requires a block" unless block_given?

    @size = Integer(size)
    raise ArgumentError, "Connection pool size cannot be negative" if @size.negative?

    @timeout = Float(timeout)
    @available = TimedStack.new(size: @size, &block)
    @key = :"pool-#{@available.object_id}"
    @key_count = :"pool-#{@available.object_id}-count"
    @key_kwargs = :"pool-#{@available.object_id}-kwargs"
    @discard_key = :"pool-#{@available.object_id}-discard"
    @lease_key = :"pool-#{@available.object_id}-lease"
    @lease_aborting_key = :"pool-#{@available.object_id}-lease-aborting"
    INSTANCES[self] = self if auto_reload_after_fork && INSTANCES
  end

  def with(**kwargs)
    # We need to manage exception handling manually here in order
    # to work correctly with `Timeout.timeout` and `Thread#raise`.
    # Otherwise an interrupted Thread can leak connections.
    Thread.handle_interrupt(Exception => :never) do
      conn = checkout(**kwargs)
      begin
        Thread.handle_interrupt(Exception => :immediate) do
          yield conn
        end
      rescue Exception
        ::Thread.current[@lease_aborting_key] = true
        raise
      ensure
        checkin
      end
    end
  end
  alias_method :then, :with

  ##
  # Offers the connection currently checked out by the calling thread for a
  # one-time transfer to another thread. The connection is detached from the
  # current owner immediately: it can no longer be accessed or checked back in
  # through the pool by that thread. The returned ConnectionPool::Lease object
  # can be passed to another thread, which receives ownership with #accept.
  #
  # The handoff is completed when the connection is checked in (e.g. at the end
  # of the enclosing +with+ block): the checkin blocks until another thread
  # accepts the lease or until +timeout+ seconds have elapsed. If the lease is
  # not accepted in time, or the owning thread raises or is killed before the
  # handoff completes, the connection is returned to the pool exactly once and
  # the lease becomes invalid.
  #
  # Transfers are not allowed inside nested checkouts because the resource
  # would otherwise have more than one possible owner. Borrow with a single
  # +with+ block (or a single +checkout+) before offering it.
  #
  # @param timeout [Numeric] maximum seconds the owner waits for a receiver
  # @return [ConnectionPool::Lease]
  #
  # @example
  #   lease = pool.with { |conn| pool.lease }
  #   Thread.new do
  #     pool.accept(lease) { |conn| conn.do_work }
  #   end.join
  def lease(timeout: @timeout)
    if ::Thread.current[@lease_key]
      raise ConnectionPool::LeaseError, "a lease is already pending for this thread"
    end
    raise ConnectionPool::LeaseError, "no connections are checked out" unless ::Thread.current[@key]
    unless ::Thread.current[@key_count] == 1
      raise ConnectionPool::LeaseError, "cannot transfer a connection that is part of a nested checkout"
    end

    conn = ::Thread.current[@key]
    kwargs = ::Thread.current[@key_kwargs]
    discard = ::Thread.current[@discard_key]
    ::Thread.current[@discard_key] = nil
    ::Thread.current[@key] = nil
    ::Thread.current[@key_count] = nil
    ::Thread.current[@key_kwargs] = nil
    lease = ConnectionPool::Lease.new(self, conn, kwargs, Float(timeout), discard)
    ::Thread.current[@lease_key] = lease
    lease
  end

  ##
  # Receives a connection previously offered with ConnectionPool#lease by
  # another thread. This must be called by a thread other than the one that
  # created the lease and each lease can only be received once.
  #
  # Blocks until the owner completes the handoff. Raises
  # ConnectionPool::TimeoutError if the lease expires before the owner hands
  # the connection over, ConnectionPool::Error if the owner cancelled the
  # offer, and ConnectionPool::LeaseError for an invalid or already received
  # lease.
  #
  # When given a block, the received connection is checked back into the pool
  # automatically when the block finishes, just like #with. Without a block the
  # connection is returned and must be checked in manually with #checkin.
  #
  # @param lease [ConnectionPool::Lease] the lease to receive
  # @param timeout [Numeric] maximum seconds to wait for the handoff
  # @yield [conn]
  def accept(lease, timeout: @timeout)
    raise ConnectionPool::LeaseError, "expected a ConnectionPool::Lease" unless lease.is_a?(ConnectionPool::Lease)
    raise ConnectionPool::LeaseError, "lease belongs to a different pool" unless lease.pool.equal?(self)
    raise ConnectionPool::LeaseError, "a lease must be received by a different thread" if ::Thread.current[@key]

    if block_given?
      receive_lease(lease, timeout:)
      begin
        Thread.handle_interrupt(Exception => :immediate) do
          yield ::Thread.current[@key]
        end
      ensure
        checkin
      end
    else
      receive_lease(lease, timeout:)
    end
  end

  ##
  # Marks the current thread's checked-out connection for discard.
  #
  # When a connection is marked for discard, it will not be returned to the pool
  # when checked in. Instead, the connection will be discarded.
  # This is useful when a connection has become invalid or corrupted
  # and should not be reused.
  #
  # Takes an optional block that will be called with the connection to be discarded.
  # The block should perform any necessary clean-up on the connection.
  #
  # @yield [conn]
  # @yieldparam conn [Object] The connection to be discarded.
  # @yieldreturn [void]
  #
  #
  # Note: This only affects the connection currently checked out by the calling thread.
  # The connection will be discarded when +checkin+ is called.
  #
  # @return [void]
  #
  # @example
  #   pool.with do |conn|
  #     begin
  #       conn.execute("SELECT 1")
  #     rescue SomeConnectionError
  #       pool.discard_current_connection  # Mark connection as bad
  #       raise
  #     end
  #   end
  def discard_current_connection(&block)
    ::Thread.current[@discard_key] = block || proc { |conn| conn }
  end

  def checkout(timeout: @timeout, **kwargs)
    if ::Thread.current[@key]
      ::Thread.current[@key_count] += 1
      ::Thread.current[@key]
    else
      conn = @available.pop(timeout:, **kwargs)
      ::Thread.current[@key] = conn
      ::Thread.current[@key_count] = 1
      ::Thread.current[@key_kwargs] = kwargs
      conn
    end
  end

  private

  def receive_lease(lease, timeout:)
    conn = Thread.handle_interrupt(Exception => :never) do
      lease.claim(timeout:).tap do
        ::Thread.current[@key] = lease.conn
        ::Thread.current[@key_count] = 1
        ::Thread.current[@key_kwargs] = lease.kwargs
        ::Thread.current[@discard_key] = lease.take_discard!
      end
    end
    conn
  end

  def return_checked_out_connection
    if ::Thread.current[@discard_key]
      begin
        @available.decrement_created
        ::Thread.current[@discard_key].call(::Thread.current[@key])
      rescue
        nil
      ensure
        ::Thread.current[@discard_key] = nil
      end
    else
      @available.push(::Thread.current[@key], **::Thread.current[@key_kwargs])
    end
  ensure
    ::Thread.current[@key] = nil
    ::Thread.current[@key_count] = nil
    ::Thread.current[@key_kwargs] = nil
    ::Thread.current[@lease_aborting_key] = nil
    nil
  end

  def restore_leased_connection(lease)
    unless ::Thread.current[@key]
      ::Thread.current[@key] = lease.conn
      ::Thread.current[@key_count] = 1
      ::Thread.current[@key_kwargs] = lease.kwargs
      if (discard = lease.take_discard!)
        ::Thread.current[@discard_key] = discard
      end
    end
  end
  public

  def checkin(force: false)
    lease = ::Thread.current[@lease_key]
    if lease
      # The owner detached the connection via #lease; rendezvous with the
      # receiver instead of touching the pool directly.
      ::Thread.current[@lease_key] = nil
      if force
        # Forced checkin (e.g. after fork) cannot wait for another thread to
        # receive: cancel the offer and return the connection at once.
        lease.cancel_owner
        restore_leased_connection(lease)
        return_checked_out_connection
        return nil
      end
      transferred = false
      handled = false
      begin
        state =
          if ::Thread.current[@lease_aborting_key] || ::Thread.current.status == "aborting"
            lease.cancel_owner
          else
            lease.release_owner
          end
        if state == :claimed
          # Ownership is transferred; release the receiver and never touch the
          # connection on this thread again.
          lease.complete_release!
          transferred = true
        else
          # Offer expired or was cancelled: restore the owner's checkout state
          # so the common return path below returns the connection exactly
          # once, including any pending discard marker.
          restore_leased_connection(lease)
          return_checked_out_connection
          handled = true
          return nil
        end
      ensure
        if !transferred && !handled && ::Thread.current.status == "aborting"
          # Thread#kill can unwind the stack straight here, even from inside
          # the rendezvous wait. Cancel any still-pending offer and reinstall
          # the connection so it is returned to the pool exactly once.
          lease.cancel_owner
          restore_leased_connection(lease)
          return_checked_out_connection
        end
      end

      return nil if transferred
    elsif ::Thread.current[@key]
      if ::Thread.current[@key_count] != 1 && !force
        ::Thread.current[@key_count] -= 1
        return nil
      end
    elsif force
      return nil
    else
      raise ConnectionPool::Error, "no connections are checked out"
    end

    return_checked_out_connection
  end

  ##
  # Shuts down the ConnectionPool by passing each connection to +block+ and
  # then removing it from the pool. Attempting to checkout a connection after
  # shutdown will raise +ConnectionPool::PoolShuttingDownError+.
  def shutdown(&block)
    @available.shutdown(&block)
  end

  ##
  # Reloads the ConnectionPool by passing each connection to +block+ and then
  # removing it the pool. Subsequent checkouts will create new connections as
  # needed.
  def reload(&block)
    @available.shutdown(reload: true, &block)
  end

  ## Reaps idle connections that have been idle for over +idle_seconds+.
  # +idle_seconds+ defaults to 60.
  def reap(idle_seconds: 60, &block)
    @available.reap(idle_seconds:, &block)
  end

  # Number of pool entries available for checkout at this instant.
  def available
    @available.length
  end

  # Number of pool entries created and idle in the pool.
  def idle
    @available.idle
  end
end

require_relative "connection_pool/timed_stack"
require_relative "connection_pool/lease"
require_relative "connection_pool/wrapper"
require_relative "connection_pool/fork"
