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
    @key_leased = :"pool-#{@available.object_id}-leased"
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
      ensure
        checkin unless ::Thread.current[@key_leased]
      end
    end
  end
  alias_method :then, :with

  ##
  # Creates a pending {ConnectionPool::Lease} used to transfer ownership of a
  # single checked-out connection from the current owner to another thread.
  #
  # The lease is only a rendezvous point: no connection moves until the
  # current owner calls #transfer and the new owner calls
  # {ConnectionPool::Lease#receive}. See {ConnectionPool::Lease} for the full
  # usage pattern and failure semantics.
  #
  # @param timeout [Numeric] default time the new owner waits for the transfer
  # @return [ConnectionPool::Lease]
  def lease(timeout: @timeout)
    Lease.new(self, timeout:)
  end

  ##
  # Transfers ownership of the connection currently checked out by the
  # calling thread to the new owner waiting on +lease+.
  #
  # This is the owner side of a lease handoff and blocks until the new owner
  # receives the connection or the transfer fails. On success the calling
  # thread immediately loses ownership: touching the connection afterwards or
  # calling #checkin raises, exactly as if it had never checked it out. The
  # connection is returned to the pool once, by the new owner.
  #
  # A connection held by a nested checkout (i.e. checked out more than once
  # by the calling thread) cannot be transferred, because ownership would be
  # ambiguous.
  #
  # @param lease [ConnectionPool::Lease] lease created by this pool
  # @param timeout [Numeric] seconds to wait for the new owner to receive
  # @raise [ConnectionPool::LeaseError] the transfer failed or was abandoned
  # @raise [ConnectionPool::TimeoutError] no receiver arrived in time
  def transfer(lease, timeout: @timeout)
    raise ConnectionPool::LeaseError, "can only transfer a lease from the owning pool" unless lease.pool.equal?(self)
    unless ::Thread.current[@key] && ::Thread.current[@key_count] == 1
      raise ConnectionPool::LeaseError, "can only transfer the connection currently owned by this thread"
    end

    conn = ::Thread.current[@key]
    kwargs = ::Thread.current[@key_kwargs]
    discard = ::Thread.current[@discard_key]

    Thread.handle_interrupt(Exception => :never) do
      lease.offer(conn, kwargs, discard, timeout:) do
        # Runs while interrupts are disabled, at the exact moment ownership
        # commits, so the owner can never return the connection itself.
        ::Thread.current[@key_leased] = true
      end

      ::Thread.current[@key] = nil
      ::Thread.current[@key_count] = nil
      ::Thread.current[@key_kwargs] = nil
      ::Thread.current[@discard_key] = nil
    end

    nil
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
      ::Thread.current[@key_leased] = nil
      conn
    end
  end

  def checkin(force: false)
    if ::Thread.current[@key]
      if ::Thread.current[@key_count] == 1 || force
        begin
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
          ::Thread.current[@key_leased] = nil
        end
      else
        ::Thread.current[@key_count] -= 1
      end
    elsif !force
      if ::Thread.current[@key_leased]
        raise ConnectionPool::LeaseError,
          "connection was transferred away and is no longer owned by this thread"
      else
        raise ConnectionPool::Error, "no connections are checked out"
      end
    end

    nil
  end

  # Receiver side of a lease handoff: waits on the lease and binds the
  # transferred connection to the calling thread's checkout slots.
  private def accept_lease(lease, timeout)
    raise ConnectionPool::LeaseError, "can only receive a lease from the owning pool" unless lease.pool.equal?(self)
    if ::Thread.current[@key] || ::Thread.current[@key_leased]
      raise ConnectionPool::LeaseError, "receiving thread already owns a connection from this pool"
    end

    lease.claim(->(conn, kwargs, discard) {
      ::Thread.current[@key] = conn
      ::Thread.current[@key_count] = 1
      ::Thread.current[@key_kwargs] = kwargs
      ::Thread.current[@discard_key] = discard
    }, timeout:)
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
