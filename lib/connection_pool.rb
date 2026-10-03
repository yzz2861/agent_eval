require "timeout"
require_relative "connection_pool/version"

class ConnectionPool
  class Error < ::RuntimeError; end

  class PoolShuttingDownError < ::ConnectionPool::Error; end

  class TimeoutError < ::Timeout::Error; end

  # Raised when a checkout is interrupted by a ConnectionPool::CancellationToken.
  class CancelledError < ::ConnectionPool::Error; end

  # A CancellationToken allows a caller to cancel a checkout that is still
  # waiting for a connection to become available. Cancelling a token wakes
  # up any waiters immediately (instead of letting them run into the pool
  # timeout) and raises ConnectionPool::CancelledError in the waiting thread.
  #
  # Cancellation only affects threads still waiting for a connection. Once a
  # connection has been checked out, the token has no effect: it will never
  # return or discard a connection that is in use by the caller.
  #
  # A single token may be shared by any number of checkouts, so one call to
  # #cancel! can abort a whole batch of pending checkouts.
  #
  #    token = ConnectionPool::CancellationToken.new
  #    pool.with(cancel_token: token) { |conn| ... }
  #    token.cancel! # from another thread, e.g. when the request is aborted
  class CancellationToken
    def initialize
      @mutex = Thread::Mutex.new
      @cancelled = false
      @listeners = []
    end

    # Cancels the token. All currently registered listeners are invoked
    # exactly once, and any future checkout using this token raises
    # ConnectionPool::CancelledError.
    def cancel!
      listeners = @mutex.synchronize do
        @cancelled = true
        @listeners.tap { @listeners = [] }
      end
      listeners.each(&:call)
      true
    end

    def cancelled?
      @mutex.synchronize { @cancelled }
    end

    def raise_if_cancelled!
      raise ConnectionPool::CancelledError, "connection checkout was cancelled" if cancelled?
    end

    # Registers +listener+ (or the given block) to be called when the token
    # is cancelled. Listeners are called synchronously from #cancel!, so they
    # must be fast and must not block on user code. If the token is already
    # cancelled the listener is called immediately. Returns the listener so
    # it can be passed to #unregister.
    def register(listener = nil, &block)
      listener ||= block
      raise ArgumentError, "register requires a listener" unless listener

      run_now = @mutex.synchronize do
        if @cancelled
          true
        else
          @listeners << listener
          false
        end
      end
      listener.call if run_now
      listener
    end

    # Removes a previously registered listener. Safe to call after the token
    # has been cancelled.
    def unregister(listener)
      @mutex.synchronize { @listeners.delete(listener) }
      nil
    end
  end
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
        checkin
      end
    end
  end
  alias_method :then, :with

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

  def checkout(timeout: @timeout, cancel_token: nil, **kwargs)
    if ::Thread.current[@key]
      # This thread already holds a connection: nested checkouts reuse it
      # and never wait, so the cancel token does not apply here.
      ::Thread.current[@key_count] += 1
      ::Thread.current[@key]
    else
      conn = @available.pop(timeout:, cancel_token:, **kwargs)
      ::Thread.current[@key] = conn
      ::Thread.current[@key_count] = 1
      ::Thread.current[@key_kwargs] = kwargs
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
        end
      else
        ::Thread.current[@key_count] -= 1
      end
    elsif !force
      raise ConnectionPool::Error, "no connections are checked out"
    end

    nil
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
require_relative "connection_pool/wrapper"
require_relative "connection_pool/fork"
