##
# The TimedStack manages a pool of homogeneous connections (or any resource
# you wish to manage). Connections are created lazily up to a given maximum
# number.
#
# Examples:
#
#    ts = TimedStack.new(size: 1) { MyConnection.new }
#
#    # fetch a connection
#    conn = ts.pop
#
#    # return a connection
#    ts.push conn
#
#    conn = ts.pop
#    ts.pop timeout: 5
#    #=> raises ConnectionPool::TimeoutError after 5 seconds
class ConnectionPool::TimedStack
  attr_reader :max

  ##
  # Creates a new pool with +size+ connections that are created from the given
  # +block+.
  def initialize(size: 0, &block)
    @create_block = block
    @created = 0
    @que = []
    @max = size
    @mutex = Thread::Mutex.new
    @resource = Thread::ConditionVariable.new
    @shutdown_block = nil
    @quiescing = false
    @shutdown_epoch = 0
  end

  ##
  # Returns +obj+ to the stack. Additional kwargs are ignored in TimedStack but may be
  # used by subclasses that extend TimedStack.
  def push(obj, **kwargs)
    @mutex.synchronize do
      if @shutdown_block
        @created -= 1 unless @created == 0
        @shutdown_block.call(obj)
      else
        store_connection obj, **kwargs
      end

      @resource.broadcast
    end
  end
  alias_method :<<, :push

  ##
  # Retrieves a connection from the stack. If a connection is available it is
  # immediately returned. If no connection is available within the given
  # timeout a ConnectionPool::TimeoutError is raised.
  #
  # @option options [Float] :timeout (0.5) Wait this many seconds for an available entry
  # @option options [Class] :exception (ConnectionPool::TimeoutError) Exception class to raise
  #   if an entry was not available within the timeout period. Use `exception: false` to return nil.
  #
  # Other options may be used by subclasses that extend TimedStack.
  def pop(timeout: 0.5, exception: ConnectionPool::TimeoutError, **kwargs)
    deadline = current_time + timeout
    @mutex.synchronize do
      shutdown_epoch = @shutdown_epoch
      loop do
        raise ConnectionPool::PoolShuttingDownError if @shutdown_block || @shutdown_epoch != shutdown_epoch

        if @quiescing
          to_wait = deadline - current_time
          if to_wait <= 0
            if exception
              raise exception, "Waited #{timeout} sec, pool is quiescing"
            else
              return nil
            end
          end
          @resource.wait(@mutex, to_wait)
          raise ConnectionPool::PoolShuttingDownError if @shutdown_epoch != shutdown_epoch
          # Re-check at the top of the loop: the barrier may have ended.
          next
        end

        if (conn = try_fetch_connection(**kwargs))
          return conn
        end

        connection = try_create(**kwargs)
        return connection if connection

        to_wait = deadline - current_time
        if to_wait <= 0
          if exception
            raise exception, "Waited #{timeout} sec, #{length}/#{@max} available"
          else
            return nil
          end
        end
        @resource.wait(@mutex, to_wait)
      end
    end
  end

  ##
  # Prevents new connections from being checked out, waits for every
  # connection currently checked out to be returned, then calls the given
  # +block+ while the stack is known to be quiescent (no connections out).
  #
  # Connections returned while the block is running are stored as usual but
  # remain unavailable to new +pop+ callers until the block finishes. The
  # barrier is always released and waiting threads are woken when the block
  # returns, raises, the wait times out, or the stack is shut down.
  #
  # Raises ConnectionPool::TimeoutError if the stack cannot be drained within
  # +timeout+ seconds and ConnectionPool::PoolShuttingDownError if +shutdown+
  # wins the race.
  def quiesce(timeout: 5)
    raise ArgumentError, "quiesce must receive a block" unless block_given?

    deadline = current_time + timeout

    @mutex.synchronize do
      shutdown_epoch = @shutdown_epoch
      loop do
        raise ConnectionPool::PoolShuttingDownError if @shutdown_block || @shutdown_epoch != shutdown_epoch
        break unless @quiescing

        to_wait = deadline - current_time
        raise ConnectionPool::TimeoutError, "Waited #{timeout} sec for an active quiesce block" if to_wait <= 0
        @resource.wait(@mutex, to_wait)
      end

      @quiescing = true

      begin
        until checked_out_count.zero?
          raise ConnectionPool::PoolShuttingDownError if @shutdown_block || @shutdown_epoch != shutdown_epoch

          to_wait = deadline - current_time
          if to_wait <= 0
            raise ConnectionPool::TimeoutError,
              "Waited #{timeout} sec for #{checked_out_count} connection(s) to be checked in"
          end
          @resource.wait(@mutex, to_wait)
        end
      rescue Exception
        release_quiesce_barrier
        raise
      end
    end

    begin
      yield
    ensure
      @mutex.synchronize { release_quiesce_barrier }
    end
  end

  ##
  # Shuts down the TimedStack by passing each connection to +block+ and then
  # removing it from the pool. Attempting to checkout a connection after
  # shutdown will raise +ConnectionPool::PoolShuttingDownError+ unless
  # +:reload+ is +true+.
  def shutdown(reload: false, &block)
    raise ArgumentError, "shutdown must receive a block" unless block

    @mutex.synchronize do
      @shutdown_block = block
      @shutdown_epoch += 1
      @resource.broadcast

      shutdown_connections
      @shutdown_block = nil if reload
      # Reload clears the shutdown state: wake threads parked on an active
      # quiesce barrier (or on pop) so they observe the new state immediately
      # instead of sleeping through their full wait slice.
      @resource.broadcast if reload
    end
  end

  ##
  # Reaps connections that were checked in more than +idle_seconds+ ago.
  def reap(idle_seconds:)
    raise ArgumentError, "reap must receive a block" unless block_given?
    raise ArgumentError, "idle_seconds must be a number" unless idle_seconds.is_a?(Numeric)
    raise ConnectionPool::PoolShuttingDownError if @shutdown_block

    count = idle
    count.times do
      conn = @mutex.synchronize do
        raise ConnectionPool::PoolShuttingDownError if @shutdown_block
        reserve_idle_connection(idle_seconds)
      end
      break unless conn

      yield conn
    end
  end

  ##
  # Returns +true+ if there are no available connections.
  def empty?
    (@created - @que.length) >= @max
  end

  ##
  # The number of connections available on the stack.
  def length
    @max - @created + @que.length
  end

  ##
  # The number of connections created and available on the stack.
  def idle
    @que.length
  end

  ##
  # The number of connections currently checked out.
  def checked_out_count
    @created - @que.length
  end

  ##
  # Reduce the created count
  def decrement_created
    @mutex.synchronize do
      @created -= 1 unless @created == 0
      @resource.broadcast
    end
  end

  private

  def release_quiesce_barrier
    @quiescing = false
    @resource.broadcast
  end

  def current_time
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # This method must returns a connection from the stack if one exists. Allows
  # subclasses with expensive match/search algorithms to avoid double-handling
  # their stack.
  def try_fetch_connection(**kwargs)
    connection_stored?(**kwargs) && fetch_connection(**kwargs)
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # This method must returns true if a connection is available on the stack.
  def connection_stored?(**_kwargs)
    !@que.empty?
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # This method must return a connection from the stack.
  def fetch_connection(**_kwargs)
    @que.pop&.first
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # This method must shut down all connections on the stack.
  def shutdown_connections(**kwargs)
    while (conn = try_fetch_connection(**kwargs))
      @created -= 1 unless @created == 0
      @shutdown_block.call(conn)
    end
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # This method returns the oldest idle connection if it has been idle for more than idle_seconds.
  # This requires that the stack is kept in order of checked in time (oldest first).
  def reserve_idle_connection(idle_seconds)
    return unless idle_connections?(idle_seconds)

    @created -= 1 unless @created == 0

    # Most active elements are at the tail of the array.
    # Most idle will be at the head so `shift` rather than `pop`.
    @que.shift.first
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # Returns true if the first connection in the stack has been idle for more than idle_seconds
  def idle_connections?(idle_seconds)
    return unless connection_stored?
    # Most idle will be at the head so `first`
    age = (current_time - @que.first.last)
    age > idle_seconds
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # This method must return +obj+ to the stack.
  def store_connection(obj, **_kwargs)
    @que.push [obj, current_time]
  end

  ##
  # This is an extension point for TimedStack and is called with a mutex.
  #
  # This method must create a connection if and only if the total number of
  # connections allowed has not been met.
  def try_create(**_kwargs)
    unless @created == @max
      object = @create_block.call
      @created += 1
      object
    end
  end
end
