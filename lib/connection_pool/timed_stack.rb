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
    @creating = 0
    @que = []
    @max = size
    @mutex = Thread::Mutex.new
    @resource = Thread::ConditionVariable.new
    @shutdown_block = nil
    @disconnect_block = proc {}
  end

  ##
  # Returns +obj+ to the stack. Additional kwargs are ignored in TimedStack but may be
  # used by subclasses that extend TimedStack.
  def push(obj, **kwargs)
    shutdown_block = nil
    disconnect_block = nil

    @mutex.synchronize do
      if @shutdown_block
        decrement_created_count
        shutdown_block = @shutdown_block
      elsif created_above_target?
        decrement_created_count
        disconnect_block = @disconnect_block
      else
        store_connection obj, **kwargs
      end

      @resource.broadcast
    end

    shutdown_block.call(obj) if shutdown_block
    disconnect_block.call(obj) if disconnect_block
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
    loop do
      conn, creating = reserve_for_pop(deadline, timeout, exception, **kwargs)
      return conn unless creating

      begin
        object = try_create(**kwargs)
      rescue
        @mutex.synchronize do
          @creating -= 1
          @resource.broadcast
        end
        raise
      end

      shutdown_block, excess_connection = commit_created_connection

      if shutdown_block
        shutdown_block.call(object)
        next
      end

      if excess_connection
        @disconnect_block.call(object)
        next
      end

      return object
    end
  end

  ##
  # Changes the maximum number of connections. Idle connections beyond the new
  # size are removed immediately. Checked-out connections are removed when they
  # are returned.
  def resize(size, &block)
    size = Integer(size)
    raise ArgumentError, "size cannot be negative" if size.negative?

    @mutex.synchronize do
      raise ConnectionPool::PoolShuttingDownError if @shutdown_block

      @max = size
      @disconnect_block = block || proc {}
      @resource.broadcast
    end

    trim_excess_connections
    size
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
      @resource.broadcast
      wait_for_connections_being_created
    end

    shutdown_connections

    @mutex.synchronize do
      @shutdown_block = nil if reload
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
    @mutex.synchronize { current_length.zero? }
  end

  ##
  # The number of connections available on the stack.
  def length
    @mutex.synchronize { current_length }
  end

  ##
  # The number of connections created and available on the stack.
  def idle
    @mutex.synchronize { @que.length }
  end

  # Number of connections currently checked out.
  def checked_out
    @mutex.synchronize { checked_out_count }
  end
  alias_method :checked_out_count, :checked_out

  # Number of existing or in-progress connections that exceed the configured size.
  def pending_reaping
    @mutex.synchronize { pending_reaping_count }
  end
  alias_method :pending_reaping_count, :pending_reaping
  alias_method :pending_reclamation_count, :pending_reaping

  def target_size
    @mutex.synchronize { @max }
  end

  def stats
    @mutex.synchronize do
      {
        target_size: @max,
        checked_out: checked_out_count,
        pending_reaping: pending_reaping_count
      }
    end
  end

  ##
  # Reduce the created count
  def decrement_created
    @mutex.synchronize do
      decrement_created_count
      @resource.broadcast
    end
  end

  private

  def reserve_for_pop(deadline, timeout, exception, **kwargs)
    @mutex.synchronize do
      loop do
        raise ConnectionPool::PoolShuttingDownError if @shutdown_block

        conn = try_fetch_connection(**kwargs)
        return [conn, false] if conn

        return [nil, true] if reserve_creation

        to_wait = deadline - current_time
        if to_wait <= 0
          if exception
            raise exception, "Waited #{timeout} sec, #{current_length}/#{@max} available"
          else
            return [nil, false]
          end
        end

        @resource.wait(@mutex, to_wait)
      end
    end
  end

  def commit_created_connection
    @mutex.synchronize do
      @creating -= 1
      @created += 1

      if @shutdown_block
        decrement_created_count
        @resource.broadcast
        @shutdown_block
      elsif @created > @max
        decrement_created_count
        @resource.broadcast
        [nil, true]
      else
        @resource.broadcast
        [nil, false]
      end
    end
  end

  def current_time
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def current_length
    checkout_capacity = @max - checked_out_count - @creating

    [checkout_capacity, 0].max
  end

  def checked_out_count
    @created - @que.length
  end

  def pending_reaping_count
    [@created + @creating - @max, 0].max
  end

  def reserve_creation
    return false if @creating.positive?
    return false if checked_out_count + @creating >= @max

    @creating += 1
    true
  end

  def decrement_created_count
    @created -= 1 unless @created.zero?
  end

  def created_above_target?
    @created > @max
  end

  def wait_for_connections_being_created
    @resource.wait(@mutex) while @creating.positive?
  end

  def trim_excess_connections
    while (conn = next_excess_connection)
      @disconnect_block.call(conn)
    end
  end

  def next_excess_connection
    @mutex.synchronize do
      return nil unless created_above_target?
      return nil if @que.empty?

      decrement_created_count
      try_fetch_connection
    end
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
    while (conn = reserve_shutdown_connection(**kwargs))
      @shutdown_block.call(conn)
    end
  end

  def reserve_shutdown_connection(**kwargs)
    @mutex.synchronize do
      return nil unless @shutdown_block

      conn = try_fetch_connection(**kwargs)
      decrement_created_count if conn
      conn
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
  # This extension point creates a connection after capacity has been reserved.
  # Unlike older versions, it is called outside the mutex so shutdown and resize
  # can make progress while a slow connection factory is running.
  def try_create(**_kwargs)
    @create_block.call
  end
  alias_method :create_connection, :try_create
end
