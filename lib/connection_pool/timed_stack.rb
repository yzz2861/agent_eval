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
    @creating = []
    @max = size
    @mutex = Thread::Mutex.new
    @resource = Thread::ConditionVariable.new
    @shutdown_block = nil
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
    return legacy_pop(timeout: timeout, exception: exception, **kwargs) if try_create_overridden?

    deadline = current_time + timeout
    reservation = nil

    @mutex.lock
    begin
      loop do
        if (connection = try_fetch_connection(**kwargs))
          return connection
        end

        raise ConnectionPool::PoolShuttingDownError if @shutdown_block

        reservation = try_reserve_creation(**kwargs)
        break if reservation

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

      if timeout.zero?
        @mutex.unlock
        begin
          connection = create_connection(**kwargs)
        rescue Exception
          complete_creation_error(reservation, $!)
          raise
        ensure
          @mutex.lock
        end

        unless @creating.delete(reservation)
          raise reservation[:shutdown_block] ? ConnectionPool::PoolShuttingDownError : reservation[:error]
        end

        shutdown_block = reservation[:shutdown_block] || @shutdown_block
        if shutdown_block
          @created -= 1 unless @created == 0
          @resource.broadcast
          @mutex.unlock
          shutdown_block.call(connection)
          raise ConnectionPool::PoolShuttingDownError
        end

        return connection
      end

      thread = Thread.new do
        Thread.current.report_on_exception = false
        finish_creation(reservation)
      end
      reservation[:thread] = thread

      @mutex.unlock
      joined = thread.join(deadline - current_time)
      @mutex.lock

      if joined
        return reservation[:result] if reservation[:result]
        raise reservation[:error] if reservation[:error]
        raise ConnectionPool::PoolShuttingDownError if reservation[:shutdown_block]
      end

      cancel_creation_locked(reservation, timeout, exception)
    ensure
      @mutex.unlock if @mutex.owned?
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
      @resource.broadcast
      @creating.each do |reservation|
        reservation[:shutdown_block] = block
      end

      shutdown_connections
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
  # Reduce the created count
  def decrement_created
    @mutex.synchronize do
      @created -= 1 unless @created == 0
      @resource.broadcast
    end
  end

  private

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

  def try_create_overridden?
    method(:try_create).owner != ConnectionPool::TimedStack
  end

  def legacy_pop(timeout:, exception:, **kwargs)
    deadline = current_time + timeout
    @mutex.synchronize do
      loop do
        raise ConnectionPool::PoolShuttingDownError if @shutdown_block
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
  # connections allowed has not been met. Subclasses that override this method
  # retain the historical behavior of running the constructor while the mutex
  # is held.
  def try_create(**_kwargs)
    unless @created == @max
      object = create_connection(**_kwargs)
      @created += 1
      object
    end
  end

  ##
  # This is an extension point for TimedStack and is called without the mutex.
  #
  # This method must create the connection represented by the given options.
  def create_connection(**_kwargs)
    @create_block.call
  end

  def try_reserve_creation(**kwargs)
    return if @created == @max

    @created += 1
    reservation = {
      kwargs: kwargs,
      shutdown_block: nil,
      result: nil,
      error: nil,
      thread: nil,
      wait_count: 1
    }
    @creating << reservation
    reservation
  end

  def cancel_creation_locked(reservation, timeout, exception)
    return reservation[:result] if reservation[:result]
    raise reservation[:error] if reservation[:error]
    raise ConnectionPool::PoolShuttingDownError if reservation[:shutdown_block]

    reservation[:wait_count] -= 1
    return nil unless exception

    raise exception, "Waited #{timeout} sec, #{length}/#{@max} available"
  end

  def finish_creation(reservation, connection = nil)
    connection ||= create_connection(**reservation[:kwargs])
    shutdown_block = nil

    @mutex.synchronize do
      return unless @creating.delete(reservation)

      shutdown_block = reservation[:shutdown_block] || @shutdown_block
      if shutdown_block
        @created -= 1 unless @created == 0
      elsif reservation[:wait_count].positive?
        reservation[:result] = connection
      else
        store_connection(connection, **reservation[:kwargs])
      end

      @resource.broadcast
    end

    shutdown_block&.call(connection)
  rescue Exception => error
    complete_creation_error(reservation, error)
  end

  def complete_creation_error(reservation, error)
    @mutex.synchronize do
      next unless @creating.include?(reservation)

      @created -= 1 unless @created == 0
      @creating.delete(reservation)
      reservation[:error] = error
      @resource.broadcast
    end
  end
end
