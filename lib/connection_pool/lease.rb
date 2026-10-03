class ConnectionPool
  # Raised when a lease cannot be transferred or received. The most common
  # causes are a failed handoff (the other thread went away), attempting to
  # receive a lease more than once, or transferring a connection which is
  # part of a nested checkout.
  class LeaseError < Error; end

  # A Lease is a one-time rendezvous point for transferring ownership of a
  # single checked-out connection from one thread (the current owner) to
  # another thread (the new owner).
  #
  # The transfer only completes when both sides take part:
  #
  #   lease = pool.lease
  #
  #   # The new owner waits to receive the connection:
  #   receiver = Thread.new do
  #     lease.receive do |conn|
  #       conn.do_work
  #     end
  #   end
  #
  #   # The current owner hands its checked-out connection over:
  #   pool.with do |conn|
  #     pool.transfer(lease)
  #   end
  #
  #   receiver.join
  #
  # Until the handoff completes, the current owner still owns the connection.
  # If the transfer fails (a timeout expires or either thread goes away), the
  # connection stays with its current owner and the lease becomes unusable. A
  # successful handoff revokes ownership immediately and irreversibly, so the
  # connection is returned to the pool exactly once, by the new owner.
  class Lease
    # Maximum time blocked on the condition variable without re-checking that
    # the other thread is still alive. Bounded waits let a rendezvous fail
    # promptly when a peer is killed while blocked.
    HEARTBEAT = 0.05

    attr_reader :pool

    def initialize(pool, timeout:)
      @pool = pool
      @timeout = timeout
      @mutex = Thread::Mutex.new
      @resource = Thread::ConditionVariable.new
      # :pending -> :received -> :transferred -> :acknowledged, or :failed
      @state = :pending
      @owner = nil
      @receiver = nil
      @connection = nil
      @kwargs = nil
      @discard = nil
      @failure = nil
    end

    # Waits for the current owner to transfer its connection through this
    # lease and becomes the new owner of that connection.
    #
    # Without a block, the connection is checked out to the calling thread
    # and returned; the caller must eventually return it with
    # ConnectionPool#checkin. With a block, the connection is yielded and
    # automatically checked back in when the block finishes.
    #
    # Raises ConnectionPool::TimeoutError if the owner does not publish the
    # connection within +timeout+ seconds. Raises ConnectionPool::LeaseError
    # if the owner abandons the transfer, the lease was already received or
    # abandoned, or the receiving thread already owns a pool connection.
    def receive(timeout: @timeout, &block)
      connection = @pool.send(:accept_lease, self, timeout)

      if block
        begin
          block.call(connection)
        ensure
          @pool.checkin
        end
      else
        connection
      end
    end

    # Owner side of the handoff. Waits for a receiver to register, publishes
    # the connection, and then waits until the receiver has confirmed it took
    # ownership.
    #
    # +commit+ runs, while interrupts are disabled, only once the receiver
    # has acknowledged the handoff; it marks the owner thread as having given
    # the connection away.
    #
    # Returns true on success. Raises ConnectionPool::TimeoutError if the
    # rendezvous does not complete in time and ConnectionPool::LeaseError if
    # the receiver abandons the transfer.
    def offer(connection, kwargs, discard, timeout:, &commit)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout

      Thread.handle_interrupt(Exception => :never) do
        @mutex.synchronize do
          if @state == :failed
            raise @failure || LeaseError.new("the lease receiver went away")
          elsif @state == :acknowledged || @state == :transferred
            raise LeaseError, "lease has already been used"
          elsif @receiver && !@receiver.alive?
            raise LeaseError, "the lease receiver went away"
          end
          @owner = Thread.current
        end

        begin
          @mutex.synchronize do
            loop do
              if @receiver && @state != :acknowledged && !@receiver.alive?
                @state = :failed
                @failure = LeaseError.new("the lease receiver went away")
                @resource.broadcast
                raise @failure
              end

              case @state
              when :acknowledged
                commit.call
                @resource.broadcast
                return true
              when :failed
                raise LeaseError, "the lease receiver went away"
              when :received
                publish(connection, kwargs, discard)
              end

              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              if remaining <= 0
                @state = :failed
                @failure = ConnectionPool::TimeoutError.new(
                  "Waited #{timeout} sec for the lease to be received"
                )
                @resource.broadcast
                raise @failure
              end

              wait_for_signal(remaining)
            end
          end
        rescue ::Exception => error
          # An interrupt (e.g. Thread#raise or Thread#kill) may land while
          # waiting. Failing the lease wakes the receiver; the owner keeps
          # the connection unless the receiver already acknowledged it.
          @mutex.synchronize do
            unless @state == :acknowledged || @state == :failed
              @state = :failed
              @failure = if error.is_a?(::Timeout::Error) || error.is_a?(ConnectionPool::Error)
                error
              else
                LeaseError.new("transfer was interrupted")
              end
              @resource.broadcast
            end
          end
          raise
        end
      end
    end

    # Receiver side of the handoff. Waits for the owner to publish the
    # connection, binds it to the receiving thread, and acknowledges the
    # handoff atomically so the owner can safely relinquish ownership.
    def claim(bind, timeout: @timeout)
      Thread.handle_interrupt(Exception => :never) do
        failure = begin
          wait_for_publication(timeout)
          nil
        rescue ::Exception => error
          error
        end

        @mutex.synchronize do
          if @state == :transferred
            bind.call(@connection, @kwargs, @discard)
            @state = :acknowledged
            @resource.broadcast
            @connection
          else
            error = translate_failure(failure)
            # Only the registered receiver can poison the rendezvous; a
            # rejected duplicate receiver must not affect the real one.
            if @receiver == Thread.current
              @state = :failed
              @failure = error
              @resource.broadcast
            end
            raise error
          end
        end
      end
    end

    private

    def publish(connection, kwargs, discard)
      @state = :transferred
      @connection = connection
      @kwargs = kwargs
      @discard = discard
      @resource.broadcast
    end

    def wait_for_publication(timeout)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout

      @mutex.synchronize do
        unless @state == :pending || @state == :received || @state == :transferred
          raise @failure || LeaseError.new("lease has already been used")
        end
        unless @receiver.nil? || @receiver == Thread.current
          raise LeaseError, "lease has already been received"
        end

        if @receiver.nil? && @state == :pending
          # Assigning the receiver and claiming the rendezvous happens
          # together; a rejected duplicate receiver never becomes @receiver
          # (and its thread later dying must not fail the real handoff).
          @receiver = Thread.current
          @state = :received
          @resource.broadcast
        end

        loop do
          return if @state == :transferred

          if @owner && !@owner.alive?
            raise LeaseError, "the lease owner went away before transferring"
          end

          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          if remaining <= 0
            raise ConnectionPool::TimeoutError,
              "Waited #{timeout} sec for a leased connection"
          end

          wait_for_signal(remaining)
        end
      end
    rescue ::Exception
      @mutex.synchronize do
        if @receiver == Thread.current && (@state == :received || @state == :transferred)
          @failure = translate_failure($!)
          @state = :failed
          @resource.broadcast
        end
      end
      raise
    end

    def wait_for_signal(remaining)
      Thread.handle_interrupt(Exception => :immediate) do
        @resource.wait(@mutex, [remaining, HEARTBEAT].min)
      end
    end

    def translate_failure(error)
      return error if error.is_a?(::Timeout::Error) || error.is_a?(ConnectionPool::Error)

      LeaseError.new(error&.message || "lease was abandoned")
    end
  end
end
