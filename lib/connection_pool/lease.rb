class ConnectionPool
  # Raised when a +Lease+ is used in an invalid way, e.g. receiving a lease
  # that has already been received, receiving it from the owning thread,
  # offering a connection that is part of a nested checkout, or accepting a
  # lease that belongs to another pool.
  class LeaseError < ::ConnectionPool::Error; end

  # A Lease represents a one-time, explicit handoff of a checked-out
  # connection from the owning thread to a different thread.
  #
  # The owner offers its current connection with ConnectionPool#lease and then
  # checks it back in. The checkin rendezvous with a receiver: it blocks until
  # another thread accepts the lease, at which point ownership passes to that
  # thread and the connection is not returned to the pool, or until the offer
  # expires or is cancelled, in which case the connection is returned to the
  # pool exactly once.
  #
  # A lease can only be accepted once. If the owner thread is killed or raises
  # while the offer is still pending, the offer is cancelled and the
  # connection is returned to the pool; a waiting receiver then raises
  # ConnectionPool::Error.
  class Lease
    # :nodoc: internal states
    PENDING   = :pending
    CLAIMED   = :claimed
    RELEASED  = :released
    EXPIRED   = :expired
    CANCELLED = :cancelled

    def initialize(pool, conn, kwargs, timeout, discard)
      @pool = pool
      @conn = conn
      @kwargs = kwargs
      @owner = ::Thread.current
      @deadline = monotonic + timeout
      @discard = discard
      @mutex = ::Thread::Mutex.new
      @resource = ::Thread::ConditionVariable.new
      @state = PENDING
      @receiver = nil
    end

    # The pool this lease belongs to.
    attr_reader :pool

    # The pooled connection being transferred.
    attr_reader :conn

    # The checkout kwargs associated with the connection.
    attr_reader :kwargs

    # Blocks the owner's checkin until the lease is claimed by another thread
    # or the offer expires. Returns the resulting state symbol. If the owner
    # thread is interrupted while waiting, the offer is cancelled so that the
    # connection is returned to the pool exactly once.
    #
    # :nodoc:
    def release_owner
      @mutex.synchronize do
        loop do
          return @state unless @state == PENDING

          remaining = @deadline - monotonic
          return expire if remaining <= 0

          owner_alive = ::Thread.current.status
          @resource.wait(@mutex, remaining)
          # Thread#kill interrupts ConditionVariable#wait without raising an
          # exception, so detect the dying owner and cancel the offer at once
          # instead of waiting for the deadline.
          if ::Thread.current.status != owner_alive
            # The owner thread is being torn down. Do not re-raise: return the
            # cancelled state so the caller's checkin can still return the
            # connection to the pool exactly once.
            return cancel_pending
          end
        end
      end
    rescue Exception
      # Thread#raise (and kill via raise) lands here. Cancel the offer and, if
      # the owner is merely aborting (Thread#kill), swallow the interrupt so
      # checkin can still return the connection to the pool once.
      cancel_owner
      raise unless ::Thread.current.status == "aborting"
      @state
    end

    # Cancels a pending offer because the owner can no longer complete it
    # (e.g. its thread was killed). Idempotent; only affects a pending offer.
    #
    # :nodoc:
    def cancel_owner
      @mutex.synchronize do
        cancel_pending if @state == PENDING
        @state
      end
    end

    # Called by the owner's checkin after a claim has been observed. Hands the
    # connection over to the waiting receiver, which is then free to use it.
    #
    # :nodoc:
    def complete_release!
      @mutex.synchronize do
        if @state == CLAIMED
          @state = RELEASED
          @resource.broadcast
        end
        @state
      end
    end

    # Returns and clears the discard callback attached to the connection.
    #
    # :nodoc:
    def take_discard!
      @mutex.synchronize do
        callback = @discard
        @discard = nil
        callback
      end
    end

    # Receives the offered connection on behalf of the calling thread. The
    # caller must be a thread other than the owner and each lease may only be
    # received once. Blocks until the owner completes the handoff, so
    # ownership is unambiguous at the moment this method returns.
    #
    # Raises ConnectionPool::LeaseError if the lease was already received or
    # is accepted by the owning thread, ConnectionPool::TimeoutError if the
    # offer expires or the handoff does not happen within +timeout+, and
    # ConnectionPool::Error if the owner cancelled the offer.
    #
    # :nodoc:
    def claim(timeout:)
      thread = ::Thread.current
      receiver_deadline = monotonic + timeout

      @mutex.synchronize do
        # Phase 1: reserve the offer for this thread.
        loop do
          now = monotonic
          case @state
          when RELEASED
            raise already_received unless thread == @receiver

            return @conn
          when CLAIMED
            raise already_received unless thread == @receiver

            break
          when CANCELLED
            raise ConnectionPool::Error, "lease was cancelled before it could be received"
          when EXPIRED
            raise ConnectionPool::TimeoutError, "lease expired before it was received"
          when PENDING
            raise ConnectionPool::LeaseError, "a lease must be received by a different thread" if thread == @owner
            raise ConnectionPool::TimeoutError, "waited #{timeout} sec to receive a lease" if receiver_deadline <= now

            @state = CLAIMED
            @receiver = thread
            @resource.broadcast
            break
          end
        end

        # Phase 2: wait for the owner to finish releasing. A successful claim
        # commits ownership to this thread, so it no longer makes sense to
        # abandon the offer: the owner completes the handoff immediately on
        # seeing the claim and the wait is bounded by the offer's lifetime.
        loop do
          return @conn if @state == RELEASED
          raise ConnectionPool::Error, "lease was cancelled before it was received" if @state == CANCELLED

          now = monotonic
          raise ConnectionPool::TimeoutError, "lease expired before it was received" if @deadline <= now

          @resource.wait(@mutex, @deadline - now)
        end
      end
    end

    private

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def expire
      @state = EXPIRED
      @resource.broadcast
      EXPIRED
    end

    def cancel_pending
      @state = CANCELLED
      @resource.broadcast
      CANCELLED
    end

    def already_received
      ConnectionPool::LeaseError.new("lease has already been received")
    end
  end
end
