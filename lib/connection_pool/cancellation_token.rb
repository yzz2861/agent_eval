class ConnectionPool
  ##
  # A CancellationToken cooperatively cancels a pending checkout.
  #
  # Pass a token to +checkout+ or +with+ via the +:cancel_token+ keyword.
  # While the caller is still *waiting* for a connection, cancelling the
  # token wakes the waiter promptly (it does not linger until the pool
  # timeout) and raises +ConnectionPool::CancelledError+.
  #
  # Once a connection has been handed to the caller the token has no
  # further effect: cancellation never checks a connection back in on
  # the caller's behalf.
  #
  # Tokens are thread-safe and may be shared across any number of
  # concurrent checkouts; a single +cancel+ releases all of them.
  #
  # Example:
  #
  #    token = ConnectionPool::CancellationToken.new
  #    upstream.on_cancel { token.cancel }
  #    pool.with(cancel_token: token) { |conn| conn.get("/") }
  #
  class CancellationToken
    def initialize
      @mutex = Thread::Mutex.new
      @cancelled = false
      @callbacks = []
    end

    ##
    # Marks the token as cancelled and invokes any registered callbacks.
    # Callbacks run outside the token's internal lock so they may safely
    # interact with the pool. Repeated calls are harmless no-ops.
    def cancel
      callbacks = @mutex.synchronize do
        if @cancelled
          nil
        else
          @cancelled = true
          @callbacks.dup.tap { @callbacks.clear }
        end
      end
      callbacks&.each(&:call)
      nil
    end

    def cancelled?
      @mutex.synchronize { @cancelled }
    end

    ##
    # Raises ConnectionPool::CancelledError if the token has been cancelled.
    def raise_if_cancelled
      raise ConnectionPool::CancelledError, "operation cancelled" if cancelled?
      nil
    end

    ##
    # Registers +block+ to be called when the token is cancelled.
    #
    # Returns a proc that unregisters the callback. If the token is
    # already cancelled the block is *not* called and +nil+ is returned,
    # so callers can distinguish "registered" from "too late" without
    # racing +cancel+.
    def on_cancel(&block)
      @mutex.synchronize do
        if @cancelled
          nil
        else
          @callbacks << block
          proc { unregister(block) }
        end
      end
    end

    private

    def unregister(callback)
      @mutex.synchronize { @callbacks.delete(callback) }
      nil
    end
  end
end
