require 'set'
require 'concurrent/synchronization/object'

module Concurrent

  # A `TVar` is a transactional variable - a single-element container that
  # is used as part of a transaction - see `Concurrent::atomically`.
  #
  # @!macro thread_safe_variable_comparison
  #
  # {include:file:docs-source/tvar.md}
  class TVar < Synchronization::Object
    safe_initialization!

    # Create a new `TVar` with an initial value.
    def initialize(value)
      @value = value
      @lock = Mutex.new
      @waiters = []
    end

    # Get the value of a `TVar`.
    def value
      Concurrent::atomically do
        Transaction::current.read(self)
      end
    end

    # Set the value of a `TVar`.
    def value=(value)
      Concurrent::atomically do
        Transaction::current.write(self, value)
      end
    end

    # @!visibility private
    def unsafe_value # :nodoc:
      @value
    end

    # @!visibility private
    def unsafe_value=(value) # :nodoc:
      @value = value
    end

    # @!visibility private
    def unsafe_lock # :nodoc:
      @lock
    end

    # Register a queue to be signalled when this `TVar` is next modified.
    # The caller must hold this `TVar`'s lock.
    #
    # @!visibility private
    def unsafe_add_waiter(queue) # :nodoc:
      @waiters << queue
    end

    # Signal and remove all registered waiters. The caller must hold this
    # `TVar`'s lock.
    #
    # @!visibility private
    def unsafe_notify_waiters # :nodoc:
      waiters, @waiters = @waiters, []
      waiters.each { |queue| queue.push(true) }
    end

  end

  # Run a block that reads and writes `TVar`s as a single atomic transaction.
  # With respect to the value of `TVar` objects, the transaction is atomic, in
  # that it either happens or it does not, consistent, in that the `TVar`
  # objects involved will never enter an illegal state, and isolated, in that
  # transactions never interfere with each other. You may recognise these
  # properties from database transactions.
  #
  # There are some very important and unusual semantics that you must be aware of:
  #
  # * Most importantly, the block that you pass to atomically may be executed
  #     more than once. In most cases your code should be free of
  #     side-effects, except for via TVar.
  #
  # * If an exception escapes an atomically block it will abort the transaction.
  #
  # * It is undefined behaviour to use callcc or Fiber with atomically.
  #
  # * If you create a new thread within an atomically, it will not be part of
  #     the transaction. Creating a thread counts as a side-effect.
  #
  # Transactions within transactions are flattened to a single transaction.
  #
  # @example
  #   a = new TVar(100_000)
  #   b = new TVar(100)
  #
  #   Concurrent::atomically do
  #     a.value -= 10
  #     b.value += 10
  #   end
  def atomically
    raise ArgumentError.new('no block given') unless block_given?

    # Get the current transaction

    transaction = Transaction::current

    # Are we not already in a transaction (not nested)?

    if transaction.nil?
      # New transaction

      begin
        # Retry loop

        loop do

          # Create a new transaction

          transaction = Transaction.new
          Transaction::current = transaction

          # Run the block, aborting on exceptions

          begin
            result = yield
          rescue Transaction::AbortError
            transaction.abort
            result = Transaction::ABORTED
          rescue Transaction::RetryError
            if transaction.empty?
              transaction.abort
              raise Transaction::RetryError.new(
                'Concurrent::retry_transaction cannot block: the transaction has not read any TVars')
            end
            transaction.retry_wait
            result = Transaction::ABORTED
          rescue Transaction::LeaveError
            transaction.abort
            break result
          rescue Exception
            transaction.abort
            raise
          end
          # If we can commit, break out of the loop

          if result != Transaction::ABORTED
            if transaction.commit
              break result
            end
          end
        end
      ensure
        # Clear the current transaction

        Transaction::current = nil
      end
    else
      # Nested transaction - flatten it and just run the block

      yield
    end
  end

  # Abort a currently running transaction - see `Concurrent::atomically`.
  def abort_transaction
    raise Transaction::AbortError.new
  end

  # Leave a transaction without committing or aborting - see `Concurrent::atomically`.
  def leave_transaction
    raise Transaction::LeaveError.new
  end

  # Abort the current transaction, block until any of the `TVar`s it has
  # read so far are modified by another transaction, and then re-run the
  # whole transaction from the start - see `Concurrent::atomically`.
  #
  # All writes made by the current attempt are discarded. While blocked the
  # thread does not consume any CPU, and writes to `TVar`s the transaction
  # has not read will not wake it up. As transactions are flattened, calling
  # this from a nested `atomically` retries the outermost transaction.
  #
  # Raises `Transaction::RetryError` if the transaction has not read any
  # `TVar` yet, as it could never be woken up.
  def retry_transaction
    raise Transaction::RetryError.new
  end

  module_function :atomically, :abort_transaction, :leave_transaction, :retry_transaction

  private

  # @!visibility private
  class Transaction

    ABORTED = ::Object.new

    OpenEntry = Struct.new(:value, :modified)

    AbortError = Class.new(StandardError)
    LeaveError = Class.new(StandardError)
    RetryError = Class.new(StandardError)

    def initialize
      @open_tvars = {}
    end

    def read(tvar)
      entry = open(tvar)
      entry.value
    end

    def write(tvar, value)
      entry = open(tvar)
      entry.modified = true
      entry.value = value
    end

    def open(tvar)
      entry = @open_tvars[tvar]

      unless entry
        unless tvar.unsafe_lock.try_lock
          Concurrent::abort_transaction
        end

        entry = OpenEntry.new(tvar.unsafe_value, false)
        @open_tvars[tvar] = entry
      end

      entry
    end

    def abort
      unlock
    end

    def empty?
      @open_tvars.empty?
    end

    # Block until another transaction modifies any of the `TVar`s opened so
    # far. The waiters are registered while this transaction still holds the
    # locks of those `TVar`s, so a commit that happens after they were read
    # cannot be missed: it either happens before the registration (impossible,
    # as committing requires the locks we hold) or observes the waiter and
    # signals it.
    def retry_wait
      waiter = Queue.new
      @open_tvars.each_key do |tvar|
        tvar.unsafe_add_waiter(waiter)
      end
      unlock
      waiter.pop
    end

    def commit
      @open_tvars.each do |tvar, entry|
        if entry.modified
          tvar.unsafe_value = entry.value
          tvar.unsafe_notify_waiters
        end
      end

      unlock
    end

    def unlock
      @open_tvars.each_key do |tvar|
        tvar.unsafe_lock.unlock
      end
    end

    def self.current
      Thread.current[:current_tvar_transaction]
    end

    def self.current=(transaction)
      Thread.current[:current_tvar_transaction] = transaction
    end

  end

end
