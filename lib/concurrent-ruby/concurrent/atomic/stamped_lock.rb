require 'thread'
require 'concurrent/atomic/atomic_fixnum'
require 'concurrent/atomic/atomic_reference'
require 'concurrent/errors'
require 'concurrent/synchronization/object'
require 'concurrent/synchronization/lock'

module Concurrent

  # A read-write lock with support for optimistic reads, modeled after
  # Java's java.util.concurrent.locks.StampedLock.
  #
  # In addition to regular read and write locks, a StampedLock issues
  # "stamps" via #try_optimistic_read. A stamp is a version token for the
  # lock: as long as no write lock is acquired, the version does not change
  # and #validate keeps returning true for the stamp. The moment a write
  # lock is released, every previously issued stamp becomes invalid --
  # even if the guarded data was restored to its original values (the "ABA"
  # problem, which comparing field values cannot detect).
  #
  # Optimistic reads are intended for read-mostly data structures: take a
  # stamp, read the fields, then validate. If validation fails, fall back to
  # a regular read lock and re-read.
  #
  # Stamps are only meaningful for the lock instance that issued them;
  # validating a stamp against a different lock instance always fails.
  #
  # @example Optimistic read of two related fields
  #   lock = Concurrent::StampedLock.new
  #
  #   # reader
  #   stamp = lock.try_optimistic_read
  #   low, high = index.low, index.high
  #   unless lock.validate(stamp)
  #     lock.with_read_lock { low, high = index.low, index.high }
  #   end
  #
  #   # writer
  #   lock.with_write_lock do
  #     index.low  = new_low
  #     index.high = new_high
  #   end
  #
  # @note Do **not** try to acquire the write lock while already holding a
  #   read lock **or** try to acquire the write lock while you already have
  #   it. This will lead to deadlock.
  #
  # @see http://docs.oracle.com/javase/8/docs/api/java/util/concurrent/locks/StampedLock.html java.util.concurrent.StampedLock
  class StampedLock < Synchronization::Object

    # @!visibility private
    WBIT = 1 # low bit of the state: set while a writer holds the lock

    # @!visibility private
    ORIGIN = 2 # initial state: version 1, no writer

    # @!visibility private
    STATE_MODULUS = 1 << 64 # stamps pack (instance tag, state) into one integer

    # @!visibility private
    MAX_READERS = (1 << 15) - 1

    # @!visibility private
    TAG_COUNTER = AtomicFixnum.new(0)

    safe_initialization!

    # Implementation notes:
    # @State is a single atomic integer combining a version counter with the
    #   writer bit (WBIT). Even values mean "no writer active". Acquiring the
    #   write lock flips the bit on, releasing it flips the bit off and bumps
    #   the version, so every stamp issued before the release becomes invalid.
    # @Readers and @WaitingWriters track reader count and writer intent, so
    #   writers are not starved by a steady stream of readers.
    # A stamp packs a per-instance tag together with the observed state, so
    #   stamps can never be validated against a different lock instance.

    # Create a new StampedLock in the unlocked state.
    def initialize
      super()
      @State          = AtomicFixnum.new(ORIGIN) # version counter + writer bit
      @Readers        = AtomicFixnum.new(0)      # number of active readers
      @WaitingWriters = AtomicFixnum.new(0)      # writers waiting to acquire
      @Writer         = AtomicReference.new(nil) # the thread holding the write lock
      @Tag            = TAG_COUNTER.increment    # unique per lock instance
      @Lock           = Synchronization::Lock.new
    end

    # Take a stamp for an optimistic read, if no write lock is currently held.
    #
    # @return [Integer] a non-zero stamp for later validation, or 0 if the
    #   write lock is currently held (optimistic read not possible).
    def try_optimistic_read
      state = @State.value
      (state & WBIT) == 0 ? pack_stamp(state) : 0
    end

    # Check whether a stamp obtained from #try_optimistic_read is still
    # valid, i.e. no write lock has been acquired since the stamp was issued.
    #
    # @param [Integer] stamp a stamp previously returned by #try_optimistic_read
    #
    # @return [Boolean] true if no write lock has been acquired (and released)
    #   since the stamp was issued; false for expired stamps, stamps issued
    #   while a writer was active, and stamps from other lock instances.
    def validate(stamp)
      stamp.is_a?(Integer) && stamp > 0 &&
        stamp / STATE_MODULUS == @Tag &&
        stamp % STATE_MODULUS == @State.value
    end

    # Execute a block operation within a read lock.
    #
    # @yield the task to be performed within the lock.
    #
    # @return [Object] the result of the block operation.
    #
    # @raise [ArgumentError] when no block is given.
    # @raise [Concurrent::ResourceLimitError] if the maximum number of readers
    #   is exceeded.
    def with_read_lock
      raise ArgumentError.new('no block given') unless block_given?
      acquire_read_lock
      begin
        yield
      ensure
        release_read_lock
      end
    end

    # Execute a block operation within a write lock.
    #
    # @yield the task to be performed within the lock.
    #
    # @return [Object] the result of the block operation.
    #
    # @raise [ArgumentError] when no block is given.
    def with_write_lock
      raise ArgumentError.new('no block given') unless block_given?
      acquire_write_lock
      begin
        yield
      ensure
        release_write_lock
      end
    end

    # Acquire a read lock. If a write lock has been acquired, or a writer is
    # waiting, will block until the writer is done. Will not block if other
    # read locks have been acquired.
    #
    # @return [Boolean] true if the lock is successfully acquired
    #
    # @raise [Concurrent::ResourceLimitError] if the maximum number of readers
    #   is exceeded.
    def acquire_read_lock
      loop do
        return true if try_acquire_read_lock_once
        @Lock.wait_until { read_lock_available? }
      end
    end

    # Try to acquire a read lock, optionally waiting up to +timeout+ seconds.
    #
    # @param [Numeric, nil] timeout maximum time in seconds to wait for the
    #   lock; nil (the default) makes a single non-blocking attempt.
    #
    # @return [Boolean] true if the lock was acquired, false otherwise.
    #   When false is returned, no lock is held and nothing needs releasing.
    #
    # @raise [Concurrent::ResourceLimitError] if the maximum number of readers
    #   is exceeded.
    def try_acquire_read_lock(timeout = nil)
      deadline = timeout && Concurrent.monotonic_time + timeout
      loop do
        return true if try_acquire_read_lock_once
        return false unless deadline
        remaining = deadline - Concurrent.monotonic_time
        return false if remaining <= 0
        @Lock.wait_until(remaining) { read_lock_available? }
      end
    end

    # Release a previously acquired read lock.
    #
    # @return [Boolean] true if the lock is successfully released
    #
    # @raise [Concurrent::IllegalOperationError] if no read lock is currently held.
    def release_read_lock
      loop do
        readers = @Readers.value
        raise IllegalOperationError, 'Cannot release a read lock which is not held' if readers == 0

        if @Readers.compare_and_set(readers, readers - 1)
          # If we were the last reader, wake up any waiting writers
          @Lock.broadcast if readers == 1
          return true
        end
      end
    end

    # Acquire a write lock. Will block and wait for all active readers and writers.
    #
    # @return [Boolean] true if the lock is successfully acquired
    def acquire_write_lock
      @WaitingWriters.increment
      begin
        loop do
          state = @State.value
          if (state & WBIT) == 0 && @Readers.value == 0 &&
             @State.compare_and_set(state, state + WBIT)
            @Writer.set(Thread.current)
            return true
          end
          @Lock.wait_until { write_lock_available? }
        end
      ensure
        # If no writers remain, waiting readers may proceed
        @Lock.broadcast if @WaitingWriters.decrement == 0
      end
    end

    # Try to acquire a write lock, optionally waiting up to +timeout+ seconds.
    #
    # @param [Numeric, nil] timeout maximum time in seconds to wait for the
    #   lock; nil (the default) makes a single non-blocking attempt.
    #
    # @return [Boolean] true if the lock was acquired, false otherwise.
    #   When false is returned, no lock is held and nothing needs releasing.
    def try_acquire_write_lock(timeout = nil)
      deadline = timeout && Concurrent.monotonic_time + timeout
      @WaitingWriters.increment
      begin
        loop do
          state = @State.value
          if (state & WBIT) == 0 && @Readers.value == 0 &&
             @State.compare_and_set(state, state + WBIT)
            @Writer.set(Thread.current)
            return true
          end
          return false unless deadline
          remaining = deadline - Concurrent.monotonic_time
          return false if remaining <= 0
          @Lock.wait_until(remaining) { write_lock_available? }
        end
      ensure
        # If no writers remain, waiting readers may proceed
        @Lock.broadcast if @WaitingWriters.decrement == 0
      end
    end

    # Release a previously acquired write lock. Bumps the lock version, which
    # invalidates every optimistic-read stamp issued so far.
    #
    # @return [Boolean] true if the lock is successfully released
    #
    # @raise [Concurrent::IllegalOperationError] if the write lock is not held
    #   by the current thread.
    def release_write_lock
      unless @Writer.compare_and_set(Thread.current, nil)
        raise IllegalOperationError, 'Cannot release a write lock which is not held by the current thread'
      end

      @State.update { |state| state + WBIT } # clears the writer bit, bumps the version
      @Lock.broadcast
      true
    end

    # Queries if the write lock is held by any thread.
    #
    # @return [Boolean] true if the write lock is held else false
    def write_locked?
      (@State.value & WBIT) != 0
    end

    # Queries whether any threads are waiting to acquire the write lock.
    #
    # @return [Boolean] true if any writers are waiting else false
    def has_waiters?
      @WaitingWriters.value > 0
    end

    private

    # @!visibility private
    def pack_stamp(state)
      @Tag * STATE_MODULUS + state
    end

    # @!visibility private
    def read_lock_available?
      (@State.value & WBIT) == 0 && @WaitingWriters.value == 0
    end

    # @!visibility private
    def write_lock_available?
      (@State.value & WBIT) == 0 && @Readers.value == 0
    end

    # @!visibility private
    # Single non-blocking attempt to take a read lock. If a writer slips in
    # between the counter increment and the re-check, backs off so that no
    # thread ever believes it holds a read lock while a writer is active.
    def try_acquire_read_lock_once
      loop do
        return false unless read_lock_available?
        readers = @Readers.value
        raise ResourceLimitError.new('Too many reader threads') if readers >= MAX_READERS

        if @Readers.compare_and_set(readers, readers + 1)
          return true if read_lock_available?
          release_read_lock # a writer slipped in; back off and retry
        end
      end
    end
  end
end
