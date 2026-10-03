require 'thread'
require 'concurrent/errors'
require 'concurrent/atomic/atomic_fixnum'
require 'concurrent/synchronization/object'
require 'concurrent/synchronization/lock'
require 'concurrent/utility/monotonic_time'

module Concurrent

  # A read-write lock with support for optimistic reads, intended for
  # read-heavy workloads where guarded data is only briefly inconsistent
  # while a writer is active.
  #
  # Besides the regular read and write locks (with optional timeouts), a
  # thread may take an optimistic "stamp" (a version snapshot), read the
  # guarded fields without any locking, and then {#validate} that no writer
  # acquired the lock in the meantime. If validation fails, the values may
  # have been torn and must be re-read under a real read lock.
  #
  # The version is bumped every time the write lock is released, so a stamp
  # taken before a write is always invalidated by that write -- even if the
  # writer restored the guarded fields to their original values (the "ABA"
  # problem, which comparing the final field values cannot detect). A stamp
  # taken while the write lock is held can never be validated successfully.
  #
  # Stamps are bound to the lock instance that issued them; passing a stamp
  # to a different {StampedLock} raises {ArgumentError}.
  #
  # @example Optimistic read of two related fields
  #   lock = Concurrent::StampedLock.new
  #
  #   stamp = lock.try_optimistic_read
  #   low, high = index.low, index.high
  #   if lock.validate(stamp)
  #     use(low, high)            # no writer intervened
  #   else
  #     lock.with_read_lock do    # fall back to a locked read
  #       use(index.low, index.high)
  #     end
  #   end
  #
  # @note This lock is not reentrant. Acquiring the write lock while holding
  #   the read lock (or vice versa) will deadlock.
  #
  # @see http://docs.oracle.com/javase/8/docs/api/java/util/concurrent/locks/StampedLock.html java.util.concurrent.StampedLock
  class StampedLock < Synchronization::Object

    # A token issued by a {StampedLock}. Stamps are immutable, carry the
    # lock version they were taken at, and can only be used with the lock
    # instance that issued them.
    class Stamp
      # @return [Symbol] one of :optimistic, :read or :write
      attr_reader :mode

      # @!visibility private
      attr_reader :lock, :bits

      # @!visibility private
      def initialize(lock, bits, mode)
        @lock = lock
        @bits = bits
        @mode = mode
        freeze
      end

      # @return [Boolean] true if this stamp was taken by {#try_optimistic_read}
      def optimistic?
        @mode == :optimistic
      end

      # @return [Boolean] true if this stamp represents a held read lock
      def read?
        @mode == :read
      end

      # @return [Boolean] true if this stamp represents a held write lock
      def write?
        @mode == :write
      end

      def inspect
        format '#<%s:0x%x mode=%s bits=%d>', self.class.name, object_id, @mode, @bits
      end
      alias to_s inspect
    end

    # @!visibility private
    LG_READERS = 7

    # @!visibility private
    RUNIT = 1

    # @!visibility private
    WBIT = 1 << LG_READERS

    # @!visibility private
    RBITS = WBIT - 1

    # @!visibility private
    RFULL = RBITS - 1

    # @!visibility private
    ABITS = RBITS | WBIT

    # @!visibility private
    STAMP_MASK = ~RBITS

    safe_initialization!

    # Implementation notes:
    # The layout of the state integer follows java.util.concurrent.StampedLock:
    #   bits 0..6  - number of readers holding the read lock
    #   bit  7     - set while the write lock is held
    #   bits 8+    - version, incremented every time the write lock is released
    # A stamp captures the state with the reader bits masked out, so
    # validation only compares the write bit and the version. Releasing the
    # write lock adds WBIT to the state, which clears the write bit and
    # carries into the version bits, invalidating every older stamp.
    # Blocking waits are guarded by an internal lock; the state itself is
    # kept in an AtomicFixnum so optimistic reads and validation never block.

    # Create a new StampedLock in the unlocked state.
    def initialize
      super()
      @State          = AtomicFixnum.new(0)
      @WaitLock       = Synchronization::Lock.new
      @WaitingWriters = 0
      @ReadStamps     = {}
      @WriteStamp     = nil
    end

    # Take an optimistic read stamp without locking. The guarded fields may
    # then be read freely, but the reads are only meaningful if
    # {#validate} subsequently returns true.
    #
    # @return [Stamp] a stamp for {#validate}; a stamp taken while the write
    #   lock is held can never be validated successfully
    def try_optimistic_read
      state = @State.value
      bits  = (state & WBIT) == 0 ? (state & STAMP_MASK) : 0
      Stamp.new(self, bits, :optimistic)
    end

    # Check whether the lock has not been acquired in write mode since the
    # given stamp was issued. Returns false for any stamp if a writer is
    # currently active or has released the write lock since the stamp was
    # taken -- regardless of whether the guarded values still look the same.
    #
    # @param stamp [Stamp] a stamp previously issued by this lock
    #
    # @return [Boolean] true if no write lock was acquired since the stamp
    #
    # @raise [ArgumentError] if the stamp was issued by another lock instance
    def validate(stamp)
      check_stamp! stamp
      stamp.bits == (@State.value & STAMP_MASK)
    end

    # Acquire the read lock, blocking if a writer holds or is waiting for
    # the write lock.
    #
    # @param timeout [Numeric, nil] maximum number of seconds to wait;
    #   nil waits forever
    #
    # @return [Stamp] the stamp to pass to {#release_read_lock}
    #
    # @raise [Concurrent::TimeoutError] if the lock was not acquired in time
    # @raise [Concurrent::ResourceLimitError] if the maximum number of
    #   readers is exceeded
    def acquire_read_lock(timeout = nil)
      lock_read_internal(timeout) ||
        raise(Concurrent::TimeoutError, 'could not acquire the read lock in time')
    end

    # Try to acquire the read lock, waiting at most timeout seconds.
    #
    # @param timeout [Numeric] maximum number of seconds to wait
    #
    # @return [Stamp, nil] the stamp, or nil if the lock was not acquired
    #   in time
    def try_acquire_read_lock(timeout = 0)
      lock_read_internal(timeout)
    end

    # Release a previously acquired read lock.
    #
    # @param stamp [Stamp] the stamp returned by {#acquire_read_lock}
    #
    # @return [Boolean] true
    #
    # @raise [ArgumentError] if the stamp was issued by another lock instance
    # @raise [Concurrent::IllegalOperationError] if the stamp does not
    #   represent a read lock currently held on this lock
    def release_read_lock(stamp)
      check_stamp! stamp
      @WaitLock.synchronize do
        unless stamp.read? && @ReadStamps.delete(stamp)
          raise IllegalOperationError, 'cannot release a read lock which is not held'
        end
        @State.value = @State.value - RUNIT
        @WaitLock.broadcast
      end
      true
    end

    # Execute a block operation within a read lock.
    #
    # @param timeout [Numeric, nil] maximum number of seconds to wait for
    #   the lock; nil waits forever
    #
    # @yield the task to be performed within the lock
    #
    # @return [Object] the result of the block operation
    #
    # @raise [ArgumentError] when no block is given
    # @raise [Concurrent::TimeoutError] if the lock was not acquired in time
    def with_read_lock(timeout = nil)
      raise ArgumentError, 'no block given' unless block_given?
      stamp = acquire_read_lock(timeout)
      begin
        yield
      ensure
        release_read_lock(stamp)
      end
    end

    # Acquire the write lock, blocking until all readers and any active
    # writer have released the lock.
    #
    # @param timeout [Numeric, nil] maximum number of seconds to wait;
    #   nil waits forever
    #
    # @return [Stamp] the stamp to pass to {#release_write_lock}
    #
    # @raise [Concurrent::TimeoutError] if the lock was not acquired in time
    def acquire_write_lock(timeout = nil)
      lock_write_internal(timeout) ||
        raise(Concurrent::TimeoutError, 'could not acquire the write lock in time')
    end

    # Try to acquire the write lock, waiting at most timeout seconds.
    #
    # @param timeout [Numeric] maximum number of seconds to wait
    #
    # @return [Stamp, nil] the stamp, or nil if the lock was not acquired
    #   in time
    def try_acquire_write_lock(timeout = 0)
      lock_write_internal(timeout)
    end

    # Release a previously acquired write lock. Bumps the lock version,
    # invalidating every stamp issued before this write.
    #
    # @param stamp [Stamp] the stamp returned by {#acquire_write_lock}
    #
    # @return [Boolean] true
    #
    # @raise [ArgumentError] if the stamp was issued by another lock instance
    # @raise [Concurrent::IllegalOperationError] if the stamp is not the
    #   currently held write lock
    def release_write_lock(stamp)
      check_stamp! stamp
      @WaitLock.synchronize do
        unless stamp.write? && stamp.equal?(@WriteStamp)
          raise IllegalOperationError, 'cannot release a write lock which is not held by this stamp'
        end
        @WriteStamp  = nil
        @State.value = @State.value + WBIT # clears WBIT and bumps the version
        @WaitLock.broadcast
      end
      true
    end

    # Execute a block operation within a write lock.
    #
    # @param timeout [Numeric, nil] maximum number of seconds to wait for
    #   the lock; nil waits forever
    #
    # @yield the task to be performed within the lock
    #
    # @return [Object] the result of the block operation
    #
    # @raise [ArgumentError] when no block is given
    # @raise [Concurrent::TimeoutError] if the lock was not acquired in time
    def with_write_lock(timeout = nil)
      raise ArgumentError, 'no block given' unless block_given?
      stamp = acquire_write_lock(timeout)
      begin
        yield
      ensure
        release_write_lock(stamp)
      end
    end

    # Queries if the write lock is held by any thread.
    #
    # @return [Boolean] true if the write lock is held else false
    def write_locked?
      (@State.value & WBIT) != 0
    end

    # Queries if the read lock is held by any thread.
    #
    # @return [Boolean] true if the read lock is held else false
    def read_locked?
      (@State.value & RBITS) != 0
    end

    private

    # @!visibility private
    def check_stamp!(stamp)
      unless stamp.is_a?(Stamp) && stamp.lock.equal?(self)
        raise ArgumentError, 'the stamp was not issued by this StampedLock'
      end
    end

    # @!visibility private
    def lock_read_internal(timeout)
      deadline = timeout && Concurrent.monotonic_time + timeout
      @WaitLock.synchronize do
        loop do
          state = @State.value
          if (state & WBIT) == 0 && @WaitingWriters == 0
            raise ResourceLimitError, 'too many reader threads' if (state & RBITS) == RFULL
            @State.value = state + RUNIT
            stamp = Stamp.new(self, state & STAMP_MASK, :read)
            @ReadStamps[stamp] = true
            return stamp
          end
          remaining = deadline ? deadline - Concurrent.monotonic_time : nil
          return nil if remaining && remaining <= 0
          @WaitLock.ns_wait(remaining)
        end
      end
    end

    # @!visibility private
    def lock_write_internal(timeout)
      deadline = timeout && Concurrent.monotonic_time + timeout
      queued   = false
      @WaitLock.synchronize do
        loop do
          state = @State.value
          if (state & ABITS) == 0
            @State.value = state | WBIT
            @WaitingWriters -= 1 if queued
            stamp = Stamp.new(self, (state | WBIT) & STAMP_MASK, :write)
            @WriteStamp = stamp
            return stamp
          end
          unless queued
            @WaitingWriters += 1
            queued = true
          end
          remaining = deadline ? deadline - Concurrent.monotonic_time : nil
          if remaining && remaining <= 0
            @WaitingWriters -= 1
            return nil
          end
          @WaitLock.ns_wait(remaining)
        end
      end
    end
  end
end
