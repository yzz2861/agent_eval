require 'concurrent/atomic/stamped_lock'
require 'concurrent/atomic/count_down_latch'
require 'concurrent/atomic/atomic_boolean'

module Concurrent

  RSpec.describe StampedLock do

    context '#try_optimistic_read and #validate' do

      it 'returns a non-zero stamp when no write lock is held' do
        stamp = subject.try_optimistic_read
        expect(stamp).to be_a Integer
        expect(stamp).to_not eq 0
      end

      it 'validates a stamp while no write lock is acquired' do
        stamp = subject.try_optimistic_read
        expect(subject.validate(stamp)).to be true
      end

      it 'returns 0 when the write lock is held' do
        latch_1 = Concurrent::CountDownLatch.new(1)
        latch_2 = Concurrent::CountDownLatch.new(1)

        in_thread do
          subject.with_write_lock do
            latch_1.count_down
            latch_2.wait(1)
          end
        end

        latch_1.wait(1)
        expect(subject.try_optimistic_read).to eq 0
        latch_2.count_down
      end

      it 'does not validate a zero stamp' do
        expect(subject.validate(0)).to be false
      end

      it 'does not validate non-integer stamps' do
        expect(subject.validate(nil)).to be false
        expect(subject.validate('stamp')).to be false
      end

      it 'invalidates a stamp taken before a write, even while the write is still running' do
        stamp = subject.try_optimistic_read
        latch_1 = Concurrent::CountDownLatch.new(1)
        latch_2 = Concurrent::CountDownLatch.new(1)

        in_thread do
          subject.with_write_lock do
            latch_1.count_down
            latch_2.wait(1)
          end
        end

        latch_1.wait(1)
        expect(subject.validate(stamp)).to be false
        latch_2.count_down
      end

      it 'invalidates old stamps after the write lock is released, even if the guarded values are restored (ABA)' do
        fields = { low: 1, high: 10 }
        stamp = subject.try_optimistic_read
        before = fields.values

        subject.with_write_lock { fields[:low], fields[:high] = 2, 20 }
        subject.with_write_lock { fields[:low], fields[:high] = 1, 10 }

        expect(fields.values).to eq before # values are back to the original state
        expect(subject.validate(stamp)).to be false # but the stamp must not validate
      end

      it 'does not validate stamps issued by a different lock instance' do
        other = described_class.new
        stamp = other.try_optimistic_read
        expect(stamp).to_not eq 0
        expect(subject.validate(stamp)).to be false
        expect(other.validate(stamp)).to be true
      end
    end

    context 'read lock' do

      it 'allows multiple concurrent readers' do
        entered = Concurrent::CountDownLatch.new(5)
        release = Concurrent::CountDownLatch.new(1)
        inside = Concurrent::AtomicFixnum.new(0)
        max = Concurrent::AtomicFixnum.new(0)

        threads = 5.times.map do
          in_thread do
            subject.with_read_lock do
              now = inside.increment
              max.update { |m| [m, now].max }
              entered.count_down
              release.wait(2)
              inside.decrement
            end
          end
        end

        entered.wait(2)
        release.count_down
        threads.each(&:join)
        expect(max.value).to be > 1
      end

      it 'blocks readers while a writer holds the lock' do
        latch_1 = Concurrent::CountDownLatch.new(1)
        latch_2 = Concurrent::CountDownLatch.new(1)
        acquired = Concurrent::AtomicBoolean.new(false)

        in_thread do
          subject.with_write_lock do
            latch_1.count_down
            latch_2.wait(2)
          end
        end

        reader = in_thread do
          latch_1.wait(1)
          subject.acquire_read_lock
          acquired.make_true
          subject.release_read_lock
        end

        sleep 0.1
        expect(acquired.value).to be false
        latch_2.count_down
        reader.join(2)
        expect(acquired.value).to be true
      end

      it 'raises when releasing a read lock that is not held' do
        expect { subject.release_read_lock }.to raise_error(IllegalOperationError)
      end

      it '#with_read_lock returns the block value and releases the lock' do
        expect(subject.with_read_lock { 42 }).to eq 42
        subject.with_write_lock { expect(subject).to be_write_locked }
      end

      it '#with_read_lock requires a block' do
        expect { subject.with_read_lock }.to raise_error(ArgumentError)
      end
    end

    context 'write lock' do

      it 'excludes other writers' do
        latch_1 = Concurrent::CountDownLatch.new(1)
        latch_2 = Concurrent::CountDownLatch.new(1)
        acquired = Concurrent::AtomicBoolean.new(false)

        in_thread do
          subject.with_write_lock do
            latch_1.count_down
            latch_2.wait(2)
          end
        end

        writer = in_thread do
          latch_1.wait(1)
          subject.with_write_lock { acquired.make_true }
        end

        sleep 0.1
        expect(acquired.value).to be false
        latch_2.count_down
        writer.join(2)
        expect(acquired.value).to be true
      end

      it 'waits for active readers' do
        latch_1 = Concurrent::CountDownLatch.new(1)
        latch_2 = Concurrent::CountDownLatch.new(1)
        acquired = Concurrent::AtomicBoolean.new(false)

        in_thread do
          subject.with_read_lock do
            latch_1.count_down
            latch_2.wait(2)
          end
        end

        writer = in_thread do
          latch_1.wait(1)
          subject.with_write_lock { acquired.make_true }
        end

        sleep 0.1
        expect(acquired.value).to be false
        latch_2.count_down
        writer.join(2)
        expect(acquired.value).to be true
      end

      it 'raises when releasing a write lock not held by the current thread' do
        expect { subject.release_write_lock }.to raise_error(IllegalOperationError)
      end

      it '#with_write_lock returns the block value and releases the lock' do
        expect(subject.with_write_lock { 42 }).to eq 42
        expect(subject).to_not be_write_locked
      end

      it '#with_write_lock requires a block' do
        expect { subject.with_write_lock }.to raise_error(ArgumentError)
      end
    end

    context 'timed acquisition' do

      it '#try_acquire_read_lock succeeds immediately when no writer is active' do
        expect(subject.try_acquire_read_lock).to be true
        subject.release_read_lock
      end

      it '#try_acquire_read_lock fails without waiting when a writer holds the lock' do
        latch_1 = Concurrent::CountDownLatch.new(1)
        latch_2 = Concurrent::CountDownLatch.new(1)

        in_thread do
          subject.with_write_lock do
            latch_1.count_down
            latch_2.wait(2)
          end
        end

        latch_1.wait(1)
        expect(subject.try_acquire_read_lock).to be false
        expect(subject.try_acquire_read_lock(0.05)).to be false
        latch_2.count_down
      end

      it '#try_acquire_read_lock waits up to the timeout and succeeds once the writer releases' do
        latch = Concurrent::CountDownLatch.new(1)

        in_thread do
          subject.with_write_lock do
            latch.count_down
            sleep 0.1
          end
        end

        latch.wait(1)
        expect(subject.try_acquire_read_lock(2)).to be true
        subject.release_read_lock
      end

      it '#try_acquire_write_lock succeeds immediately when the lock is free' do
        expect(subject.try_acquire_write_lock).to be true
        expect(subject).to be_write_locked
        subject.release_write_lock
      end

      it '#try_acquire_write_lock fails while readers are active' do
        subject.acquire_read_lock
        expect(subject.try_acquire_write_lock).to be false
        expect(subject.try_acquire_write_lock(0.05)).to be false
        subject.release_read_lock
      end

      it '#try_acquire_write_lock waits up to the timeout and succeeds once readers leave' do
        latch = Concurrent::CountDownLatch.new(1)

        in_thread do
          subject.with_read_lock do
            latch.count_down
            sleep 0.1
          end
        end

        latch.wait(1)
        expect(subject.try_acquire_write_lock(2)).to be true
        subject.release_write_lock
      end

      it 'does not hold anything after a failed timed acquisition' do
        subject.acquire_read_lock
        expect(subject.try_acquire_write_lock(0.05)).to be false
        subject.release_read_lock

        expect(subject.try_acquire_write_lock).to be true
        subject.release_write_lock
        expect(subject.try_optimistic_read).to_not eq 0
      end
    end

    context '#write_locked?' do

      it 'returns true only while the write lock is held' do
        expect(subject).to_not be_write_locked
        subject.with_write_lock { expect(subject).to be_write_locked }
        expect(subject).to_not be_write_locked
      end
    end

    context '#has_waiters?' do

      it 'returns false when no writers are waiting' do
        expect(subject).to_not have_waiters
      end

      it 'returns true while a writer waits for a reader' do
        latch_1 = Concurrent::CountDownLatch.new(1)
        latch_2 = Concurrent::CountDownLatch.new(1)

        in_thread do
          subject.with_read_lock do
            latch_1.count_down
            latch_2.wait(2)
          end
        end

        writer = in_thread do
          latch_1.wait(1)
          subject.acquire_write_lock
          subject.release_write_lock
        end

        latch_1.wait(1)
        sleep 0.1
        expect(subject).to have_waiters
        latch_2.count_down
        writer.join(2)
        expect(subject).to_not have_waiters
      end
    end
  end
end
