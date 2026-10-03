require 'concurrent/atomic/stamped_lock'
require 'concurrent/atomic/count_down_latch'

module Concurrent

  RSpec.describe StampedLock do

    context 'optimistic reads' do

      it 'validates a stamp when no write lock was acquired' do
        stamp = subject.try_optimistic_read
        expect(stamp).to be_optimistic
        expect(subject.validate(stamp)).to be true
      end

      it 'remains valid while read locks are acquired and released' do
        stamp = subject.try_optimistic_read
        subject.with_read_lock { nil }
        expect(subject.validate(stamp)).to be true
      end

      it 'invalidates the stamp once the write lock is released, even if the guarded values are restored' do
        fields = [1, 1]

        stamp = subject.try_optimistic_read
        before = fields.dup

        subject.with_write_lock do
          fields[0] = 2
          fields[1] = 2
          fields[0] = 1
          fields[1] = 1
        end

        expect(fields).to eq before                 # final values are identical
        expect(subject.validate(stamp)).to be false # but the stamp is still invalid
      end

      it 'does not validate a stamp taken before a write while the write lock is held' do
        stamp    = subject.try_optimistic_read
        acquired = Concurrent::CountDownLatch.new(1)
        release  = Concurrent::CountDownLatch.new(1)

        in_thread do
          subject.with_write_lock do
            acquired.count_down
            release.wait(2)
          end
        end

        acquired.wait(2)
        expect(subject.validate(stamp)).to be false
        release.count_down
      end

      it 'never validates a stamp taken while the write lock is held' do
        acquired = Concurrent::CountDownLatch.new(1)
        release  = Concurrent::CountDownLatch.new(1)

        writer = in_thread do
          subject.with_write_lock do
            acquired.count_down
            release.wait(2)
          end
        end

        acquired.wait(2)
        stamp = subject.try_optimistic_read
        expect(subject.validate(stamp)).to be false

        release.count_down
        writer.join(2)
        expect(subject.validate(stamp)).to be false
      end

      it 'supports the take-stamp, read, validate flow for related fields' do
        fields = [0, 0]

        writer = in_thread do
          100.times do |i|
            subject.with_write_lock do
              fields[0] = i + 1
              fields[1] = i + 1
            end
          end
        end

        100.times do
          loop do
            stamp = subject.try_optimistic_read
            first, second = fields
            break expect(first).to eq second if subject.validate(stamp)
          end
        end

        writer.join(5)
      end
    end

    context 'stamp ownership' do

      it 'rejects stamps issued by another lock instance' do
        other = described_class.new

        expect { subject.validate(other.try_optimistic_read) }.
          to raise_error(ArgumentError)

        read_stamp = other.acquire_read_lock
        expect { subject.release_read_lock(read_stamp) }.
          to raise_error(ArgumentError)
        other.release_read_lock(read_stamp)

        write_stamp = other.acquire_write_lock
        expect { subject.release_write_lock(write_stamp) }.
          to raise_error(ArgumentError)
        other.release_write_lock(write_stamp)
      end

      it 'rejects values which are not stamps at all' do
        expect { subject.validate(0) }.to raise_error(ArgumentError)
        expect { subject.release_read_lock(:stamp) }.to raise_error(ArgumentError)
      end
    end

    context 'read lock' do

      it 'allows multiple readers at the same time' do
        first  = subject.acquire_read_lock
        second = subject.acquire_read_lock

        expect(subject).to be_read_locked
        subject.release_read_lock(first)
        expect(subject).to be_read_locked
        subject.release_read_lock(second)
        expect(subject).to_not be_read_locked
      end

      it 'raises when releasing a read lock which is not held' do
        expect { subject.release_read_lock(subject.try_optimistic_read) }.
          to raise_error(Concurrent::IllegalOperationError)
      end

      it 'raises when the same stamp is released twice' do
        stamp = subject.acquire_read_lock
        subject.release_read_lock(stamp)
        expect { subject.release_read_lock(stamp) }.
          to raise_error(Concurrent::IllegalOperationError)
      end

      it 'times out while the write lock is held' do
        write_stamp = subject.acquire_write_lock

        expect(subject.try_acquire_read_lock(0.05)).to be_nil
        expect { subject.acquire_read_lock(0.05) }.
          to raise_error(Concurrent::TimeoutError)

        subject.release_write_lock(write_stamp)
      end

      it 'acquires immediately once the writer is gone' do
        subject.with_write_lock { nil }
        expect(subject.try_acquire_read_lock(0)).to be_a(StampedLock::Stamp)
      end
    end

    context 'write lock' do

      it 'excludes readers while held' do
        write_stamp = subject.acquire_write_lock
        acquired    = false

        reader = in_thread do
          subject.with_read_lock { acquired = true }
        end

        sleep 0.1
        expect(acquired).to be false
        subject.release_write_lock(write_stamp)
        reader.join(2)
        expect(acquired).to be true
      end

      it 'excludes other writers while held' do
        subject.acquire_write_lock
        expect(subject.write_locked?).to be true
        expect(subject.try_acquire_write_lock(0.05)).to be_nil
      end

      it 'times out while readers are active' do
        read_stamp = subject.acquire_read_lock

        expect(subject.try_acquire_write_lock(0.05)).to be_nil
        expect { subject.acquire_write_lock(0.05) }.
          to raise_error(Concurrent::TimeoutError)

        subject.release_read_lock(read_stamp)
      end

      it 'raises when released with a stamp which is not the held write lock' do
        stamp = subject.acquire_write_lock
        expect { subject.release_write_lock(subject.try_optimistic_read) }.
          to raise_error(Concurrent::IllegalOperationError)
        subject.release_write_lock(stamp)
        expect { subject.release_write_lock(stamp) }.
          to raise_error(Concurrent::IllegalOperationError)
      end
    end

    context '#with_read_lock and #with_write_lock' do

      it 'returns the value of the block' do
        expect(subject.with_read_lock { 42 }).to eq 42
        expect(subject.with_write_lock { 42 }).to eq 42
      end

      it 'requires a block' do
        expect { subject.with_read_lock }.to raise_error(ArgumentError)
        expect { subject.with_write_lock }.to raise_error(ArgumentError)
      end

      it 'releases the read lock when the block raises' do
        expect { subject.with_read_lock { raise 'boom' } }.to raise_error('boom')
        expect(subject).to_not be_read_locked
      end

      it 'releases the write lock when the block raises' do
        expect { subject.with_write_lock { raise 'boom' } }.to raise_error('boom')
        expect(subject).to_not be_write_locked
        expect(subject.try_acquire_write_lock(0)).to be_a(StampedLock::Stamp)
      end
    end

    context '#write_locked? and #read_locked?' do

      it 'reports the write lock state' do
        expect(subject).to_not be_write_locked
        stamp = subject.acquire_write_lock
        expect(subject).to be_write_locked
        subject.release_write_lock(stamp)
        expect(subject).to_not be_write_locked
      end

      it 'reports the read lock state' do
        expect(subject).to_not be_read_locked
        stamp = subject.acquire_read_lock
        expect(subject).to be_read_locked
        subject.release_read_lock(stamp)
        expect(subject).to_not be_read_locked
      end
    end
  end
end
