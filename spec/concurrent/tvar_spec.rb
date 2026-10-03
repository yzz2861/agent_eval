require 'concurrent/tvar'
require 'timeout'

module Concurrent

  RSpec.describe TVar do

    context '#initialize' do

      it 'accepts an initial value' do
        t = TVar.new(14)
        expect(t.value).to eq 14
      end

    end

    context '#value' do

      it 'gets the value' do
        t = TVar.new(14)
        expect(t.value).to eq 14
      end

    end

    context '#value=' do

      it 'sets the value' do
        t = TVar.new(14)
        t.value = 2
        expect(t.value).to eq 2
      end

    end

  end

  RSpec.describe '#atomically' do

    it 'raises an exception when no block given' do
      expect { Concurrent::atomically }.to raise_error(ArgumentError)
    end

    it 'raises the same exception that was raised in Concurrent::atomically' do
      expect {
        Concurrent::atomically do
          raise StandardError, 'This is an error!'
        end
      }.to raise_error(StandardError, 'This is an error!')
    end

    it 'aborts and releases locks for exceptions outside StandardError' do
      t = TVar.new(0)
      error = Interrupt.new('This is an interrupt!')

      expect {
        Concurrent::atomically do
          t.value = 1
          raise error
        end
      }.to raise_error(error)

      expect(t.value).to eq 0
      expect { Concurrent::atomically { t.value = 2 } }.not_to raise_error
      expect(t.value).to eq 2
    end

    it 'retries on abort' do
      count = 0

      Concurrent::atomically do
        if count == 0
          count = 1
          Concurrent::abort_transaction
        else
          count = 2
        end
      end

      expect(count).to eq 2
    end

    it 'commits writes if the transaction succeeds' do
      t = TVar.new(0)

      Concurrent::atomically do
        t.value = 1
      end

      expect(t.value).to eq 1
    end

    it 'undoes writes if the transaction is aborted' do
      t = TVar.new(0)

      count = 0

      Concurrent::atomically do
        if count == 0
          t.value = 1
          count = 1
          Concurrent::abort_transaction
        end
      end

      expect(t.value).to eq 0
    end

    it 'provides atomicity' do
      t1 = TVar.new(0)
      t2 = TVar.new(0)

      count = 0

      Concurrent::atomically do
        if count == 0
          count = 1
          t1.value = 1
          Concurrent::abort_transaction
          t2.value = 2
        end
      end

      expect(t1.value).to eq 0
      expect(t2.value).to eq 0
    end

    it 'nests' do
      t = TVar.new(0)

      Concurrent::atomically do
        expect(t.value).to eq 0
        t.value = 1
        Concurrent::atomically do
          expect(t.value).to eq 1
          t.value = 2
          Concurrent::atomically do
            expect(t.value).to eq 2
            t.value = 3
          end
          expect(t.value).to eq 3
          t.value = 4
        end
        expect(t.value).to eq 4
        t.value = 5
      end

      expect(t.value).to eq 5
    end

    it 'reflects transactional writes from within the same transaction' do
      t = TVar.new(0)

      Concurrent::atomically do
        expect(t.value).to eq 0
        t.value = 14
        expect(t.value).to eq 14
        t.value = 2
        expect(t.value).to eq 2
      end
    end

  end

  RSpec.describe '#abort_transaction' do

    it 'raises an exception outside an #atomically block' do
      expect { Concurrent::abort_transaction }.to raise_error(Concurrent::Transaction::AbortError)
    end

  end

  RSpec.describe '#leave_transaction' do

    it 'raises an exception outside an #atomically block' do
      expect { Concurrent::leave_transaction }.to raise_error(Concurrent::Transaction::LeaveError)
    end

    it 'neither commits nor aborts a transaction' do
      t = TVar.new(0)

      Concurrent::atomically do
        expect(t.value).to eq 0
        t.value = 14
        Concurrent::leave_transaction
      end

      expect(t.value).to eq 0
    end

  end

  RSpec.describe '#retry_transaction' do

    it 'raises an exception outside an #atomically block' do
      expect { Concurrent.retry_transaction }.to raise_error(Concurrent::IllegalOperationError)
    end

    it 'raises when the transaction does not read a TVar' do
      t = TVar.new(0)

      expect do
        Concurrent.atomically do
          t.value = 1
          Concurrent.retry_transaction
        end
      end.to raise_error(Concurrent::IllegalOperationError)

      expect(t.value).to eq 0
    end

    it 'raises when a nested transaction does not read a TVar' do
      t = TVar.new(0)

      expect do
        Concurrent.atomically do
          t.value = 1
          Concurrent.atomically do
            Concurrent.retry_transaction
          end
        end
      end.to raise_error(Concurrent::IllegalOperationError)

      expect(t.value).to eq 0
    end

    it 'retries a nested transaction through the outermost transaction' do
      t = TVar.new(0)
      attempts = 0
      ready = Queue.new

      thread = Thread.new do
        Concurrent.atomically do
          attempts += 1
          value = t.value
          ready << :ready

          Concurrent.atomically do
            Concurrent.retry_transaction if value.zero?
          end

          value
        end
      end

      expect(ready.pop).to eq :ready
      t.value = 1

      expect(Timeout.timeout(5) { thread.value }).to eq 1
      expect(attempts).to eq 2
    end

    it 'waits without retrying until a read TVar changes, then rereads it' do
      watched = TVar.new(0)
      unrelated = TVar.new(0)
      unchanged = TVar.new(0)
      pending = TVar.new(0)
      attempts = Queue.new
      ready = Queue.new
      result = Queue.new

      thread = Thread.new do
        result << Concurrent.atomically do
          value = watched.value
          attempts << value
          pending.value = 42 if value.zero?
          unchanged.value
          ready << :ready

          Concurrent.retry_transaction if value.zero?

          value
        end
      end

      expect(ready.pop).to eq :ready
      expect(pending.value).to eq 0

      10.times do |index|
        unrelated.value = index + 1
      end

      unchanged.value = 0

      sleep(0.05)
      expect(thread.status).to eq 'sleep'
      expect(attempts.length).to eq 1
      expect(attempts.pop(true)).to eq 0

      watched.value = 1

      expect(Timeout.timeout(5) { result.pop }).to eq 1
      expect(attempts.pop(true)).to eq 1
      expect(thread.join(5)).to be_truthy
      expect(pending.value).to eq 0
    end

    it 'does not miss a commit made after retry but before waiting' do
      50.times do
        watched = TVar.new(0)
        ready = Queue.new
        result = Queue.new

        thread = Thread.new do
          result << Concurrent.atomically do
            value = watched.value
            ready << :ready
            Concurrent.retry_transaction if value.zero?
            value
          end
        end

        expect(ready.pop).to eq :ready
        watched.value = 1

        expect(Timeout.timeout(5) { result.pop }).to eq 1
        expect(thread.join(5)).to be_truthy
      end
    end

  end

end
