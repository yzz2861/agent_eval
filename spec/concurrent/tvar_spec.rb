require 'concurrent/tvar'

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
      expect { Concurrent::retry_transaction }.to raise_error(Concurrent::Transaction::RetryError)
    end

    it 'raises when retrying before anything has been read' do
      expect {
        Concurrent::atomically { Concurrent::retry_transaction }
      }.to raise_error(Concurrent::Transaction::RetryError, /not read any TVars/)
    end

    it 'blocks without busy-waiting and re-reads the new value when woken' do
      stock = TVar.new(0)
      executions = Queue.new
      observed = Queue.new

      thread = Thread.new do
        Concurrent::atomically do
          available = stock.value
          executions.push(true)
          Concurrent::retry_transaction if available < 1
          observed.push(available)
          stock.value = available - 1
        end
      end

      executions.pop # the first attempt ran and is now blocked
      sleep 0.2
      expect(executions.size).to eq 0 # it is sleeping, not busy-spinning

      stock.value = 5
      expect(observed.pop).to eq 5 # it re-read the new value after waking
      expect(thread.join(5)).to eq thread
      expect(stock.value).to eq 4
    end

    it 'is not woken up by writes to unrelated TVars' do
      stock = TVar.new(0)
      unrelated = TVar.new(0)
      executions = Queue.new

      thread = Thread.new do
        Concurrent::atomically do
          executions.push(true)
          Concurrent::retry_transaction if stock.value < 1
        end
      end

      executions.pop
      sleep 0.1
      3.times { |i| unrelated.value = i + 1 }
      sleep 0.2
      expect(executions.size).to eq 0
      expect(thread.join(0.1)).to be_nil

      stock.value = 1
      expect(thread.join(5)).to eq thread
    end

    it 'does not miss commits that happen between the read and the wait' do
      50.times do
        stock = TVar.new(0)
        about_to_retry = Queue.new
        observed = Queue.new

        thread = Thread.new do
          Concurrent::atomically do
            available = stock.value
            if available < 1
              about_to_retry.push(true)
              Concurrent::retry_transaction
            end
            observed.push(available)
          end
        end

        about_to_retry.pop
        stock.value = 1 # may land anywhere between the read and the wait
        expect(thread.join(5)).to eq thread
        expect(observed.pop).to eq 1
      end
    end

    it 'nested retries use the outermost transaction and discard its writes' do
      stock = TVar.new(0)
      log = TVar.new(0)
      executions = Queue.new

      thread = Thread.new do
        Concurrent::atomically do
          log.value = log.value + 1
          executions.push(true)
          Concurrent::atomically do
            Concurrent::retry_transaction if stock.value == 0
          end
        end
      end

      executions.pop
      sleep 0.2
      expect(log.value).to eq 0 # the attempt's writes were discarded
      expect(executions.size).to eq 0

      stock.value = 1
      expect(thread.join(5)).to eq thread
      expect(log.value).to eq 1 # re-ran once from the top and committed
    end

  end

end
