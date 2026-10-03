require 'concurrent/executor/keyed_executor'
require 'concurrent/executor/fixed_thread_pool'

module Concurrent
  RSpec.describe KeyedExecutor do
    class RejectingExecutor
      def can_overflow?
        false
      end

      def serialized?
        false
      end

      def post
        raise RejectedExecutionError
      end
    end

    class RecoverableRejectingExecutor < RejectingExecutor
      attr_reader :rejected_count
      attr_accessor :accept_tasks

      def initialize
        @rejected_count = 0
        @accept_tasks = false
      end

      def post(&block)
        if accept_tasks
          Thread.new(&block)
          true
        else
          @rejected_count += 1
          raise RejectedExecutionError
        end
      end
    end

    class DeferredExecutor
      attr_reader :posted_task

      def initialize
        @mutex = Mutex.new
      end

      def can_overflow?
        false
      end

      def serialized?
        false
      end

      def post(&task)
        @mutex.synchronize do
          raise RejectedExecutionError if @posted_task

          @posted_task = task
        end
        true
      end

      def run_posted_task
        task = @mutex.synchronize { @posted_task }
        task&.call
      end

      def shutdown
        true
      end

      alias kill shutdown

      def wait_for_termination(_timeout = nil)
        true
      end
    end

    let(:executor) do
      FixedThreadPool.new(
        2,
        max_queue: 1,
        fallback_policy: :abort
      )
    end
    let(:keyed_executor) { described_class.new(executor) }

    after do
      executor.kill
      executor.wait_for_termination(5)
    end

    it 'returns the result of each submission' do
      future = keyed_executor.submit(:account) { 7 }

      expect(future.value!(5)).to eq(7)
    end

    it 'runs submissions with the same key in submission order' do
      events = 4.times.map { Event.new }
      order = []
      mutex = Mutex.new

      futures = 4.times.map do |index|
        keyed_executor.submit(:account) do
          events[index].wait(5)
          mutex.synchronize { order << index }
        end
      end

      events[2].set
      sleep(0.05)
      expect(order).to be_empty

      events[0].set
      futures[0].wait!(5)
      events[1].set
      futures[1].wait!(5)
      events[3].set
      futures[3].wait!(5)

      expect(order).to eq([0, 1, 2, 3])
    end

    it 'interleaves different keys and keeps same-key order after a failure' do
      a1_started = Event.new
      b1_started = Event.new
      release_first = Event.new
      release_second = Event.new
      a_order = []
      b_order = []

      futures = []
      futures << keyed_executor.submit(:a) do
        a_order << :a1
        a1_started.set
        release_first.wait(5)
      end
      futures << keyed_executor.submit(:b) do
        b_order << :b1
        b1_started.set
        release_second.wait(5)
      end
      futures << keyed_executor.submit(:a) { raise 'boom' }
      futures << keyed_executor.submit(:b) { b_order << :b2 }
      futures << keyed_executor.submit(:a) { a_order << :a3; :recovered }
      futures << keyed_executor.submit(:b) { b_order << :b3 }

      expect(a1_started.wait(5)).to be(true)
      expect(b1_started.wait(5)).to be(true)
      expect(futures[2]).to be_pending
      expect(futures[3]).to be_pending

      release_second.set
      expect(futures[3].wait!(5)).to be(true)
      release_first.set

      expect { futures[2].value!(5) }.to raise_error(RuntimeError, 'boom')
      expect(futures[4].value!(5)).to eq(:recovered)
      expect(futures[5].wait!(5)).to be(true)
      expect(a_order).to eq([:a1, :a3])
      expect(b_order).to eq([:b1, :b2, :b3])
    end

    it 'does not stall the chain when the wrapped executor rejects a task' do
      rejecting_executor = RejectingExecutor.new
      wrapper = described_class.new(rejecting_executor)
      future = wrapper.submit(:account) { :ran_inline }

      expect(future.value!(5)).to eq(:ran_inline)
    end

    it 'continues the chain after the wrapped executor starts accepting again' do
      rejecting_executor = RecoverableRejectingExecutor.new
      wrapper = described_class.new(rejecting_executor)
      futures = 3.times.map { |index| wrapper.submit(:account) { index } }

      expect(futures.map { |future| future.value!(5) }).to eq([0, 1, 2])
      expect(rejecting_executor.rejected_count).to be >= 1

      rejecting_executor.accept_tasks = true
      later = wrapper.submit(:account) { :later }
      expect(later.value!(5)).to eq(:later)
    end

    it 'removes an idle key after its chain drains' do
      keyed_executor.submit(:account) { :done }.value!(5)

      expect(keyed_executor.instance_variable_get(:@Chains)).to be_empty
      keyed_executor.shutdown
      expect(keyed_executor.wait_for_termination(5)).to be(true)
    end

    it 'drains accepted tasks during orderly shutdown' do
      future = keyed_executor.submit(:account) { :done }
      keyed_executor.shutdown
      expect(keyed_executor.wait_for_termination(5)).to be(true)
      expect(future.value!(5)).to eq(:done)
    end

    it 'does not shut down an executor it does not own' do
      allow(executor).to receive(:shutdown)
      allow(executor).to receive(:kill)

      keyed_executor.shutdown
      keyed_executor.wait_for_termination(5)

      expect(executor).not_to have_received(:shutdown)
      expect(executor).not_to have_received(:kill)
    end

    it 'shuts down an executor it owns and rejects queued tasks when killed' do
      deferred_executor = DeferredExecutor.new
      owned_wrapper = described_class.new(deferred_executor, owns_executor: true)
      dispatched = owned_wrapper.submit(:a) { :never }
      queued = owned_wrapper.submit(:a) { :also_never }

      owned_wrapper.kill
      expect(owned_wrapper.wait_for_termination(5)).to be(true)
      expect(dispatched).to be_rejected
      expect(queued).to be_rejected
      expect { dispatched.value!(5) }.to raise_error(RejectedExecutionError)
      expect { queued.value!(5) }.to raise_error(RejectedExecutionError)

      deferred_executor.run_posted_task
    end

    it 'rejects submissions after shutdown starts' do
      keyed_executor.shutdown
      future = keyed_executor.submit(:account) { :never }

      expect(future).to be_rejected
      expect { future.value!(5) }.to raise_error(RejectedExecutionError)
    end

    it 'raises when submitted without a block' do
      expect { keyed_executor.submit(:account) }.to raise_error(ArgumentError, 'no block given')
    end

    it 'requires an explicit key for the shorthand operator' do
      expect { keyed_executor << -> {} }
        .to raise_error(ArgumentError, 'use submit(key, *args) to submit a keyed task')
    end
  end
end
