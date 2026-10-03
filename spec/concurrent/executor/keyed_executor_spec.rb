require 'concurrent/executor/keyed_executor'
require 'concurrent/executor/fixed_thread_pool'
require 'concurrent/array'
require 'concurrent/atomic/count_down_latch'

module Concurrent

  # An executor which raises RejectedExecutionError for the first
  # `failures` posts and delegates to a real executor afterwards.
  class KeyedExecutorSpecFlakyExecutor
    def initialize(delegate, failures)
      @delegate = delegate
      @failures = failures
    end

    def post(*args, &task)
      if @failures > 0
        @failures -= 1
        raise RejectedExecutionError
      end
      @delegate.post(*args, &task)
    end

    def can_overflow?
      false
    end
  end

  RSpec.describe KeyedExecutor do

    let(:pool) { FixedThreadPool.new(4) }
    let(:executor) { KeyedExecutor.new(pool) }

    after do
      executor.kill
      pool.kill
    end

    it 'raises an exception when no block is given' do
      expect { executor.post(:a) }.to raise_error(ArgumentError)
    end

    it 'returns an IVar fulfilled with the task result' do
      result = executor.post(:a, 1, 2) { |a, b| a + b }
      expect(result.value(10)).to eq 3
    end

    it 'serializes interleaved keys independently and runs them in parallel' do
      gate      = CountDownLatch.new(1)
      a_started = CountDownLatch.new(1)
      b_started = CountDownLatch.new(1)
      order     = Concurrent::Array.new

      # submissions of the two keys are interleaved
      a0 = executor.post(:a) { a_started.count_down; both = b_started.wait(10); gate.wait(10); order << :a0; both }
      a1 = executor.post(:a) { order << :a1; :a1 }
      a2 = executor.post(:a) { order << :a2; :a2 }
      b0 = executor.post(:b) { b_started.count_down; both = a_started.wait(10); gate.wait(10); order << :b0; both }
      b1 = executor.post(:b) { order << :b1; :b1 }
      b2 = executor.post(:b) { order << :b2; :b2 }
      gate.count_down

      # the rendezvous proves both keys were executing at the same time
      expect(a0.value(10)).to be true
      expect(b0.value(10)).to be true
      expect([a1, a2, b1, b2].map { |r| r.value(10) }).to eq [:a1, :a2, :b1, :b2]

      # each key kept its submission order
      expect(order.select { |e| e.to_s.start_with?('a') }).to eq [:a0, :a1, :a2]
      expect(order.select { |e| e.to_s.start_with?('b') }).to eq [:b0, :b1, :b2]
    end

    it 'continues the key chain in order after a task raises' do
      gate  = CountDownLatch.new(1)
      order = Concurrent::Array.new
      boom  = StandardError.new('boom')

      r0 = executor.post(:a) { gate.wait(10); order << :a0; :a0 }
      r1 = executor.post(:a) { order << :a1; raise boom }
      r2 = executor.post(:a) { order << :a2; :a2 }
      s0 = executor.post(:b) { gate.wait(10); order << :b0; :b0 }
      s1 = executor.post(:b) { order << :b1; :b1 }
      gate.count_down

      expect(r0.value(10)).to eq :a0
      expect(r1).to be_rejected
      expect(r1.reason).to be boom
      expect(r2.value(10)).to eq :a2
      expect(s0.value(10)).to eq :b0
      expect(s1.value(10)).to eq :b1

      # the failing task did not disturb the execution order of its key
      expect(order.select { |e| e.to_s.start_with?('a') }).to eq [:a0, :a1, :a2]
      expect(order.select { |e| e.to_s.start_with?('b') }).to eq [:b0, :b1]
    end

    context 'when the underlying executor rejects tasks' do

      it 'rejects the task result without getting stuck' do
        flaky    = KeyedExecutorSpecFlakyExecutor.new(pool, 1)
        executor = KeyedExecutor.new(flaky)

        r1 = executor.post(:k) { :first }
        r2 = executor.post(:k) { :second }

        expect(r1).to be_rejected
        expect(r1.reason).to be_a RejectedExecutionError
        # the chain kept moving: the next task of the same key still ran
        expect(r2.value(10)).to eq :second
        expect(executor.key_count).to eq 0
      end

      it 'never blocks the chain when every post is rejected' do
        flaky    = KeyedExecutorSpecFlakyExecutor.new(pool, 100)
        executor = KeyedExecutor.new(flaky)

        results = 3.times.map { executor.post(:k) { :nope } }

        results.each do |result|
          expect(result).to be_rejected
          expect(result.reason).to be_a RejectedExecutionError
        end
        expect(executor.key_count).to eq 0
      end
    end

    it 'rejects tasks posted after shutdown' do
      executor.shutdown
      result = executor.post(:a) { :nope }
      expect(result).to be_rejected
      expect(result.reason).to be_a RejectedExecutionError
    end

    it 'drains queued tasks on shutdown before terminating' do
      gate = CountDownLatch.new(1)
      ran  = Concurrent::Array.new

      executor.post(:a) { gate.wait(10); ran << 1 }
      executor.post(:a) { ran << 2 }
      executor.post(:b) { gate.wait(10); ran << 3 }

      executor.shutdown
      expect(executor).to be_shuttingdown
      gate.count_down

      expect(executor.wait_for_termination(10)).to be true
      expect(ran.sort).to eq [1, 2, 3]
      expect(executor).to be_shutdown
      expect(executor).not_to be_running
    end

    it 'drops bookkeeping of idle keys' do
      results = 10.times.map { |i| executor.post(:"key_#{i}") { i } }
      expect(results.map { |r| r.value(10) }).to eq (0..9).to_a
      expect(executor.key_count).to eq 0
    end

    context 'with an external executor' do

      it 'does not own the underlying executor' do
        expect(executor.owns_executor?).to be false
      end

      it 'leaves the underlying executor running on shutdown' do
        executor.shutdown
        expect(executor.wait_for_termination(10)).to be true
        expect(pool).to be_running
      end
    end

    context 'with an owned executor' do

      let(:executor) { KeyedExecutor.new }

      it 'owns the underlying executor' do
        expect(executor.owns_executor?).to be true
      end

      it 'shuts the underlying executor down with itself' do
        executor.post(:a) { :done }.wait(10)
        executor.shutdown
        expect(executor.wait_for_termination(10)).to be true
        expect(executor.executor).to be_shutdown
      end
    end
  end
end
