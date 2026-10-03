require 'concurrent/atomic/count_down_latch'
require 'concurrent/edge/task_group'

RSpec.describe Concurrent::TaskGroup, edge: true do
  class GatedExecutor
    def initialize
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @jobs = []
      @released = false
    end

    def post(*args, &job)
      @mutex.synchronize { @jobs << job }
      Thread.new(args, job) do |job_args, queued_job|
        @mutex.synchronize { @condition.wait(@mutex) until @released }
        queued_job.call(*job_args)
      end
      true
    end

    def wait_for_job(timeout = 1)
      @mutex.synchronize do
        deadline = Time.now + timeout
        until @jobs.any?
          remaining = deadline - Time.now
          return false if remaining <= 0
          @condition.wait(@mutex, remaining)
        end
        true
      end
    end

    def jobs
      @mutex.synchronize { @jobs.dup }
    end

    def release
      @mutex.synchronize do
        @released = true
        @condition.broadcast
      end
    end
  end

  class RejectingExecutor
    def post(*)
      false
    end
  end

  describe '.wait' do
    it 'returns values from accepted tasks in submission order' do
      values = described_class.wait do |group|
        group.future { 2 }
        group.future { 1 + 2 }
      end

      expect(values).to eq [2, 3]
    end

    it 'waits for tasks submitted from inside running tasks' do
      values = described_class.wait do |group|
        group.future do |task|
          task.future { :nested }
          :outer
        end
      end

      expect(values).to eq [:outer]

      values = described_class.wait do |group|
        outer = group.future { |task| task.future { :nested }.value! }
        outer.value!
      end

      expect(values).to eq [:nested, :nested]
    end

    it 'signals running tasks and lets remaining tasks stop cooperatively after failure' do
      started = Concurrent::CountDownLatch.new(2)
      completed = Queue.new
      executor = Concurrent::FixedThreadPool.new(2, max_queue: -1)

      expect do
        described_class.wait(executor: executor) do |group|
          group.future do |task|
            started.count_down
            task.origin.wait
            completed << :running
          end

          group.future do
            started.count_down
            raise 'boom'
          end

          group.future do |task|
            task.check!
            completed << :queued
          end

          started.wait(1)
        end
      end.to raise_error(RuntimeError, 'boom')

      executor.shutdown
      executor.wait_for_termination(1)
      expect(completed.pop).to eq :running
      expect(completed.empty?).to eq true
    end

    it 'preserves every failure after waiting for accepted tasks' do
      error = nil

      begin
        described_class.wait do |group|
          group.future { raise 'one' }
          group.future do |task|
            task.origin.wait
            raise 'two'
          end
        end
      rescue => e
        error = e
      end

      expect(error).to be_a Concurrent::MultipleErrors
      expect(error.errors.map(&:message)).to match_array %w[one two]
    end

    it 'rejects submissions after scope exit with a rejected future' do
      escaped = nil

      described_class.wait do |group|
        escaped = group
        group.future { 1 }
      end

      future = escaped.future { 2 }

      expect(future).to be_rejected
      expect(future.reason).to be_a Concurrent::CancelledOperationError
    end

    it 'reports an executor rejection as a task failure' do
      expect do
        described_class.wait(executor: RejectingExecutor.new) do |group|
          group.future { 1 }
        end
      end.to raise_error(Concurrent::RejectedExecutionError)
    end

    it 'signals tasks when the scope itself fails' do
      observed = Queue.new

      expect do
        described_class.wait do |group|
          group.future do |task|
            task.origin.wait
            observed << true
          end

          sleep 0.01
          raise 'scope failed'
        end
      end.to raise_error(RuntimeError, 'scope failed')

      expect(observed.pop).to eq true
    end

    it 'does not turn a completed running task into a cancellation' do
      future = nil

      expect do
        described_class.wait do |group|
          future = group.future { :completed }
          future.wait!
          raise 'after completion'
        end
      end.to raise_error(RuntimeError, 'after completion')

      expect(future).to be_fulfilled
      expect(future.value).to eq :completed
    end

    it 'gives closing and a racing submission exactly one ownership' do
      executor = GatedExecutor.new
      group = described_class.new(executor: executor)
      group.future { :accepted }
      executor.wait_for_job

      closing = Thread.new { group.close }
      submitting = Thread.new do
        future = group.future { :racing }
        future.fulfilled? ? :accepted : :rejected
      end

      result = submitting.value
      closing.join
      executor.release
      group.wait

      expect([:accepted, :rejected]).to include result
      if result == :accepted
        expect(group.futures.map(&:value!)).to eq [:accepted, :racing]
      else
        expect(group.futures.map(&:value!)).to eq [:accepted]
      end
    end

    it 'propagates a parent cancellation signal to an explicit child group' do
      signaled = Queue.new

      expect do
        described_class.wait do |parent|
          parent.future do
            described_class.wait do |child|
              child.future do |task|
                task.origin.wait
                signaled << true
              end
            end
          end

          parent.future { raise 'parent failure' }
        end
      end.to raise_error(RuntimeError, 'parent failure')

      expect(signaled.pop).to eq true
      expect(signaled.empty?).to eq true
    end
  end
end
