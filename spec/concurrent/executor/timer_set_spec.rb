require 'concurrent/executor/timer_set'
require 'concurrent/atomic/count_down_latch'
require 'concurrent/atomic/atomic_boolean'
require 'timecop'

module Concurrent

  RSpec.describe TimerSet do

    let(:executor){ Concurrent::ImmediateExecutor.new }
    subject{ TimerSet.new(executor: executor) }

    after(:each){ subject.shutdown }

    context 'construction' do
      it 'uses the executor given at construction' do
        subject = TimerSet.new(executor: Concurrent.global_immediate_executor)
        expect(subject.instance_variable_get(:@task_executor)).to eq Concurrent.global_immediate_executor
      end

      it 'uses the global io executor be default' do
        subject = TimerSet.new
        expect(subject.instance_variable_get(:@task_executor)).to eq Concurrent.global_io_executor
      end
    end

    context '#post' do

      it 'raises an exception when given a task with a delay less than zero' do
        expect {
          subject.post(-10){ nil }
        }.to raise_error(ArgumentError)
      end

      it 'raises an exception when no block given' do
        expect {
          subject.post(10)
        }.to raise_error(ArgumentError)
      end

      it 'immediately posts a task when the delay is zero' do
        timer = subject.instance_variable_get(:@timer_executor)
        expect(timer).not_to receive(:post).with(any_args)
        subject.post(0){ true }
      end
    end

    context 'execution' do

      it 'executes a given task when given an interval in seconds' do
        latch = CountDownLatch.new(1)
        subject.post(0.1){ latch.count_down }
        expect(latch.wait(0.2)).to be_truthy
      end

      it 'returns an IVar when posting a task' do
        expect(subject.post(0.1) { nil }).to be_a Concurrent::IVar
      end

      it 'executes a given task when given an interval in seconds, even if longer tasks have been scheduled' do
        latch = CountDownLatch.new(1)
        subject.post(0.5){ nil }
        subject.post(0.1){ latch.count_down }
        expect(latch.wait(0.2)).to be_truthy
      end

      it 'passes all arguments to the task on execution' do
        expected = AtomicReference.new
        latch = CountDownLatch.new(1)
        subject.post(0.1, 1, 2, 3) do |*args|
          expected.value = args
          latch.count_down
        end
        expect(latch.wait(0.2)).to be_truthy
        expect(expected.value).to eq [1, 2, 3]
      end

      it 'does not execute tasks early' do
        latch = Concurrent::CountDownLatch.new(1)
        start = Time.now.to_f
        subject.post(0.2){ latch.count_down }
        expect(latch.wait(1)).to be true
        expect(Time.now.to_f - start).to be >= 0.19
      end

      it 'executes all tasks scheduled for the same time' do
        latch = CountDownLatch.new(5)
        5.times{ subject.post(0.1){ latch.count_down } }
        expect(latch.wait(1)).to be_truthy
      end

      it 'executes tasks with different times in schedule order' do
        latch = CountDownLatch.new(3)
        expected = []
        3.times{|i| subject.post(i/10){ expected << i; latch.count_down } }
        latch.wait(1)
        expect(expected).to eq [0, 1, 2]
      end

      it 'executes tasks with different times in schedule time' do
        tests = 3
        interval = 0.1
        latch = CountDownLatch.new(tests)
        expected = Queue.new
        start = Time.now

        (1..tests).each do |i|
          subject.post(interval * i) { expected << Time.now - start; latch.count_down }
        end

        expect(latch.wait((tests * interval) + 1)).to be true

        (1..tests).each do |i|
          delta = expected.pop
          expect(delta).to be_within(0.1).of((i * interval) + 0.05)
        end
      end

      it 'continues to execute new tasks even after the queue is emptied' do
        3.times do |i|
          task = subject.post(0.1){ i }
          expect(task.value).to eq i
        end
      end

      it 'safely handles an executor raising RejectedExecutionError' do
        # force a task's executor to raise RejectedExecutionError within the TimerSet
        abort_executor = ImmediateExecutor.new
        allow(abort_executor).to receive(:post).and_raise(Concurrent::RejectedExecutionError)
        ScheduledTask.execute(0.2, executor: abort_executor, timer_set: subject){ nil }
        abort_executor.shutdown

        latch = CountDownLatch.new(1)
        ScheduledTask.execute(0.3, timer_set: subject) do
          latch.count_down
        end
        expect(latch.wait(1)).to be_truthy
      end
    end

    context 'resolution' do

      it 'sets the IVar value on success when delay is zero' do
        job = subject.post(0){ 42 }
        expect(job.value).to eq 42
        expect(job.reason).to be_nil
        expect(job).to be_fulfilled
      end

      it 'sets the IVar value on success when given a delay' do
        job = subject.post(0.1){ 42 }
        expect(job.value).to eq 42
        expect(job.reason).to be_nil
        expect(job).to be_fulfilled
      end

      it 'sets the IVar reason on failure when delay is zero' do
        error = ArgumentError.new('expected error')
        job = subject.post(0){ raise error }
        expect(job.value).to be_nil
        expect(job.reason).to eq error
        expect(job).to be_rejected
      end

      it 'sets the IVar reason on failure when given a delay' do
        error = ArgumentError.new('expected error')
        job = subject.post(0.1){ raise error }
        expect(job.value).to be_nil
        expect(job.reason).to eq error
        expect(job).to be_rejected
      end
    end

    context 'task cancellation' do

      after(:each) do
        Timecop.return
      end

      it 'fails to cancel the task once processing has begun' do
        start_latch = Concurrent::CountDownLatch.new
        continue_latch = Concurrent::CountDownLatch.new
        job = subject.post(0.1) do
          start_latch.count_down
          continue_latch.wait(2)
          42
        end

        start_latch.wait(2)
        success = job.cancel
        continue_latch.count_down

        expect(success).to be false
        expect(job.value).to eq 42
        expect(job.reason).to be_nil
      end

      it 'fails to cancel the task once processing is complete' do
        job = subject.post(0.1){ 42 }

        job.wait(2)
        success = job.cancel

        expect(success).to be false
        expect(job.value).to eq 42
        expect(job.reason).to be_nil
      end

      it 'cancels a pending task' do
        actual = AtomicBoolean.new(false)
        Timecop.freeze
        job = subject.post(0.1){ actual.make_true }
        success = job.cancel
        Timecop.travel(1)
        expect(success).to be true
        expect(job.value(0)).to be_nil
        expect(job.reason).to be_a CancelledOperationError
      end

      it 'returns false when not running' do
        task = subject.post(10){ nil }
        subject.shutdown
        expect(expect(subject.wait_for_termination(pool_termination_timeout)).to eq true).to eq true
        expect(task.cancel).to be false
      end
    end

    context 'task rescheduling' do

      let(:queue) { subject.instance_variable_get(:@queue) }

      it 'raises an exception when given an invalid time' do
        task = subject.post(10){ nil }
        expect{ task.reschedule(-1) }.to raise_error(ArgumentError)
      end

      it 'does not change the current schedule when given an invalid time' do
        task = subject.post(10){ nil }
        expected = task.schedule_time
        begin
          task.reschedule(-1)
        rescue
        end
        expect(task.schedule_time).to eq expected
      end

      it 'reschedules a pending and unpost task when given a valid time' do
        initial_delay = 10
        rescheduled_delay = 20
        task = subject.post(initial_delay){ nil }
        original_schedule = task.schedule_time
        success = task.reschedule(rescheduled_delay)
        expect(success).to be true
        expect(task.initial_delay).to be_within(0.01).of(rescheduled_delay)
        expect(task.schedule_time).to be > original_schedule
      end

      it 'returns false once the task has been post to the executor' do
        start_latch = Concurrent::CountDownLatch.new
        continue_latch = Concurrent::CountDownLatch.new

        task = subject.post(0.1) do
          start_latch.count_down
          continue_latch.wait(2)
        end
        start_latch.wait(2)

        expected = task.schedule_time
        success = task.reschedule(10)
        continue_latch.count_down
        expect(success).to be false
        expect(task.schedule_time).to eq expected
      end

      it 'returns false once the task is processing' do
        start_latch = Concurrent::CountDownLatch.new
        continue_latch = Concurrent::CountDownLatch.new
        task = subject.post(0.1) do
          start_latch.count_down
          continue_latch.wait(2)
        end
        start_latch.wait(2)

        expected = task.schedule_time
        success = task.reschedule(10)
        continue_latch.count_down
        expect(success).to be false
        expect(task.schedule_time).to eq expected
      end

      it 'returns false once the task has is complete' do
        task = subject.post(0.1){ nil }
        task.value(2)
        expected = task.schedule_time
        success = task.reschedule(10)
        expect(success).to be false
        expect(task.schedule_time).to eq expected
      end

      it 'returns false when not running' do
        task = subject.post(10){ nil }
        subject.shutdown
        expect(expect(subject.wait_for_termination(pool_termination_timeout)).to eq true).to eq true
        expected = task.schedule_time
        success = task.reschedule(10)
        expect(success).to be false
        expect(task.schedule_time).to be_within(0.01).of(expected)
      end
    end

    context 'task resetting' do

      it 'calls #reschedule with the original delay' do
        initial_delay = 10
        task = subject.post(initial_delay){ nil }
        expect(task).to receive(:ns_reschedule).with(initial_delay)
        task.reset
      end
    end

    context 'termination' do

      it 'cancels all pending tasks on #shutdown' do
        queue = subject.instance_variable_get(:@queue)
        expect(queue).to receive(:clear).with(no_args).at_least(:once)
        subject.shutdown
      end

      it 'cancels all pending tasks on #kill' do
        queue = subject.instance_variable_get(:@queue)
        expect(queue).to receive(:clear).with(no_args).at_least(:once)
        subject.kill
      end

      it 'stops the monitor thread on #shutdown' do
        timer_executor = subject.instance_variable_get(:@timer_executor)
        subject.shutdown
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        expect(timer_executor).not_to be_running
      end

      it 'kills the monitor thread on #kill' do
        timer_executor = subject.instance_variable_get(:@timer_executor)
        subject.kill
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        expect(timer_executor).not_to be_running
      end

      it 'rejects tasks once shutdown' do
        queue = subject.instance_variable_get(:@queue)
        subject.shutdown
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        subject.post(1) { nil }
        expect(queue).to be_empty
      end

      it 'rejects tasks once killed' do
        queue = subject.instance_variable_get(:@queue)
        subject.kill
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        subject.post(1) { nil }
        expect(queue).to be_empty
      end

      specify '#wait_for_termination returns true if shutdown completes before timeout' do
        latch = Concurrent::CountDownLatch.new(1)
        subject.post(0){ latch.count_down }
        latch.wait(1)
        subject.shutdown
        expect(subject.wait_for_termination(pool_termination_timeout)).to be_truthy
      end

      specify '#wait_for_termination returns false on timeout' do
        latch = Concurrent::CountDownLatch.new(1)
        subject.post(0){ latch.count_down }
        latch.wait(0.1)
        # do not call shutdown -- force timeout
        expect(subject.wait_for_termination(0.1)).to be_falsey
      end
    end

    context 'state' do

      it 'is running? when first created' do
        expect(subject).to be_running
        expect(subject).not_to be_shutdown
      end

      it 'is running? after tasks have been post' do
        subject.post(0.1){ nil }
        expect(subject).to be_running
        expect(subject).not_to be_shutdown
      end

      it 'is shutdown? after shutdown completes' do
        subject.shutdown
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        expect(subject).not_to be_running
        expect(subject).to be_shutdown
      end

      it 'is shutdown? after being killed' do
        subject.kill
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        expect(subject).not_to be_running
        expect(subject).to be_shutdown
      end
    end

    context 'manual clock' do

      let(:executor){ Concurrent::ImmediateExecutor.new }
      subject{ TimerSet.new(executor: executor, clock: :manual) }

      it 'reports the clock mode and a virtual time starting at zero' do
        expect(subject).to be_manual_clock
        expect(subject.current_time).to eq 0.0
      end

      it 'does not start the background timer thread' do
        timer = subject.instance_variable_get(:@timer_executor)
        expect(timer).not_to receive(:post)
        subject.post(10){ nil }
      end

      it 'does not execute tasks before the clock is advanced' do
        executed = AtomicBoolean.new(false)
        subject.post(5){ executed.make_true }
        subject.advance_to(4)
        expect(executed.true?).to be false
      end

      it 'executes tasks due at the advanced time' do
        executed = AtomicBoolean.new(false)
        subject.post(5){ executed.make_true }
        subject.advance_to(5)
        expect(executed.true?).to be true
      end

      it 'executes zero-delay tasks without advancing the clock' do
        executed = AtomicBoolean.new(false)
        subject.post(0){ executed.make_true }
        subject.advance(0)
        expect(executed.true?).to be true
      end

      it 'advances the virtual clock by a relative amount' do
        executed = AtomicBoolean.new(false)
        subject.post(2.5){ executed.make_true }
        subject.advance(2)
        expect(executed.true?).to be false
        expect(subject.current_time).to be_within(0.0001).of(2.0)
        subject.advance(0.5)
        expect(executed.true?).to be true
        expect(subject.current_time).to be_within(0.0001).of(2.5)
      end

      it 'does not execute future tasks while processing earlier ones' do
        later = AtomicBoolean.new(false)
        subject.post(10){ later.make_true }
        subject.advance_to(5)
        expect(later.true?).to be false
        subject.advance_to(10)
        expect(later.true?).to be true
      end

      it 'executes tasks with the same deadline in submission order' do
        order = []
        5.times { |i| subject.post(1){ order << i } }
        subject.advance_to(1)
        expect(order).to eq [0, 1, 2, 3, 4]
      end

      it 'runs callback-added due tasks after previously queued same-deadline tasks' do
        order = []
        subject.post(1) { order << :first }
        subject.post(1) { order << :second }
        subject.post(1) do
          order << :third
          subject.post(0){ order << :added }
        end
        subject.advance_to(1)
        expect(order).to eq [:first, :second, :third, :added]
      end

      it 'processes newly due tasks scheduled from a callback in the same advance' do
        executed = AtomicBoolean.new(false)
        subject.post(1) do
          subject.post(0){ executed.make_true }
        end
        subject.advance_to(1)
        expect(executed.true?).to be true
      end

      it 'bounds the number of executed tasks and leaves a resumable state' do
        count = 0
        schedule = nil
        schedule = lambda do
          subject.post(0){ count += 1; schedule.call }
        end
        schedule.call

        executed = subject.advance_to(1, 10)
        expect(executed).to eq 10
        expect(count).to eq 10
        expect(subject.current_time).to eq 1.0

        more = subject.advance(0, 5)
        expect(more).to eq 5
        expect(count).to eq 15
      end

      it 'stops at the cap even when no callback adds tasks' do
        executed = []
        3.times { |i| subject.post(0){ executed << i } }
        expect(subject.advance_to(1, 2)).to eq 2
        expect(executed).to eq [0, 1]
        expect(subject.advance(0)).to eq 1
        expect(executed).to eq [0, 1, 2]
      end

      it 'returns the number of executed tasks' do
        3.times { subject.post(1){ nil } }
        subject.post(2){ nil }
        expect(subject.advance_to(1)).to eq 3
        expect(subject.advance_to(2)).to eq 1
      end

      it 'keeps cancelled tasks from running on advance' do
        executed = AtomicBoolean.new(false)
        task = subject.post(5){ executed.make_true }
        expect(task.cancel).to be true
        subject.advance_to(5)
        expect(executed.true?).to be false
      end

      it 'honors reschedule relative to the virtual clock' do
        executed = AtomicBoolean.new(false)
        task = subject.post(5){ executed.make_true }
        subject.advance_to(3)
        expect(task.reschedule(4)).to be true
        subject.advance_to(6)
        expect(executed.true?).to be false
        subject.advance_to(7)
        expect(executed.true?).to be true
      end

      it 'raises when advancing backwards' do
        subject.advance_to(5)
        expect { subject.advance_to(4) }.to raise_error(ArgumentError)
        expect { subject.advance(-1) }.to raise_error(ArgumentError)
      end

      it 'raises for a non-positive task limit' do
        expect { subject.advance_to(1, 0) }.to raise_error(ArgumentError)
        expect { subject.advance_to(1, -1) }.to raise_error(ArgumentError)
      end

      it 'refuses advance on a real clock set' do
        real_set = TimerSet.new(executor: executor)
        expect { real_set.advance_to(1) }.to raise_error(ArgumentError)
        real_set.shutdown
      end
    end
  end
end
