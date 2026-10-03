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

      subject{ TimerSet.manual(executor: executor) }

      it 'can be constructed with the :clock option' do
        timers = TimerSet.new(executor: executor, clock: :manual)
        expect(timers).to be_manual_clock
        expect(timers.now).to eq 0.0
      end

      it 'is not a manual clock by default' do
        timers = TimerSet.new(executor: executor)
        expect(timers).not_to be_manual_clock
        timers.shutdown
        expect(timers.wait_for_termination(pool_termination_timeout)).to eq true
      end

      it 'rejects an unknown clock mode' do
        expect { TimerSet.new(clock: :bogus) }.to raise_error(ArgumentError)
      end

      it 'does not allow advancing a real clock timer set' do
        timers = TimerSet.new(executor: executor)
        expect { timers.advance(1) }.to raise_error(ArgumentError)
        expect { timers.advance_to(1) }.to raise_error(ArgumentError)
        timers.shutdown
        expect(timers.wait_for_termination(pool_termination_timeout)).to eq true
      end

      it 'rejects a non-positive execution limit' do
        expect { TimerSet.manual(max_tasks_per_advance: 0) }.to raise_error(ArgumentError)
        expect { TimerSet.manual(max_tasks_per_advance: -1) }.to raise_error(ArgumentError)
      end

      it 'does not execute tasks until the clock is advanced' do
        executed = AtomicBoolean.new(false)
        subject.post(1) { executed.make_true }
        expect(executed.value).to be false
      end

      it 'never posts work to the timer monitor executor' do
        timer_executor = subject.instance_variable_get(:@timer_executor)
        monitor_posts = 0
        timer_executor.singleton_class.send(:alias_method, :__original_post, :post)
        timer_executor.define_singleton_method(:post) do |*args, &block|
          monitor_posts += 1
          __original_post(*args, &block)
        end
        subject.post(1) { nil }
        subject.advance(0)
        expect(monitor_posts).to eq 0
      end

      it 'reports the virtual clock time' do
        subject.advance(2.5)
        expect(subject.now).to eq 2.5
        subject.advance_to(10)
        expect(subject.now).to eq 10.0
      end

      it 'refuses to move the clock backwards' do
        subject.advance(5)
        expect { subject.advance_to(4) }.to raise_error(ArgumentError)
        expect(subject.now).to eq 5.0
      end

      it 'refuses a negative advance' do
        expect { subject.advance(-1) }.to raise_error(ArgumentError)
        expect(subject.now).to eq 0.0
      end

      it 'executes a due task when advanced by the delay' do
        latch = CountDownLatch.new(1)
        subject.post(1) { latch.count_down }
        subject.advance(1)
        expect(latch.wait(0.2)).to be_truthy
      end

      it 'executes a due task when advanced to its schedule time' do
        latch = CountDownLatch.new(1)
        subject.post(3) { latch.count_down }
        subject.advance_to(3)
        expect(latch.wait(0.2)).to be_truthy
      end

      it 'executes a zero delay task on the first advance' do
        latch = CountDownLatch.new(1)
        subject.post(0) { latch.count_down }
        subject.advance(0)
        expect(latch.wait(0.2)).to be_truthy
      end

      it 'does not execute tasks scheduled beyond the new time' do
        executed = AtomicBoolean.new(false)
        subject.post(5) { executed.make_true }
        subject.advance(4)
        expect(executed).not_to be_true
      end

      it 'executes overdue tasks without further delay' do
        latch = CountDownLatch.new(1)
        subject.post(1) { latch.count_down }
        subject.advance(3)
        expect(latch.wait(0.2)).to be_truthy
      end

      it 'returns the number of dispatched tasks' do
        2.times { subject.post(1) { nil } }
        subject.post(5) { nil }
        expect(subject.advance(2)).to eq 2
        expect(subject.advance(3)).to eq 1
      end

      it 'executes tasks with the same deadline in submission order' do
        order = []
        3.times { |i| subject.post(1) { order << i } }
        subject.advance(1)
        expect(order).to eq [0, 1, 2]
      end

      it 'executes callbacks scheduled by an earlier callback within the same advance' do
        events = Queue.new
        subject.post(1) do
          events << :first
          subject.post(0) { events << :second }
        end
        subject.advance(1)
        expect(events.length).to eq 2
        expect([events.pop, events.pop]).to eq [:first, :second]
      end

      it 'does not execute a callback task scheduled with a positive delay until it is due' do
        events = Queue.new
        subject.post(1) do
          events << :first
          subject.post(1) { events << :second }
        end
        subject.advance(2)
        expect(events.length).to eq 1
        expect(events.pop).to eq :first
        subject.advance(1)
        expect(events.length).to eq 1
        expect(events.pop).to eq :second
      end

      it 'stops after the execution limit and leaves remaining tasks queued' do
        timers = TimerSet.manual(executor: executor, max_tasks_per_advance: 2)
        executed = Queue.new
        3.times { |i| timers.post(1) { executed << i } }

        expect(timers.advance(1)).to eq 2
        expect(executed.length).to eq 2
        expect(timers.now).to eq 1.0

        expect(timers.advance(0)).to eq 1
        expect(executed.length).to eq 3
        timers.shutdown
        expect(timers.wait_for_termination(pool_termination_timeout)).to eq true
      end

      it 'caps self-rescheduling zero delay callbacks so an advance can finish' do
        timers = TimerSet.manual(executor: Concurrent::ImmediateExecutor.new, max_tasks_per_advance: 3)
        count = 0
        reschedule = nil
        reschedule = proc do
          count += 1
          timers.post(0, &reschedule)
        end
        timers.post(0, &reschedule)

        expect { timers.advance(0) }.not_to raise_error
        expect(count).to eq 3
        expect(timers.advance(0)).to eq 3
        expect(count).to eq 6
        timers.shutdown
        expect(timers.wait_for_termination(pool_termination_timeout)).to eq true
      end

      it 'keeps a pending ScheduledTask cancellable before it is due' do
        executed = AtomicBoolean.new(false)
        task = subject.post(1) { executed.make_true }
        expect(task.cancel).to be true
        subject.advance(1)
        expect(executed.value).to be false
        expect(task.reason).to be_a CancelledOperationError
      end

      it 'completes the ScheduledTask after advancing' do
        task = subject.post(1) { 42 }
        subject.advance(1)
        expect(task.value(0.2)).to eq 42
        expect(task).to be_fulfilled
      end

      it 'honors reschedule before advancing' do
        task = subject.post(1) { 42 }
        original_schedule = task.schedule_time
        expect(task.reschedule(5)).to be true
        subject.advance(2)
        expect(task.pending?).to be true
        subject.advance(3)
        expect(task.value(0.2)).to eq 42
        expect(task.schedule_time).to be > original_schedule
      end

      it 'rejects new tasks after shutdown' do
        subject.shutdown
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        expect(subject.post(1) { nil }).to be false
      end

      it 'dispatches nothing when advanced after shutdown' do
        latch = CountDownLatch.new(1)
        subject.post(1) { latch.count_down }
        subject.shutdown
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
        expect(subject.advance(1)).to eq 0
        expect(latch.wait(0.1)).to be_falsey
      end
    end
  end
end
