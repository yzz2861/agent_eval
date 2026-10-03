require 'concurrent/scheduled_task'
require 'concurrent/atomic/event'
require 'concurrent/collection/non_concurrent_priority_queue'
require 'concurrent/executor/executor_service'
require 'concurrent/executor/single_thread_executor'
require 'concurrent/errors'
require 'concurrent/options'

module Concurrent

  # Executes a collection of tasks, each after a given delay. A master task
  # monitors the set and schedules each task for execution at the appropriate
  # time. Tasks are run on the global thread pool or on the supplied executor.
  # Each task is represented as a `ScheduledTask`.
  #
  # A timer set can either follow the real monotonic clock (the default) or a
  # manually controlled clock. A manual timer set never starts the monitor
  # thread and no task is performed until the clock is advanced with
  # {#advance} or {#advance_to}. Every task whose schedule time is not later
  # than the new clock time is then dispatched to the task executor, including
  # tasks that become due while those callbacks run. This makes timer sets
  # deterministic and suitable for testing without waiting real time.
  #
  # @example A manually driven timer set
  #
  #   timers = Concurrent::TimerSet.new(clock: :manual)
  #   timers.post(5) { puts 'five seconds later' }
  #   timers.advance(5) # the block is performed here, without a real delay
  #
  # @see Concurrent::ScheduledTask
  #
  # @!macro monotonic_clock_warning
  class TimerSet < RubyExecutorService

    # Create a new set of timed tasks.
    #
    # @!macro executor_options
    #
    #   @param [Hash] opts the options used to specify the executor on which to perform actions
    #   @option opts [Executor] :executor when set use the given `Executor` instance.
    #     Three special values are also supported: `:task` returns the global task pool,
    #     `:operation` returns the global operation pool, and `:immediate` returns a new
    #     `ImmediateExecutor` object.
    #   @option opts [Symbol] :clock (:real) `:real` follows the system monotonic clock
    #     and runs a monitor thread; `:manual` keeps a clock that only moves when
    #     {#advance} or {#advance_to} is called.
    #   @option opts [Integer] :max_tasks_per_advance (nil) maximum number of due
    #     tasks dispatched by a single {#advance}/{#advance_to} call in `:manual`
    #     clock mode. When the limit is reached the remaining due tasks stay queued
    #     and the clock can be advanced again to continue. Defaults to no limit.
    def initialize(opts = {})
      super(opts)
    end

    # Create a new timer set driven by a manual clock.
    #
    # @param [Hash] opts the options accepted by {#initialize}, except `:clock`
    #
    # @return [TimerSet] a timer set in `:manual` clock mode
    #
    # @see #initialize
    def self.manual(opts = {})
      new(opts.merge(clock: :manual))
    end

    # Post a task to be execute run after a given delay (in seconds). If the
    # delay is less than 1/100th of a second the task will be immediately post
    # to the executor.
    #
    # @param [Float] delay the number of seconds to wait for before executing the task.
    # @param [Array<Object>] args the arguments passed to the task on execution.
    #
    # @yield the task to be performed.
    #
    # @return [Concurrent::ScheduledTask, false] IVar representing the task if the post
    #   is successful; false after shutdown.
    #
    # @raise [ArgumentError] if the intended execution time is not in the future.
    # @raise [ArgumentError] if no block is given.
    def post(delay, *args, &task)
      raise ArgumentError.new('no block given') unless block_given?
      return false unless running?
      opts = { executor:  @task_executor,
               args:      args,
               timer_set: self }
      task = ScheduledTask.execute(delay, opts, &task) # may raise exception
      task.unscheduled? ? false : task
    end

    # Is this timer set driven by a manual clock?
    #
    # @return [Boolean] true when the timer set uses a manual clock else false
    def manual_clock?
      synchronize { @manual_clock }
    end

    # The current time of the clock used to schedule tasks. The time uses the
    # same monotonic scale as `Concurrent.monotonic_time`; a manual clock starts
    # at zero.
    #
    # @return [Float] the current clock time in seconds
    def now
      synchronize { ns_current_time }
    end

    # Move a manual clock forward by the given number of seconds and perform
    # all tasks that become due up to the new time.
    #
    # @param [Float] seconds the number of seconds to move the clock forward
    #
    # @return [Integer] the number of due tasks dispatched to the task executor
    #
    # @raise [ArgumentError] when the timer set does not use a manual clock
    # @raise [ArgumentError] when `seconds` is negative
    #
    # @see #advance_to
    def advance(seconds)
      advance_to(now + seconds.to_f)
    end

    # Move a manual clock to the given monotonic time and perform all tasks
    # that become due up to the new time. Tasks are dispatched in schedule
    # order and tasks with the same schedule time are dispatched in the order
    # they were submitted. Tasks added by callbacks are processed in the same
    # call when their schedule time is not later than the new clock time. When
    # the configured `:max_tasks_per_advance` limit is reached the clock is
    # left at the new time and the remaining due tasks stay queued for a
    # subsequent call.
    #
    # @param [Float] time the monotonic time to move the clock to
    #
    # @return [Integer] the number of due tasks dispatched to the task executor
    #
    # @raise [ArgumentError] when the timer set does not use a manual clock
    # @raise [ArgumentError] when `time` is earlier than the current clock time
    def advance_to(time)
      time = time.to_f
      synchronize do
        raise ArgumentError.new('timer set does not use a manual clock') unless @manual_clock
        raise ArgumentError.new('cannot move the manual clock backwards') if time < @clock_time
        @clock_time = time
      end

      executed = 0
      loop do
        task = synchronize { ns_next_due_task(executed) }
        break unless task

        begin
          task.executor.post { task.process_task }
        rescue RejectedExecutionError
          # ignore and continue
        end
        executed += 1
      end
      executed
    end

    # Begin an immediate shutdown. In-progress tasks will be allowed to
    # complete but enqueued tasks will be dismissed and no new tasks
    # will be accepted. Has no additional effect if the thread pool is
    # not running.
    def kill
      shutdown
      @timer_executor.kill
    end

    private :<<

    private

    # Initialize the object.
    #
    # @param [Hash] opts the options to create the object with.
    # @!visibility private
    def ns_initialize(opts)
      @queue              = Collection::NonConcurrentPriorityQueue.new(order: :min)
      @task_executor      = Options.executor_from_options(opts) || Concurrent.global_io_executor
      @timer_executor     = SingleThreadExecutor.new
      @condition          = Event.new
      @ruby_pid           = $$ # detects if Ruby has forked

      clock = opts.fetch(:clock, :real).to_sym
      unless [:real, :manual].include?(clock)
        raise ArgumentError.new("unsupported clock mode: #{opts[:clock].inspect}")
      end
      @manual_clock          = clock == :manual
      @clock_time            = 0.0
      @queue_sequence        = 0
      @max_tasks_per_advance = opts[:max_tasks_per_advance]
      if !@max_tasks_per_advance.nil? &&
         (!@max_tasks_per_advance.is_a?(Integer) || @max_tasks_per_advance <= 0)
        raise ArgumentError.new(':max_tasks_per_advance must be a positive integer')
      end
    end

    # The time used to place newly scheduled tasks on the clock.
    #
    # @!visibility private
    def current_time
      synchronize { ns_current_time }
    end

    # Post the task to the internal queue.
    #
    # @note This is intended as a callback method from ScheduledTask
    #   only. It is not intended to be used directly. Post a task
    #   by using the `SchedulesTask#execute` method.
    #
    # @!visibility private
    def post_task(task)
      synchronize { ns_post_task(task) }
    end

    # @!visibility private
    def ns_post_task(task)
      return false unless ns_running?
      ns_reset_if_forked
      if @manual_clock
        task.queue_order = (@queue_sequence += 1)
        @queue.push(task)
      elsif (task.initial_delay) <= 0.01
        task.executor.post { task.process_task }
      else
        task.queue_order = (@queue_sequence += 1)
        @queue.push(task)
        # only post the process method when the queue is empty
        @timer_executor.post(&method(:process_tasks)) if @queue.length == 1
        @condition.set
      end
      true
    end

    # Remove the given task from the queue.
    #
    # @note This is intended as a callback method from `ScheduledTask`
    #   only. It is not intended to be used directly. Cancel a task
    #   by using the `ScheduledTask#cancel` method.
    #
    # @!visibility private
    def remove_task(task)
      synchronize { @queue.delete(task) }
    end

    # `ExecutorService` callback called during shutdown.
    #
    # @!visibility private
    def ns_shutdown_execution
      ns_reset_if_forked
      @queue.clear
      @condition.set
      @condition.reset
      @timer_executor.shutdown
      stopped_event.set
    end

    def ns_reset_if_forked
      if $$ != @ruby_pid
        @queue.clear
        @condition.reset
        @ruby_pid = $$
      end
    end

    # The current clock time without locking.
    #
    # @!visibility private
    def ns_current_time
      @manual_clock ? @clock_time : Concurrent.monotonic_time
    end

    # Remove and return the next task due at the current manual clock time,
    # respecting the per-advance execution limit.
    #
    # @!visibility private
    def ns_next_due_task(executed)
      return nil if @queue.empty?
      return nil if @max_tasks_per_advance && executed >= @max_tasks_per_advance
      task = @queue.peek
      return nil unless task.schedule_time <= @clock_time
      @queue.pop
    end

    # Run a loop and execute tasks in the scheduled order and at the approximate
    # scheduled time. If no tasks remain the thread will exit gracefully so that
    # garbage collection can occur. If there are no ready tasks it will sleep
    # for up to 60 seconds waiting for the next scheduled task.
    #
    # @!visibility private
    def process_tasks
      loop do
        task = synchronize { @condition.reset; @queue.peek }
        break unless task

        now  = Concurrent.monotonic_time
        diff = task.schedule_time - now

        if diff <= 0
          # We need to remove the task from the queue before passing
          # it to the executor, to avoid race conditions where we pass
          # the peek'ed task to the executor and then pop a different
          # one that's been added in the meantime.
          #
          # Note that there's no race condition between the peek and
          # this pop - this pop could retrieve a different task from
          # the peek, but that task would be due to fire now anyway
          # (because @queue is a priority queue, and this thread is
          # the only reader, so whatever timer is at the head of the
          # queue now must have the same pop time, or a closer one, as
          # when we peeked).
          task = synchronize { @queue.pop }
          begin
            task.executor.post { task.process_task }
          rescue RejectedExecutionError
            # ignore and continue
          end
        else
          @condition.wait([diff, 60].min)
        end
      end
    end
  end
end
