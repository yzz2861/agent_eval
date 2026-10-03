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
    #   @option opts [Symbol] :clock (:real) selects the clock used to schedule tasks.
    #     `:real` uses the system monotonic clock and a background thread which waits
    #     until each task is due. `:manual` uses a virtual monotonic clock starting at
    #     zero which only moves when {#advance_to} or {#advance} is called; no
    #     background thread is used, which makes scheduled tasks deterministic in
    #     tests.
    def initialize(opts = {})
      super(opts)
    end

    # Whether this set uses a virtual clock that can only be moved with
    # {#advance_to} or {#advance}.
    #
    # @return [Boolean] true when created with `clock: :manual`
    def manual_clock?
      synchronize { @manual_clock }
    end

    # The current value of the clock used to schedule tasks. In real clock mode
    # this is the system monotonic time; in manual clock mode it is the virtual
    # time set by {#advance_to} or {#advance} (zero before the first advance).
    #
    # @return [Float] the current monotonic time in seconds
    def current_time
      synchronize { ns_current_time }
    end

    # In manual clock mode, advance the virtual clock to the given monotonic
    # time and post every task scheduled at or before that time to its executor.
    # Tasks scheduled for the same time are posted in the order in which they were
    # submitted, and tasks that become due while a due task is running (including
    # tasks posted from within a task callback) are processed in the same call as
    # long as they are due by `time`.
    #
    # If `max_tasks` is given and more than that many due tasks remain, the
    # virtual clock is still moved to `time` but only `max_tasks` tasks are
    # posted; the rest stay queued and can be processed by another call to
    # {#advance_to} (or {#advance}) with a later or equal time. This prevents
    # callbacks that endlessly schedule zero-delay tasks from looping forever.
    #
    # @param [Float] time the absolute virtual time to advance to, in seconds
    # @param [Integer, nil] max_tasks maximum number of tasks to post during
    #   this call; nil means no limit
    #
    # @return [Integer] the number of tasks posted to executors
    #
    # @raise [ArgumentError] when not using a manual clock, when `time` is in the
    #   past of the virtual clock, or when `max_tasks` is not positive
    def advance_to(time, max_tasks = nil)
      time = time.to_f
      max_tasks = validate_max_tasks(max_tasks)
      synchronize do
        raise ArgumentError.new('manual clock is not enabled') unless @manual_clock
        raise ArgumentError.new('time cannot be in the past') if time < @manual_time
        raise ArgumentError.new('cannot advance while shutting down') unless ns_running?

        @manual_time = time
        @advance_target_time = time
      end
      process_due_tasks(max_tasks)
    end

    # In manual clock mode, advance the virtual clock by `seconds` relative to
    # the current virtual time. See {#advance_to} for processing order and the
    # `max_tasks` cap.
    #
    # @param [Float] seconds the number of virtual seconds to advance by
    # @param [Integer, nil] max_tasks maximum number of tasks to post during
    #   this call; nil means no limit
    #
    # @return [Integer] the number of tasks posted to executors
    #
    # @raise [ArgumentError] when not using a manual clock, when `seconds` is
    #   negative, or when `max_tasks` is not positive
    def advance(seconds, max_tasks = nil)
      seconds = seconds.to_f
      raise ArgumentError.new('seconds cannot be negative') if seconds < 0.0
      advance_to(current_time + seconds, max_tasks)
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
      @manual_clock       = opts.fetch(:clock, :real) == :manual
      @manual_time        = 0.0
      @advance_target_time = nil
      @sequence           = 0
    end

    # Current monotonic time of the configured clock. Must be called under
    # the lock.
    #
    # @!visibility private
    def ns_current_time
      if @manual_clock
        # Tasks scheduled from callbacks during an advance are stamped with
        # the advance target so that already-queued tasks due at that same
        # instant keep their submission-order precedence. It equals
        # @manual_time between advances, so ordinary scheduling is unaffected.
        @advance_target_time || @manual_time
      else
        Concurrent.monotonic_time
      end
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
      if !@manual_clock && (task.initial_delay) <= 0.01
        task.executor.post { task.process_task }
      else
        task.schedule_order = @sequence
        @sequence += 1
        @queue.push(task)
        # only post the process method when the queue is empty
        @timer_executor.post(&method(:process_tasks)) if !@manual_clock && @queue.length == 1
        @condition.set
      end
      true
    end

    # Post all queued tasks scheduled at or before the current clock time to
    # their executors, in schedule-time then submission order. Each task is
    # removed under the lock but posted to its executor outside the lock, so
    # callbacks that post or cancel tasks can re-enter the lock freely.
    #
    # @param [Integer, nil] max_tasks maximum number of tasks to post
    #
    # @return [Integer] the number of tasks posted
    #
    # @!visibility private
    def process_due_tasks(max_tasks)
      executed = 0
      loop do
        due_task = nil
        done = synchronize do
          task = @queue.peek
          if task.nil? || task.schedule_time > ns_current_time
            true
          elsif max_tasks && executed >= max_tasks
            true
          else
            due_task = @queue.pop
            false
          end
        end
        break if done

        begin
          due_task.executor.post { due_task.process_task }
          executed += 1
        rescue RejectedExecutionError
          # ignore and continue
        end
      end
      executed
    end

    # @!visibility private
    def validate_max_tasks(max_tasks)
      return nil if max_tasks.nil?
      max_tasks = max_tasks.to_i
      raise ArgumentError.new('max_tasks must be greater than zero') if max_tasks <= 0
      max_tasks
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
