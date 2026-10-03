require 'concurrent/errors'
require 'concurrent/executor/executor_service'
require 'concurrent/executor/cached_thread_pool'
require 'concurrent/ivar'
require 'concurrent/synchronization/lockable_object'

module Concurrent

  # An executor wrapper which guarantees that tasks submitted with the same
  # key are executed sequentially and in submission order, while tasks with
  # different keys may run in parallel on the shared underlying executor.
  #
  # Every {#post} returns a {Concurrent::IVar} which is fulfilled with the
  # task's return value, or rejected with the error the task raised. A
  # failing task never blocks the rest of its key's queue: subsequent tasks
  # submitted with the same key are executed normally.
  #
  # When the underlying executor refuses a task (it raises
  # {RejectedExecutionError} or returns +false+), the affected task's IVar
  # is rejected and the key's chain keeps moving, so neither the chain nor
  # the caller is ever stuck.
  #
  # Per-key bookkeeping is dropped as soon as the key's queue drains, so
  # state does not accumulate for keys which are no longer in use.
  class KeyedExecutor < Synchronization::LockableObject
    include ExecutorService

    # @return [ExecutorService] the executor tasks are delegated to
    attr_reader :executor

    # Create a new keyed executor.
    #
    # @param [ExecutorService] executor the executor used to run the tasks.
    #   When omitted, an internal {CachedThreadPool} is created and owned by
    #   this instance (see {#owns_executor?}).
    # @param [Hash] opts options used to build the owned executor, ignored
    #   when +executor+ is given
    def initialize(executor = nil, opts = {})
      super()
      synchronize do
        if executor
          @executor      = executor
          @owns_executor = false
        else
          @executor      = CachedThreadPool.new(opts)
          @owns_executor = true
        end
        @chains      = {}
        @running     = true
        @active_jobs = 0
      end
    end

    # Does this instance shut down the underlying executor when it is itself
    # shut down? True only when the executor was created internally.
    #
    # @return [Boolean]
    def owns_executor?
      @owns_executor
    end

    # The number of keys currently tracked, i.e. keys with queued or running
    # tasks. Idle keys are not tracked.
    #
    # @return [Integer]
    def key_count
      synchronize { @chains.size }
    end

    # Submit a task to be executed once all previously submitted tasks with
    # an equal key have completed.
    #
    # @param [Object] key tasks with equal keys are serialized
    # @param [Array] args zero or more arguments to be passed to the task
    #
    # @yield the asynchronous task to perform
    #
    # @return [IVar] fulfilled with the task result or rejected with the
    #   error the task raised; rejected with {RejectedExecutionError} when
    #   the task cannot be accepted
    #
    # @raise [ArgumentError] if no task is given
    def post(key, *args, &task)
      raise ArgumentError.new('no block given') unless block_given?

      result = IVar.new
      job    = Job.new(args, task, result)

      accepted, job_to_schedule = synchronize do
        if @running
          chain = (@chains[key] ||= Chain.new)
          chain.jobs.push job
          @active_jobs += 1
          if chain.running
            [true, nil]
          else
            chain.running = true
            [true, chain.jobs.shift]
          end
        else
          [false, nil]
        end
      end

      if accepted
        schedule key, job_to_schedule if job_to_schedule
      else
        result.fail RejectedExecutionError.new('executor is shutdown')
      end
      result
    end

    # Submit a task to be executed once all previously submitted tasks with
    # an equal key have completed.
    #
    # @param [Array(Object, Proc)] key_and_task a pair of the key and the
    #   task to perform
    #
    # @return [self] returns itself
    def <<(key_and_task)
      key, task = key_and_task
      post(key, &task)
      self
    end

    # @!macro executor_service_method_can_overflow_question
    def can_overflow?
      executor.can_overflow?
    end

    # @!macro executor_service_method_shutdown
    #
    # The underlying executor is shut down as well, but only when it is
    # owned by this instance (see {#owns_executor?}).
    def shutdown
      owned = synchronize do
        if @running
          @running = false
          ns_broadcast if ns_terminated?
          @owns_executor
        end
      end
      executor.shutdown if owned
      true
    end

    # @!macro executor_service_method_kill
    #
    # Queued tasks are dismissed and their IVars are rejected with
    # {RejectedExecutionError}; in-progress tasks are allowed to complete.
    # The underlying executor is killed as well, but only when it is owned
    # by this instance (see {#owns_executor?}).
    def kill
      dropped, owned = synchronize do
        if @running
          @running = false
          jobs     = []
          @chains.each_value do |chain|
            chain.jobs.each do |job|
              @active_jobs -= 1
              jobs << job
            end
            chain.jobs.clear
            chain.running = false
          end
          @chains.clear
          ns_broadcast if ns_terminated?
          [jobs, @owns_executor]
        else
          [nil, nil]
        end
      end
      if dropped
        dropped.each { |job| job.result.fail RejectedExecutionError.new('executor was killed') }
        executor.kill if owned
      end
      true
    end

    # @!macro executor_service_method_wait_for_termination
    def wait_for_termination(timeout = nil)
      terminated = synchronize { ns_wait_until(timeout) { ns_terminated? } }
      terminated = executor.wait_for_termination(timeout) if terminated && owns_executor?
      !!terminated
    end

    # @!macro executor_service_method_running_question
    def running?
      synchronize { @running }
    end

    # @!macro executor_service_method_shuttingdown_question
    def shuttingdown?
      synchronize { !@running && !ns_terminated? }
    end

    # @!macro executor_service_method_shutdown_question
    def shutdown?
      synchronize { ns_terminated? }
    end

    private

    Job = Struct.new(:args, :task, :result)

    # @!visibility private
    class Chain
      attr_accessor :running
      attr_reader :jobs

      def initialize
        @jobs    = []
        @running = false
      end
    end

    def ns_terminated?
      !@running && @active_jobs.zero?
    end

    def schedule(key, job)
      accepted = begin
        executor.post { run_job key, job }
      rescue RejectedExecutionError => ex
        reject_job key, job, ex
        return
      end
      reject_job key, job, RejectedExecutionError.new('executor is not running') unless accepted
    end

    def reject_job(key, job, error)
      job.result.fail error
      advance key
    end

    def run_job(key, job)
      begin
        value = job.task.call(*job.args)
      rescue Exception => ex
        error = ex
      end
      advance key
      error ? job.result.fail(error) : job.result.set(value)
    end

    # Hands the next queued job of the key to the underlying executor, or
    # drops the key's bookkeeping once its queue has drained.
    def advance(key)
      next_job = synchronize do
        @active_jobs -= 1
        chain = @chains[key]
        if chain
          shifted = chain.jobs.shift
          if shifted
            shifted
          else
            chain.running = false
            @chains.delete key
            ns_broadcast if ns_terminated?
            nil
          end
        else
          ns_broadcast if ns_terminated?
          nil
        end
      end
      schedule key, next_job if next_job
    end
  end
end
