require 'thread'
require 'concurrent/atomic/event'
require 'concurrent/concern/logging'
require 'concurrent/executor/ruby_executor_service'
require 'concurrent/utility/monotonic_time'
require 'concurrent/collection/timeout_queue'

module Concurrent

  # @!macro thread_pool_executor
  # @!macro thread_pool_options
  # @!visibility private
  class RubyThreadPoolExecutor < RubyExecutorService
    include Concern::Deprecation

    MANAGED_BLOCK_WORKER = :concurrent_managed_block_worker
    private_constant :MANAGED_BLOCK_WORKER

    # @!macro thread_pool_executor_constant_default_max_pool_size
    DEFAULT_MAX_POOL_SIZE      = 2_147_483_647 # java.lang.Integer::MAX_VALUE

    # @!macro thread_pool_executor_constant_default_min_pool_size
    DEFAULT_MIN_POOL_SIZE      = 0

    # @!macro thread_pool_executor_constant_default_max_queue_size
    DEFAULT_MAX_QUEUE_SIZE     = 0

    # @!macro thread_pool_executor_constant_default_thread_timeout
    DEFAULT_THREAD_IDLETIMEOUT = 60

    # @!macro thread_pool_executor_constant_default_synchronous
    DEFAULT_SYNCHRONOUS = false

    # @!macro thread_pool_executor_attr_reader_max_length
    attr_reader :max_length

    # @!macro thread_pool_executor_attr_reader_min_length
    attr_reader :min_length

    # @!macro thread_pool_executor_attr_reader_idletime
    attr_reader :idletime

    # @!macro thread_pool_executor_attr_reader_max_queue
    attr_reader :max_queue

    # @!macro thread_pool_executor_attr_reader_synchronous
    attr_reader :synchronous

    # @!macro thread_pool_executor_method_initialize
    def initialize(opts = {})
      super(opts)
    end

    # @!macro thread_pool_executor_attr_reader_largest_length
    def largest_length
      synchronize { @largest_length }
    end

    # @!macro thread_pool_executor_attr_reader_scheduled_task_count
    def scheduled_task_count
      synchronize { @scheduled_task_count }
    end

    # @!macro thread_pool_executor_attr_reader_completed_task_count
    def completed_task_count
      synchronize { @completed_task_count }
    end

    # @!macro thread_pool_executor_method_active_count
    def active_count
      synchronize do
        @pool.length - @ready.length - @blocked_workers.size
      end
    end

    # Marks the current worker as blocked while the block runs. The pool may
    # start one temporary worker per blocked worker so queued tasks continue.
    def managed_block
      raise ArgumentError.new('no block given') unless block_given?

      worker = Thread.current.thread_variable_get(MANAGED_BLOCK_WORKER)
      unless worker.is_a?(Worker) && worker.pool.equal?(self)
        raise IllegalOperationError.new('managed_block can only be called by a worker of this pool')
      end

      synchronize do
        if worker.managed_block_depth.zero?
          unless running?
            raise IllegalOperationError.new('cannot enter managed_block after shutdown')
          end

          @blocked_workers[worker] = true
          ns_assign_queued_to_compensation_worker(worker)
        end

        worker.managed_block_depth += 1
      end

      yield
    ensure
      if worker
        synchronize do
          worker.managed_block_depth -= 1
          ns_end_managed_block(worker) if worker.managed_block_depth.zero?
        end
      end
    end

    # @!macro executor_service_method_can_overflow_question
    def can_overflow?
      synchronize { ns_limited_queue? }
    end

    # @!macro thread_pool_executor_attr_reader_length
    def length
      synchronize { @pool.length }
    end

    # @!macro thread_pool_executor_attr_reader_queue_length
    def queue_length
      synchronize { @queue.length }
    end

    # @!macro thread_pool_executor_attr_reader_remaining_capacity
    def remaining_capacity
      synchronize do
        if ns_limited_queue?
          @max_queue - @queue.length
        else
          -1
        end
      end
    end

    # removes the worker if it can be pruned
    #
    # @return [true, false] if the worker was pruned
    #
    # @!visibility private
    def prune_worker(worker)
      synchronize do
        if ns_prunable_capacity > 0
          remove_worker worker
          true
        else
          false
        end
      end
    end

    # @!visibility private
    def remove_worker(worker)
      synchronize do
        if @retiring_workers.delete(worker)
          owner = @compensation_workers.key(worker)
          @compensation_workers.delete(owner) if owner
        end
        ns_remove_ready_worker worker
        ns_remove_busy_worker worker
      end
    end

    # @!visibility private
    def ready_worker(worker, last_message)
      synchronize { ns_ready_worker worker, last_message }
    end

    # @!visibility private
    def worker_died(worker)
      synchronize { ns_worker_died worker }
    end

    # @!visibility private
    def worker_task_completed
      synchronize { @completed_task_count += 1 }
    end

    # @!macro thread_pool_executor_method_prune_pool
    def prune_pool
      deprecated "#prune_pool has no effect and will be removed in next the release, see https://github.com/ruby-concurrency/concurrent-ruby/pull/1082."
    end

    private

    # @!visibility private
    def ns_initialize(opts)
      @min_length      = opts.fetch(:min_threads, DEFAULT_MIN_POOL_SIZE).to_i
      @max_length      = opts.fetch(:max_threads, DEFAULT_MAX_POOL_SIZE).to_i
      @idletime        = opts.fetch(:idletime, DEFAULT_THREAD_IDLETIMEOUT).to_i
      @max_queue       = opts.fetch(:max_queue, DEFAULT_MAX_QUEUE_SIZE).to_i
      @synchronous     = opts.fetch(:synchronous, DEFAULT_SYNCHRONOUS)
      @fallback_policy = opts.fetch(:fallback_policy, :abort)

      raise ArgumentError.new("`synchronous` cannot be set unless `max_queue` is 0") if @synchronous && @max_queue > 0
      raise ArgumentError.new("#{@fallback_policy} is not a valid fallback policy") unless FALLBACK_POLICIES.include?(@fallback_policy)
      raise ArgumentError.new("`max_threads` cannot be less than #{DEFAULT_MIN_POOL_SIZE}") if @max_length < DEFAULT_MIN_POOL_SIZE
      raise ArgumentError.new("`max_threads` cannot be greater than #{DEFAULT_MAX_POOL_SIZE}") if @max_length > DEFAULT_MAX_POOL_SIZE
      raise ArgumentError.new("`min_threads` cannot be less than #{DEFAULT_MIN_POOL_SIZE}") if @min_length < DEFAULT_MIN_POOL_SIZE
      raise ArgumentError.new("`min_threads` cannot be more than `max_threads`") if min_length > max_length

      @pool                 = [] # all workers
      @ready                = [] # used as a stash (most idle worker is at the start)
      @queue                = [] # used as queue
      # @ready or @queue is empty at all times
      @scheduled_task_count = 0
      @completed_task_count = 0
      @largest_length       = 0
      @workers_counter      = 0
      @ruby_pid             = $$ # detects if Ruby has forked
      @blocked_workers      = {}
      @compensation_workers = {}
      @retiring_workers     = {}
    end

    # @!visibility private
    def ns_limited_queue?
      @max_queue != 0
    end

    # @!visibility private
    def ns_execute(*args, &task)
      ns_reset_if_forked

      assigned = ns_assign_worker(*args, &task)
      enqueued = !assigned && ns_enqueue_with_compensation(*args, &task)
      if assigned || enqueued
        @scheduled_task_count += 1
        nil
      elsif @blocked_workers.any?
        lambda { raise RejectedExecutionError }
      else
        fallback_action(*args, &task)
      end
    end

    # @!visibility private
    def ns_shutdown_execution
      ns_reset_if_forked

      if @pool.empty?
        # nothing to do
        stopped_event.set
      end

      if @queue.empty?
        # no more tasks will be accepted, just stop all workers
        @pool.each(&:stop)
      end
    end

    # @!visibility private
    def ns_kill_execution
      # TODO log out unprocessed tasks in queue
      # TODO try to shutdown first?
      @pool.each(&:kill)
      @pool.clear
      @ready.clear
      @blocked_workers.clear
      @compensation_workers.clear
      @retiring_workers.clear
    end

    # tries to assign task to a worker, tries to get one from @ready or to create new one
    # @return [true, false] if task is assigned to a worker
    #
    # @!visibility private
    def ns_assign_worker(*args, &task)
      # keep growing if the pool is not at the minimum yet
      if @pool.size >= @min_length
        ready_index = @ready.index { |candidate, _| !@retiring_workers[candidate] }
        worker, _ = ready_index && @ready.delete_at(ready_index)
        unless worker
          owner = ns_unassigned_blocked_worker
          worker = ns_add_busy_worker
          @compensation_workers[owner] = worker if owner && worker
        end
      else
        worker = ns_add_busy_worker
      end

      if worker
        worker << [task, args]
        true
      else
        false
      end
    rescue ThreadError
      # Raised when the operating system refuses to create the new thread
      return false
    end

    # tries to enqueue task
    # @return [true, false] if enqueued
    #
    # @!visibility private
    def ns_enqueue(*args, &task)
      return false if @synchronous

      if !ns_limited_queue? || @queue.size < @max_queue
        @queue << [task, args]
        true
      else
        false
      end
    end

    def ns_enqueue_with_compensation(*args, &task)
      return false if @synchronous
      return false if ns_limited_queue? && @queue.size >= @max_queue

      owner = ns_unassigned_blocked_worker
      ready_index = owner && @ready.index { |candidate, _| !@retiring_workers[candidate] }
      worker, _ = ready_index && @ready.delete_at(ready_index)
      unless worker
        worker = owner ? ns_add_busy_worker : nil
        @compensation_workers[owner] = worker if owner && worker
      end

      @queue << [task, args]
      worker << @queue.shift if worker
      true
    end

    # @!visibility private
    def ns_worker_died(worker)
      owner = @compensation_workers.key(worker)
      blocked = @blocked_workers.delete(worker)
      dependent_worker = owner ? @compensation_workers.delete(owner) : nil
      @compensation_workers.delete(worker)
      ns_remove_busy_worker(worker, clear_mappings: false)

      if owner && !blocked
        replacement_worker = ns_add_busy_worker
        if replacement_worker
          @compensation_workers[owner] = replacement_worker
          ns_ready_worker(replacement_worker, Concurrent.monotonic_time, false)
        end
      end

      if dependent_worker
        ns_retire_compensation_worker(dependent_worker)
      elsif owner.nil? && !blocked
        replacement_worker = ns_add_busy_worker
        ns_ready_worker(replacement_worker, Concurrent.monotonic_time, false) if replacement_worker
      end
    end

    # creates new worker which has to receive work to do after it's added
    # @return [nil, Worker] nil of max capacity is reached
    #
    # @!visibility private
    def ns_add_busy_worker
      return if @pool.size - @blocked_workers.size >= @max_length

      @workers_counter += 1
      @pool << (worker = Worker.new(self, @workers_counter))
      @largest_length = @pool.length if @pool.length > @largest_length
      worker
    end

    def ns_assign_queued_to_compensation_worker(owner = nil)
      return if @queue.empty?

      owner ||= ns_unassigned_blocked_worker
      return unless owner

      worker = ns_add_busy_worker
      return unless worker

      @compensation_workers[owner] = worker
      worker << @queue.shift
    end

    def ns_unassigned_blocked_worker
      @blocked_workers.keys.find do |blocked_worker|
        !@compensation_workers.key?(blocked_worker)
      end
    end

    # handle ready worker, giving it new job or assigning back to @ready
    #
    # @!visibility private
    def ns_ready_worker(worker, last_message, success = true)
      if @retiring_workers.delete(worker)
        owner = @compensation_workers.key(worker)
        @compensation_workers.delete(owner) if owner
        ns_remove_busy_worker(worker, clear_mappings: false)
        worker.stop
        return
      end

      task_and_args = @queue.shift
      if task_and_args
        worker << task_and_args
      else
        # stop workers when !running?, do not return them to @ready
        if running?
          raise unless last_message
          @ready.push([worker, last_message])
        else
          worker.stop
        end
      end
    end

    # removes a worker which is not tracked in @ready
    #
    # @!visibility private
    def ns_remove_busy_worker(worker, clear_mappings: true)
      @pool.delete(worker)
      if clear_mappings
        @blocked_workers.delete(worker)
        owner = @compensation_workers.key(worker)
        @compensation_workers.delete(owner) if owner
      end
      @retiring_workers.delete(worker)
      stopped_event.set if @pool.empty? && !running?
      true
    end

    # @!visibility private
    def ns_remove_ready_worker(worker)
      if index = @ready.index { |rw, _| rw == worker }
        @ready.delete_at(index)
      end
      true
    end

    # @return [Integer] number of excess idle workers which can be removed without
    #                   going below min_length, or all workers if not running
    #
    # @!visibility private
    def ns_prunable_capacity
      if running?
        normal_ready_workers = @ready.count do |worker, _|
          !@compensation_workers.value?(worker) && !@retiring_workers[worker]
        end
        [[@pool.size - @min_length, normal_ready_workers].min, 0].max
      else
        @pool.size
      end
    end

    # @!visibility private
    def ns_reset_if_forked
      if $$ != @ruby_pid
        @queue.clear
        @ready.clear
        @pool.clear
        @scheduled_task_count = 0
        @completed_task_count = 0
        @largest_length       = 0
        @workers_counter      = 0
        @ruby_pid             = $$
        @blocked_workers      = {}
        @compensation_workers = {}
        @retiring_workers     = {}
      end
    end

    def ns_end_managed_block(worker)
      @blocked_workers.delete(worker)
      compensation_worker = @compensation_workers.delete(worker)
      ns_retire_compensation_worker(compensation_worker) if compensation_worker
    end

    def ns_retire_compensation_worker(worker)
      return unless worker

      if index = @ready.index { |candidate, _| candidate == worker }
        @ready.delete_at(index)
        @pool.delete(worker)
        @retiring_workers.delete(worker)
        stopped_event.set if @pool.empty? && !running?
        worker.stop
      elsif @pool.include?(worker)
        @retiring_workers[worker] = true
      end
    end

    # @!visibility private
    class Worker
      include Concern::Logging

      attr_reader :pool

      attr_accessor :managed_block_depth

      def initialize(pool, id)
        # instance variables accessed only under pool's lock so no need to sync here again
        @queue  = Collection::TimeoutQueue.new
        @pool   = pool
        @managed_block_depth = 0
        @thread = create_worker @queue, pool, pool.idletime

        if @thread.respond_to?(:name=)
          @thread.name = [pool.name, 'worker', id].compact.join('-')
        end
      end

      def <<(message)
        @queue << message
      end

      def stop
        @queue << :stop
      end

      def kill
        @thread.kill
      end

      private

      def create_worker(queue, pool, idletime)
        Thread.new(queue, pool, idletime) do |my_queue, my_pool, my_idletime|
          Thread.current.thread_variable_set(:concurrent_managed_block_worker, self)
          catch(:stop) do
            prunable = true

            loop do
              timeout = prunable && my_pool.running? ? my_idletime : nil
              case message = my_queue.pop(timeout: timeout)
              when nil
                throw :stop if my_pool.prune_worker(self)
                prunable = false
              when :stop
                my_pool.remove_worker(self)
                throw :stop
              else
                task, args = message
                run_task my_pool, task, args
                my_pool.ready_worker(self, Concurrent.monotonic_time)
                prunable = true
              end
            end
          end
        end
      end

      def run_task(pool, task, args)
        previous_worker = Thread.current.thread_variable_get(:concurrent_managed_block_worker)
        Thread.current.thread_variable_set(:concurrent_managed_block_worker, self)
        begin
          task.call(*args)
          pool.worker_task_completed
        ensure
          Thread.current.thread_variable_set(:concurrent_managed_block_worker, previous_worker)
        end
      rescue => ex
        # let it fail
        log DEBUG, ex
      rescue Exception => ex
        log ERROR, ex
        pool.worker_died(self)
        throw :stop
      end
    end

    private_constant :Worker
  end
end
