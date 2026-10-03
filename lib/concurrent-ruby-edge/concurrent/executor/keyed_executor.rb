require 'monitor'

require 'concurrent/errors'
require 'concurrent/executor/executor_service'
require 'concurrent/promises'
require 'concurrent/synchronization/object'
require 'concurrent/utility/monotonic_time'

module Concurrent
  # Executes tasks submitted for the same key in submission order while allowing
  # tasks submitted for different keys to run concurrently on the wrapped executor.
  #
  # Each submission returns a {Promises::Future}. An exception raised by one task
  # rejects its own future, but does not prevent later tasks with the same key from
  # running.
  #
  # @!macro warn.edge
  class KeyedExecutor < Synchronization::Object
    safe_initialization!
    include ExecutorService

    Entry = Struct.new(:chain, :future, :args, :task, :executing)

    class Chain < Monitor
      attr_reader :key, :queue
      attr_accessor :active
      attr_writer :closed

      def initialize(key)
        super()
        @key = key
        @queue = []
        @active = nil
        @closed = false
      end

      def closed?
        @closed
      end
    end

    # @param [ExecutorService] executor the pool used to run submitted tasks
    # @param [Boolean] owns_executor when true, shutting down or killing the
    #   wrapper also shuts down or kills the wrapped executor
    def initialize(executor = Concurrent.global_io_executor, options = {})
      super()
      @Executor = executor
      @OwnsExecutor = options.fetch(:owns_executor, false)
      @Mutex = Monitor.new
      @Condition = @Mutex.new_cond
      @Chains = {}
      @State = :running
    end

    # Submit a task associated with a key.
    #
    # @param [Object] key the key used to serialize execution
    # @param [Array<Object>] args arguments passed to the task
    # @yield [*Array<Object>] the task to execute
    # @return [Promises::Future] the result of this individual submission
    def submit(key, *args, &task)
      raise ArgumentError, 'no block given' unless block_given?

      future = Concurrent::Promises.resolvable_future
      chain = loop do
        candidate = @Mutex.synchronize do
          unless @State == :running
            future.reject(RejectedExecutionError.new('executor is shut down'))
            return future
          end

          existing_chain = @Chains[key]
          if existing_chain.nil? || existing_chain.closed?
            new_chain = Chain.new(key)
            @Chains[key] = new_chain
          else
            existing_chain
          end
        end

        appended = candidate.synchronize do
          unless candidate.closed?
            candidate.queue << Entry.new(candidate, future, args, task, false)
            true
          end
        end

        break candidate if appended
      end

      schedule_head(chain)
      future
    end
    alias_method :post, :submit

    # Keyed tasks must be submitted with {#submit} so the ordering key is explicit.
    #
    # @raise [ArgumentError] always
    def <<(_task)
      raise ArgumentError, 'use submit(key, *args) to submit a keyed task'
    end

    # @return [Boolean] whether the wrapped executor has a bounded task queue
    def can_overflow?
      @Executor.can_overflow?
    end

    # @return [Boolean] always false; only tasks with the same key are serialized
    def serialized?
      false
    end

    # Begin an orderly shutdown. Already accepted tasks are allowed to complete.
    #
    # @return [Boolean] true when shutdown starts or has already been requested
    def shutdown
      @Mutex.synchronize do
        return true unless @State == :running
        @State = :shutting_down
        @Executor.shutdown if @OwnsExecutor
        @Condition.broadcast if @Chains.empty?
      end
      true
    end

    # Reject queued tasks and prevent new submissions. When the wrapper owns the
    # wrapped executor, the wrapped executor is also killed.
    #
    # @return [Boolean] true when termination starts or has already occurred
    def kill
      @Mutex.synchronize do
        return true if shutdown?
        @State = :shutdown
        @Executor.kill if @OwnsExecutor
        @Condition.broadcast
      end
      reject_queued_tasks
      true
    end

    # Wait until all accepted tasks have completed after {#shutdown}, or until the
    # wrapper has been killed.
    #
    # @param [Numeric, nil] timeout maximum time to wait
    # @return [Boolean] true when stopped, false on timeout
    def wait_for_termination(timeout = nil)
      deadline = timeout ? Concurrent.monotonic_time + timeout : nil

      if @OwnsExecutor
        remaining = deadline ? deadline - Concurrent.monotonic_time : nil
        return false if remaining && remaining <= 0
        return false unless @Executor.wait_for_termination(remaining)
      end

      wait_until_stopped(deadline ? deadline - Concurrent.monotonic_time : nil)
    end

    # @return [Boolean] whether new tasks are accepted
    def running?
      @Mutex.synchronize { @State == :running }
    end

    # @return [Boolean] whether orderly shutdown is draining accepted tasks
    def shuttingdown?
      @Mutex.synchronize { @State == :shutting_down }
    end

    # @return [Boolean] whether the wrapper has been killed
    def shutdown?
      @Mutex.synchronize { @State == :shutdown }
    end

    private

    def wait_until_stopped(remaining)
      @Mutex.synchronize do
        until @State == :shutdown || (@State == :shutting_down && @Chains.empty?)
          return false if remaining && remaining <= 0

          start_wait = Concurrent.monotonic_time
          @Condition.wait(remaining)
          break if remaining.nil?

          remaining -= Concurrent.monotonic_time - start_wait
        end
      end
      true
    end

    def schedule_head(chain)
      loop do
        entry = chain.synchronize do
          next nil if chain.closed? || chain.active
          entry = chain.queue.shift
          chain.active = entry
          entry
        end

        unless entry
          chain.synchronize { chain.closed = true if chain.active.nil? && chain.queue.empty? }
          cleanup_chain(chain)
          return
        end

        if dispatch(entry) != :rejected
          return
        end

        chain.synchronize do
          if chain.active.equal?(entry)
            chain.active = nil
            entry.executing = true
            entry.future.reject(RejectedExecutionError.new('executor is shut down'))
          end
        end
      end
    end

    def dispatch(entry)
      posted = @Executor.post { run_entry(entry) }
      return :posted if posted
      dispatch_rejected(entry)
    rescue RejectedExecutionError
      dispatch_rejected(entry)
    end

    def dispatch_rejected(entry)
      if running? || shuttingdown?
        run_entry(entry)
        :inline
      else
        :rejected
      end
    end

    def run_entry(entry)
      chain = entry.chain
      chain.synchronize do
        return unless chain.active.equal?(entry) && !entry.executing

        entry.executing = true
        if @State == :shutdown
          chain.active = nil
          entry.future.reject(RejectedExecutionError.new('executor is shut down'))
          schedule_head(chain)
          return
        end
      end

      begin
        entry.future.fulfill(entry.task.call(*entry.args))
      rescue StandardError => error
        entry.future.reject(error)
      ensure
        chain.synchronize { chain.active = nil if chain.active.equal?(entry) }
        schedule_head(chain)
      end
    end

    def cleanup_chain(chain)
      removed = chain.synchronize do
        chain.closed? && chain.queue.empty? && @Chains[chain.key].equal?(chain)
      end
      return unless removed

      @Mutex.synchronize do
        if chain.closed? && chain.queue.empty? && @Chains[chain.key].equal?(chain)
          @Chains.delete(chain.key)
        end
        @Condition.broadcast if @State == :shutdown || (@State == :shutting_down && @Chains.empty?)
      end
    end

    def reject_queued_tasks
      chains = @Mutex.synchronize { @Chains.values.dup }
      chains.each do |chain|
        entries = chain.synchronize do
          entries = chain.queue.dup
          chain.queue.clear
          chain.closed = true

          if chain.active && !chain.active.executing
            active = chain.active
            chain.active = nil
            active.executing = true
            active.future.reject(RejectedExecutionError.new('executor is shut down'))
          end

          entries
        end

        entries.each do |entry|
          next if entry.executing

          entry.executing = true
          entry.future.reject(RejectedExecutionError.new('executor is shut down'))
        end

        if chain.closed? && chain.active.nil?
          @Mutex.synchronize { @Chains.delete(chain.key) }
        end
      end
    end
  end
end
