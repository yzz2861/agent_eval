require 'concurrent/errors'
require 'concurrent/edge/cancellation'
require 'concurrent/options'
require 'concurrent/promises'

module Concurrent
  # Runs concurrently submitted tasks as one bounded collection. New tasks stop
  # being accepted after the first task failure or when the group is closed,
  # and {.wait} blocks until every accepted task has resolved. Tasks receive
  # the group and can cooperatively observe the shared cancellation origin.
  class TaskGroup
    CURRENT_KEY = :concurrent_task_group
    private_constant :CURRENT_KEY

    # Creates a group, evaluates the block, and waits for every accepted task.
    # @return [Array] values of all accepted futures in submission order
    # @raise [Exception] the sole failure, or {MultipleErrors} for more than one
    def self.wait(executor: :io, &block)
      new(executor: executor).wait(&block)
    end

    def initialize(executor: :io)
      @Executor = executor.is_a?(Symbol) ? Options.executor(executor) : executor
      @Mutex = Mutex.new
      @Condition = ConditionVariable.new
      @Futures = []
      @Pending = 0
      @Closing = false
      @Failed = false
      @ErrorCount = 0
      @Errors = []
      @Cancellation = Promises.resolvable_event
      @ExternalCancellation = false
      @ParentGroup = nil
      observe_parent_cancellation
    end

    # Submits a task to the group. After closing, returns a rejected future
    # instead of accepting another task.
    # @return [Promises::Future]
    def future(*args, &task)
      raise ArgumentError, 'no block given' unless block_given?

      result = @Mutex.synchronize do
        if @Closing
          Promises.rejected_future(CancelledOperationError.new)
        else
          future = Promises.resolvable_future
          @Futures << future
          @Pending += 1
          future
        end
      end

      result.on_resolution!(&method(:resolve_task)) unless result.resolved?
      submit(result, args, task) unless result.resolved?
      result
    end

    alias_method :submit, :future
    alias_method :post, :future
    alias_method :spawn, :future

    # @return [Cancellation] cooperative cancellation shared by all tasks
    def cancellation
      Cancellation.new(@Cancellation)
    end

    # @return [Promises::Event] resolved when accepted tasks should stop
    def origin
      @Cancellation
    end

    # @return [Boolean]
    def canceled?
      @Cancellation.resolved?
    end

    # Raises when the group has issued its cooperative stop signal.
    # @return [self]
    def check!(error = CancelledOperationError)
      raise error if canceled?
      self
    end

    # Stops accepting new tasks without cancelling already accepted tasks.
    # @return [self]
    def close
      @Mutex.synchronize do
        @Closing = true
        @Condition.broadcast
      end
      self
    end

    # Optionally evaluates the block as the group scope, then waits for every
    # accepted task. Running tasks are never interrupted or marked cancelled.
    # @return [Array] values of all accepted futures in submission order
    # @raise [Exception] the sole failure, or {MultipleErrors} for more than one
    def wait(&block)
      previous_group = Thread.current[CURRENT_KEY]
      Thread.current[CURRENT_KEY] = self
      scope_error = begin
        block.call(self) if block
        nil
      rescue Exception => error
        error
      end

      close
      fail(scope_error) if scope_error

      @Mutex.synchronize do
        raise IllegalOperationError, 'cannot wait for a task group from one of its own tasks' if nested_wait?

        @Condition.wait(@Mutex) until @Pending.zero?
      end

      begin
        raise aggregate_error if aggregate_error
        @Futures.map(&:value)
      ensure
        Thread.current[CURRENT_KEY] = previous_group
      end
    end

    alias_method :join, :wait

    # @return [Array<Promises::Future>] all futures accepted by the group
    def futures
      @Mutex.synchronize { @Futures.dup }
    end

    private

    def observe_parent_cancellation
      @ParentGroup = Thread.current[CURRENT_KEY]
      return unless @ParentGroup

      @ParentGroup.origin.on_resolution! do
        @Mutex.synchronize do
          next if @Closing
          @Closing = true
          @ExternalCancellation = true
          @Condition.broadcast
        end
        @Cancellation.resolve(false)
      end
    end

    def nested_wait?
      group = @ParentGroup
      while group
        return true if group.equal?(self)
        group = group.instance_variable_get(:@ParentGroup)
      end
      false
    end

    def submit(result, args, task)
      posted = @Executor.post(result, self, args, task) do |future, group, task_args, block|
        Thread.current[CURRENT_KEY] = group
        value = call_task(block, group, task_args)
        future.fulfill(value, false)
        Thread.current[CURRENT_KEY] = group.instance_variable_get(:@ParentGroup)
      rescue Exception => error
        future.reject(error, false)
        Thread.current[CURRENT_KEY] = group.instance_variable_get(:@ParentGroup)
        raise error unless error.is_a?(StandardError)
      end

      result.reject(RejectedExecutionError.new('executor rejected task'), false) unless posted
    rescue Exception => error
      result.reject(error, false)
    end

    def resolve_task(fulfilled, _value, reason)
      @Mutex.synchronize do
        @Pending -= 1
        unless fulfilled
          existing_failures = @ErrorCount.positive?
          cooperative = reason.is_a?(CancelledOperationError) &&
            (@ExternalCancellation || existing_failures || @Cancellation.resolved?)
          add_error(reason) unless cooperative
          @Closing = true unless existing_failures
          @Failed = true
        end
        @Condition.broadcast if @Pending.zero?
      end
      @Cancellation.resolve(false) unless fulfilled
    end

    def call_task(task, group, args)
      if task.arity.zero?
        task.call
      else
        task.call(group, *args)
      end
    end

    def fail(error, signal: true)
      @Mutex.synchronize do
        @Closing = true
        add_error(error)
        @Failed = true
        @Condition.broadcast
      end
      @Cancellation.resolve(false) if signal
      self
    end

    def add_error(error)
      errors = error.is_a?(MultipleErrors) ? error.errors.dup : Array(error)
      @Errors.concat(errors.map do |candidate|
        Exception === candidate ? candidate : RuntimeError.new(candidate.inspect)
      end)
      @ErrorCount = @Errors.size
    end

    def aggregate_error
      @Mutex.synchronize do
        errors = @ExternalCancellation ? @Errors.reject { |error| error.is_a?(CancelledOperationError) } : @Errors
        errors = errors.reject do |error|
          error.is_a?(RejectedExecutionError) && @ErrorCount > 1
        end
        errors = [CancelledOperationError.new] if errors.empty? && @ExternalCancellation

        if errors.empty?
          nil
        elsif errors.size == 1
          errors.first
        else
          MultipleErrors.new(errors.uniq)
        end
      end
    end
  end
end
