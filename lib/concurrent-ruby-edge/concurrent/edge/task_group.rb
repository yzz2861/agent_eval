require 'concurrent/errors'
require 'concurrent/options'
require 'concurrent/synchronization/lockable_object'
require 'concurrent/edge/cancellation'

module Concurrent
  module Edge
    # Waits for a collection of concurrently running tasks to finish before
    # leaving the group's scope.
    #
    # Tasks are submitted with {#submit}, which immediately returns a
    # {Concurrent::Promises::Future}. The group does not stop running tasks
    # when one fails. Instead it resolves its cooperative {#cancellation}
    # and waits for every task it has already accepted. Tasks which have not
    # started when cancellation is resolved are rejected without invoking
    # their block; tasks which have started must inspect the cancellation
    # themselves. Ruby threads are never killed.
    #
    # @example
    #   Concurrent::TaskGroup.start do |group, cancellation|
    #     group.submit do |task_group, task_cancellation|
    #       task_cancellation.check!
    #       :done
    #     end
    #   end
    #
    # @!macro warn.edge
    class TaskGroup < Synchronization::LockableObject
      safe_initialization!

      THREAD_LOCAL_STACK = :concurrent_edge_task_groups

      # Runs a block inside a new task group and waits for all accepted tasks
      # before returning.
      #
      # @param [Executor, :io, :fast, :immediate] executor used for submitted tasks.
      # @yieldparam [Cancellation] cancellation when the block accepts one argument.
      # @yieldparam [TaskGroup] group when the block accepts two arguments.
      # @return [Object] the value returned by the block.
      # @raise [Exception] the original failure when only one task fails, or a
      #   {MultipleErrors} containing every failure when more than one fails.
      def self.start(executor = :io)
        group = new(executor)
        result = nil

        begin
          result = yield(group, group.cancellation)
        rescue Exception => error
          group.fail(error)
        ensure
          group.close
        end

        result
      end

      class << self
        alias_method :open, :start
      end

      # @param [Executor, :io, :fast, :immediate] executor used for submitted tasks.
      def initialize(executor = :io)
        super()
        @Executor           = Concurrent::Options.executor(executor)
        @CancellationOrigin = Promises.resolvable_event_on(@Executor)
        @Cancellation       = Cancellation.new(@CancellationOrigin)
        @Pending            = 0
        @Errors             = []
        @State              = :running
      end

      # @return [Cancellation] resolved after the first accepted task fails.
      def cancellation
        @Cancellation
      end

      # @return [Symbol] one of `:running`, `:closing`, `:cancelling`,
      #   `:closed`, or `:failed`.
      def state
        synchronize { @State }
      end

      # Submits a task to the group.
      #
      # Submission and close are serialized. A task whose submission is
      # accepted is always waited for; a task submitted after closing or
      # cancellation has started is returned as an already rejected future.
      #
      # A block without arguments receives none. A block with one argument
      # receives {#cancellation}; a block with two or more arguments receives
      # the group and its cancellation.
      # @return [Promises::Future] represents the submitted or rejected task.
      def submit(&task)
        raise ArgumentError, 'no block given' unless task

        future = synchronize do
          if accepting?
            future = Promises.resolvable_future_on(@Executor)
            future.on_resolution! { |fulfilled, _value, reason| task_resolved(fulfilled, reason) }
            @Pending += 1
            next future
          else
            next Promises.rejected_future(rejection_reason, @Executor)
          end
        end

        schedule(future, task)
        future
      end

      alias_method :future, :submit
      alias_method :post, :submit

      # Marks the group as closed and waits for all accepted tasks. New tasks
      # submitted by callers outside an accepted task are rejected once this
      # method has won the submission/close race. Nested tasks submitted by an
      # already running accepted task are still accepted while the group is
      # closing normally.
      #
      # @return [self]
      # @raise [Exception] all failures observed while waiting.
      def close
        synchronize do
          @State = :closed if @State == :running && @Pending.zero?
          @State = :closing if @State == :running
          ns_wait_until { @State == :closed || @State == :failed }
        end

        raise aggregate_error if @Errors.any?
        self
      end

      # Reports an external failure and cancels remaining accepted tasks.
      #
      # @param [Exception] error the failure to report.
      # @return [self]
      def fail(error)
        should_cancel = false

        synchronize do
          add_error(error)
          should_cancel = begin_cancellation
          @State = :failed if @Pending.zero?
          ns_broadcast
        end

        @CancellationOrigin.resolve if should_cancel
        self
      end

      private

      def accepting?
        (@State == :running ||
          (@State == :closing && task_thread?)) &&
          @State != :cancelling
      end

      def task_thread?
        stack = Thread.current[THREAD_LOCAL_STACK]
        stack && stack.include?(object_id)
      end

      def rejection_reason
        @CancellationOrigin.resolved? ? CancelledOperationError.new : RejectedExecutionError.new
      end

      def schedule(future, task)
        executed = @Executor.post do
          execute_task(future, task)
        end

        unless executed
          future.reject(RejectedExecutionError.new, false)
        end
      rescue StandardError => error
        future.reject(error, false)
      end

      def execute_task(future, task)
        stack = Thread.current[THREAD_LOCAL_STACK] ||= []
        stack.push(object_id)

        begin
          if @Cancellation.canceled?
            future.reject(CancelledOperationError.new, false)
          else
            case task_arity(task)
            when :none
              future.evaluate_to(&task)
            when :cancellation
              future.evaluate_to(@Cancellation, &task)
            else
              future.evaluate_to(self, @Cancellation, &task)
            end
          end
        ensure
          stack.pop
        end
      end

      def task_arity(task)
        case task.arity
        when 0
          :none
        when 1
          :cancellation
        else
          :group_and_cancellation
        end
      end

      def task_resolved(fulfilled, reason)
        should_cancel = false

        synchronize do
          @Pending -= 1

          unless fulfilled || cooperative_cancellation?(reason)
            add_error(reason)
            should_cancel = begin_cancellation
          end

          finish_if_done
          ns_broadcast
        end

        @CancellationOrigin.resolve if should_cancel
      end

      def cooperative_cancellation?(reason)
        @CancellationOrigin.resolved? && reason.is_a?(CancelledOperationError)
      end

      def add_error(error)
        @Errors << error
      end

      def begin_cancellation
        return false if @CancellationOrigin.resolved?

        @State = :cancelling if @State == :running || @State == :closing
        true
      end

      def finish_if_done
        return unless @Pending.zero?

        @State = @Errors.any? ? :failed : :closed
      end

      def aggregate_error
        errors = synchronize { @Errors.dup }
        return nil if errors.empty?
        return errors.first if errors.size == 1

        MultipleErrors.new(errors)
      end
    end
  end

  TaskGroup = Edge::TaskGroup
end
