# frozen_string_literal: true

module StateMachines
  module AsyncMode
    # The outcome of an asynchronously executed transition.
    #
    # The completion result distinguishes between the four ways an async
    # transition can end:
    #
    # * +:success+ - The guard passed and the action (if any) succeeded
    # * +:guard_rejected+ - No transition matched; guards rejected the event
    # * +:action_failed+ - The guard passed but the action or a callback
    #   halted the transition
    # * +:cancelled+ - The caller cancelled the handle before the executor
    #   claimed it; no guard, action, or transition callback ran
    class TransitionResult
      # All possible outcomes of an async transition
      OUTCOMES = %i[success guard_rejected action_failed cancelled].freeze

      # The outcome of the transition (see OUTCOMES)
      attr_reader :outcome

      # The transition that was performed, if the guard accepted the event
      attr_reader :transition

      def initialize(outcome, transition: nil)
        raise ArgumentError, "Unknown outcome: #{outcome.inspect}" unless OUTCOMES.include?(outcome)

        @outcome = outcome
        @transition = transition
      end

      # Whether the transition completed successfully
      def success?
        @outcome == :success
      end

      # Whether the handle was cancelled before the transition started
      def cancelled?
        @outcome == :cancelled
      end

      # Whether the guard rejected the event (no matching transition)
      def guard_rejected?
        @outcome == :guard_rejected
      end

      # Whether the guard passed but the action or callbacks failed
      def action_failed?
        @outcome == :action_failed
      end

      # Allows comparing results with true/false for convenience:
      #   handle.wait == true  # => succeeded
      #   handle.wait == false # => did not succeed
      def ==(other)
        case other
        when true then success?
        when false, nil then !success?
        when TransitionResult then outcome == other.outcome
        else super
        end
      end

      def to_s
        outcome.to_s
      end

      def inspect
        "#<#{self.class.name} #{outcome}>"
      end
    end

    # A queryable, awaitable handle for an asynchronously fired event.
    #
    # The handle is returned by the async event interfaces (e.g.
    # +async_fire_event+ or the generated +<event>_async+ helpers) and
    # represents a transition that has been scheduled but may not have
    # started yet.
    #
    # == Cancellation
    #
    # Calling +cancel+ while the handle is still pending prevents the
    # transition from starting: its guard, action, and transition callbacks
    # will never run. Cancellation is a cooperative, pre-execution gate --
    # it never kills threads or Async tasks, and it never attempts to undo
    # side effects that already happened. Once the executor has claimed the
    # handle, +cancel+ returns false and the transition runs to completion.
    #
    # == Execution paths
    #
    # The transition is executed on an +Async+ child task when scheduled
    # inside an Async reactor, and on a plain +Thread+ otherwise. Both
    # paths share the same claim/cancel/complete protocol.
    #
    # == Example
    #
    #   handle = vehicle.ignite_async
    #   handle.cancelled?           # => false
    #   handle.cancel               # => true (only if not yet claimed)
    #   result = handle.wait        # => #<TransitionResult cancelled>
    #   result.outcome              # => :cancelled
    class TransitionHandle
      # Lifecycle states of the handle
      # * +:pending+ - scheduled, but the executor has not claimed it yet
      # * +:claimed+ - the executor started the transition; cancel will fail
      # * +:completed+ - the transition finished (any non-cancelled outcome)
      # * +:cancelled+ - cancelled before being claimed
      STATES = %i[pending claimed completed cancelled].freeze

      # The name of the event being fired
      attr_reader :event_name

      # The machine the event belongs to
      attr_reader :machine

      def initialize(object, machine, event_name, args = [], kwargs = {}, raise_on_failure: false)
        @object = object
        @machine = machine
        @event_name = event_name
        @args = args
        @kwargs = kwargs
        @raise_on_failure = raise_on_failure

        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @state = :pending
        @result = nil
        @error = nil
        @executor = nil
      end

      # Creates a handle and immediately schedules its execution.
      # Inside an Async reactor the transition runs on an Async child task,
      # otherwise it runs on a background thread.
      def self.schedule(object, machine, event_name, args = [], kwargs = {}, raise_on_failure: false)
        new(object, machine, event_name, args, kwargs, raise_on_failure: raise_on_failure).start
      end

      # Schedules the transition for execution. Called automatically by
      # +schedule+; handles built with +new+ can be started manually.
      def start
        @executor = if self.class.async_context?
                      Async do
                        # Yield before claiming so the caller gets a chance to
                        # cancel before the transition actually starts
                        ::Async::Task.current.yield
                        execute
                      end
                    else
                      Thread.new { execute }
                    end
        self
      end

      # Attempts to cancel the transition before it starts.
      #
      # Returns true if the handle was still pending and is now cancelled:
      # the guard, action, and transition callbacks will not run. Returns
      # false once the executor has claimed the handle (or it already
      # finished); in that case the transition completes normally.
      def cancel
        @mutex.synchronize do
          return false unless @state == :pending

          @state = :cancelled
          @result = TransitionResult.new(:cancelled)
          @condition.broadcast
          true
        end
      end

      # The current lifecycle state of the handle (see STATES)
      def status
        @mutex.synchronize { @state }
      end

      # Whether the transition has not been claimed by the executor yet
      def pending?
        status == :pending
      end

      # Whether the executor has started running the transition
      def claimed?
        status == :claimed
      end

      # Whether the handle was cancelled before the transition started
      def cancelled?
        status == :cancelled
      end

      # Whether the handle has settled (completed or cancelled)
      def completed?
        %i[completed cancelled].include?(status)
      end

      # Blocks until the handle settles and returns its TransitionResult.
      #
      # For handles created with +raise_on_failure+ (the bang variants),
      # waiting raises StateMachines::InvalidTransition when the guard
      # rejects the event or the action fails. Cancellation is not an
      # error: waiting on a cancelled handle returns the cancelled result.
      # Exceptions raised by the transition itself are re-raised here.
      def wait
        # When the executor is an Async task and we're inside its reactor,
        # wait on the task directly so we block the fiber instead of the
        # whole reactor thread (which would deadlock the executor)
        if @executor.is_a?(::Async::Task) && self.class.async_context?
          @executor.wait
          @mutex.synchronize do
            raise @error if @error

            return @result
          end
        end

        @mutex.synchronize do
          @condition.wait(@mutex) while @state == :pending || @state == :claimed
          raise @error if @error

          @result
        end
      end
      alias result wait

      # Whether the handle is being executed inside an Async reactor
      def self.async_context?
        defined?(::Async::Task) && ::Async::Task.current? ? true : false
      end

      private

      # Runs the transition if it hasn't been cancelled. This is the only
      # entry point used by both the Async and the thread executors.
      def execute
        return unless claim

        begin
          outcome, transition = perform_transition

          if @raise_on_failure && outcome != :success
            finish_with_error(StateMachines::InvalidTransition.new(@object, @machine, @event_name))
          else
            finish(TransitionResult.new(outcome, transition: transition))
          end
        rescue StandardError => e
          finish_with_error(e)
        end
      end

      # Atomically claims the handle for execution. Returns false if the
      # handle was cancelled first, in which case nothing runs.
      def claim
        @mutex.synchronize do
          next false if @state == :cancelled

          @state = :claimed
          true
        end
      end

      # Performs the actual transition, mirroring Event#fire semantics, and
      # returns the outcome along with the transition (if any).
      def perform_transition
        event = @machine.events[@event_name]
        @machine.reset(@object)

        transition = event.transition_for(@object, {}, *@args, **@kwargs)
        if transition.nil?
          event.on_failure(@object, *@args, **@kwargs)
          [:guard_rejected, nil]
        else
          performed = transition.perform(*@args, **@kwargs)
          [performed ? :success : :action_failed, transition]
        end
      end

      def finish(result)
        @mutex.synchronize do
          @result = result
          @state = :completed
          @condition.broadcast
        end
      end

      def finish_with_error(error)
        @mutex.synchronize do
          @error = error
          @state = :completed
          @condition.broadcast
        end
      end
    end
  end
end
