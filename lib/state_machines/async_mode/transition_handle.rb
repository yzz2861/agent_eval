# frozen_string_literal: true

module StateMachines
  module AsyncMode
    # Queryable, waitable handle for a transition that may run in a Thread or
    # an Async fiber. Cancellation is only a claim operation; it never stops a
    # running transition or reverses external side effects.
    class TransitionHandle
      def self.start(object, event_name, *args, bang: false, qualified: false, **kwargs)
        machine = object.class.state_machines.values.find do |candidate|
          candidate.async_mode_enabled? && candidate.events[event_name, qualified ? :qualified_name : :name]
        end
        raise ArgumentError, "Event #{event_name} not found in any state machine" unless machine

        event = machine.events[event_name, qualified ? :qualified_name : :name]
        mode = defined?(::Async::Task) && ::Async::Task.current? ? :async : :thread
        event_name = event.name if qualified
        new(object, machine, event, event_name, args, kwargs, mode: mode, bang: bang)
      end

      attr_reader :event_name, :mode, :result, :exception

      def initialize(object, machine, event, event_name, args, kwargs, mode:, bang:)
        @object = object
        @machine = machine
        @event = event
        @event_name = event_name
        @args = args
        @kwargs = kwargs
        @mode = mode
        @bang = bang

        @mutex = Mutex.new
        @state = :pending
        @started = false
        @result = nil
        @exception = nil

        @ready = build_queue
        @start = build_queue
        @completion = ::Thread::Queue.new
        @worker = start_worker

        @ready.pop
      end

      def status
        @mutex.synchronize { @state }
      end
      alias state status

      def pending?
        status == :pending
      end

      def claimed?
        status == :running
      end
      alias running? claimed?

      def terminal?
        %i[cancelled guard_rejected action_failed succeeded].include?(status)
      end
      alias complete? terminal?
      alias completed? terminal?

      def cancel
        cancelled = @mutex.synchronize do
          next false unless @state == :pending

          @state = :cancelled
          @result = TransitionResult.cancelled
          true
        end

        @start.push(:cancel) if cancelled
        cancelled
      end

      def wait
        schedule_start
        @completion.pop unless terminal?
        outcome = @mutex.synchronize { @result }

        raise @exception if @bang && @exception
        raise InvalidTransition.new(@object, @machine, @event_name) if @bang && !outcome.succeeded? && !outcome.cancelled?

        outcome
      end
      alias join wait

      def start
        schedule_start
        self
      end

      def cancelled?
        status == :cancelled
      end

      def guard_rejected?
        status == :guard_rejected
      end

      def action_failed?
        status == :action_failed
      end

      def succeeded?
        status == :succeeded
      end

      def inspect
        "#<#{self.class} event=#{@event_name.inspect} status=#{status.inspect} mode=#{@mode.inspect}>"
      end

      private

      def schedule_start
        should_start = @mutex.synchronize do
          next false if @started
          next false unless @state == :pending

          @started = true
        end

        @start.push(:start) if should_start
        self
      end

      def start_worker
        if @mode == :async
          Async(transient: true) { run }
        else
          Thread.new { run }.tap do |thread|
            thread.report_on_exception = false
            thread.abort_on_exception = false
          end
        end
      end

      def build_queue
        @mode == :async ? ::Async::Queue.new : ::Thread::Queue.new
      end

      def run
        @ready.push(:ready)
        @start.pop
        return unless claim

        begin
          finish(@event.fire_with_result(@object, *@args, **@kwargs))
        rescue StandardError => error
          finish(TransitionResult.action_failed(exception: error))
        end
      end

      def claim
        acquired = @mutex.synchronize do
          next false unless @state == :pending

          @state = :running
          true
        end
        @worker.transient = false if acquired && @mode == :async
        acquired
      end

      def finish(outcome)
        @mutex.synchronize do
          return unless @state == :running

          @state = outcome.status
          @result = outcome
          @exception = outcome.exception
        end

        @completion.push(outcome)
      end
    end
  end
end
