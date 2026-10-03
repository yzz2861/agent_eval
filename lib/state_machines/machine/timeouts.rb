# frozen_string_literal: true

module StateMachines
  class Machine
    # Adds support for state timeouts: states declared with a +timeout+
    # option automatically fire an event (default +:timeout+) once the
    # configured delay has elapsed after the state was entered.
    #
    # The library deliberately does *not* spawn background threads or maintain
    # a persistent queue.  Instead, the application provides a scheduler via
    # the machine's +:scheduler+ option.  A scheduler is any object that
    # responds to:
    #
    #   schedule(delay_in_seconds) { ... } # => handle
    #
    # and invokes the given block once the delay has elapsed.  The returned
    # handle may optionally respond to +cancel+; it is used to eagerly cancel
    # timers when the state is left.  Even when a handle cannot be canceled
    # (or a stale callback fires anyway), the callback is verified against a
    # per-entry token and the object's current state, so superseded timers
    # are always ignored.
    #
    # == Example
    #
    #   class Order
    #     state_machine :state, initial: :pending, scheduler: MyScheduler.new do
    #       state :awaiting_payment, timeout: 300
    #
    #       event :timeout do
    #         transition awaiting_payment: :expired
    #       end
    #     end
    #   end
    module Timeouts
      # Tracks a single armed state timeout for an object
      TimeoutRecord = Struct.new(:token, :handle, :deadline, :state_name, :event_name)

      # The scheduler used to arm state timeouts.  Must respond to
      # +schedule(delay, &callback)+.  The return value may respond to
      # +cancel+.
      attr_accessor :scheduler

      # The clock used to compute timeout deadlines.  Must respond to +call+
      # and return a value comparable to (and addable with) the timeout
      # delays, e.g. a Time.  Defaults to the current wall clock.
      attr_accessor :clock

      private

      # Installs the internal after_transition hook that arms/cancels state
      # timeouts.  Called automatically the first time a state is configured
      # with a timeout.
      def install_state_timeout_hook
        return if @state_timeout_hook_installed

        @state_timeout_hook_installed = true
        after_transition do |object, transition|
          transition.machine.send(:refresh_state_timeout, object, transition)
        end
      end

      # Reconciles the armed timeout with the state the object just
      # transitioned into: any previously armed timer is canceled and, if the
      # new state declares a timeout, a fresh timer is armed.
      def refresh_state_timeout(object, transition)
        cancel_state_timeout(object)

        state = states.fetch(transition.to_name)
        arm_state_timeout(object, state) if state.timeout
      end

      # Arms a new timeout for the given object and state.  Dynamic (Proc)
      # timeouts are evaluated exactly once, here, at entry time.
      #
      # If the scheduler cannot be invoked, a StateMachines::SchedulingError
      # is raised to the caller that triggered the transition and no timeout
      # record is left behind, so the object never appears to have a timer
      # armed when it does not.
      def arm_state_timeout(object, state)
        scheduler = @scheduler
        unless scheduler.respond_to?(:schedule)
          raise StateMachines::SchedulingError.new(object, "Cannot arm timeout for #{name}.#{state.name.inspect}: no scheduler configured. Pass the :scheduler option to the state machine.")
        end

        duration = state.timeout.is_a?(Proc) ? evaluate_method(object, state.timeout) : state.timeout
        unless duration.is_a?(Numeric) && duration >= 0
          raise StateMachines::SchedulingError.new(object, "Cannot arm timeout for #{name}.#{state.name.inspect}: timeout must evaluate to a non-negative number, got #{duration.inspect}")
        end

        record = TimeoutRecord.new(Object.new, nil, @clock.call + duration, state.name, state.timeout_event || :timeout)

        begin
          record.handle = scheduler.schedule(duration) { dispatch_state_timeout(object, record.token) }
        rescue StandardError => e
          raise StateMachines::SchedulingError.new(object, "Failed to schedule timeout for #{name}.#{state.name.inspect}: #{e.message}")
        end

        state_timeout_records(object)[name] = record
        record
      end

      # Cancels any timeout currently armed for the object on this machine.
      def cancel_state_timeout(object)
        record = state_timeout_records(object).delete(name)
        return unless record

        handle = record.handle
        handle.cancel if handle.respond_to?(:cancel)
        record
      end

      # Dispatches a fired timer.  Callbacks that arrive late (after the
      # object left the state or a newer timer superseded them) are ignored.
      # Callbacks that arrive before the deadline (e.g. scheduler clock skew)
      # are re-armed for the remaining delay.  On-time callbacks fire the
      # state's timeout event through the regular event machinery, so the
      # event's own transition guards decide whether a transition happens.
      def dispatch_state_timeout(object, token)
        record = state_timeout_records(object)[name]
        return unless record && record.token.equal?(token)

        state = states.match(object)
        return unless state && state.name == record.state_name

        now = @clock.call
        if now < record.deadline
          remaining = record.deadline - now
          record.handle = @scheduler.schedule(remaining) { dispatch_state_timeout(object, record.token) }
          return
        end

        state_timeout_records(object).delete(name)

        event = events[record.event_name]
        unless event
          raise StateMachines::SchedulingError.new(object, "Cannot fire timeout for #{name}.#{record.state_name.inspect}: #{record.event_name.inspect} is not a defined event")
        end

        event.fire(object)
      end

      # The per-object registry of armed timeouts, keyed by machine name
      def state_timeout_records(object)
        object.instance_variable_get(:@_state_machine_state_timeouts) ||
          object.instance_variable_set(:@_state_machine_state_timeouts, {})
      end
    end
  end
end
