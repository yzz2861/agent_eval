# frozen_string_literal: true

module StateMachines
  class Machine
    # Adds support for state-scoped timeouts.  A state can declare how long an
    # object may remain in it before a timeout event is automatically fired:
    #
    #   class Order
    #     state_machine initial: :pending do
    #       event :start_payment do
    #         transition pending: :awaiting_payment
    #       end
    #
    #       event :timeout do
    #         transition awaiting_payment: :expired
    #       end
    #
    #       state :awaiting_payment, timeout: 300
    #     end
    #   end
    #
    # The timeout duration may also be computed dynamically when the state is
    # entered (evaluated exactly once per entry):
    #
    #   state :awaiting_payment, timeout: ->(order) { order.payment_window }
    #
    # A custom event can be fired instead of :timeout:
    #
    #   state :awaiting_payment, timeout: 300, timeout_event: :expire
    #
    # == Schedulers
    #
    # This library does *not* ship with background threads or persistent
    # queues.  Instead, the application provides a scheduler that responds to
    # +schedule(delay_in_seconds, &block)+ and returns a handle:
    #
    #   machine.timeout_scheduler = MyScheduler.new
    #
    # Pending timeouts are cancelled through the returned handle (if it
    # responds to +cancel+) or through the scheduler itself (if it responds to
    # +cancel(handle)+).
    #
    # Timeouts are armed whenever a transition *into* the state succeeds and
    # are cancelled whenever the object leaves the state -- including loopback
    # transitions that re-enter the same state, in which case a fresh timeout
    # is armed.  If the scheduler fails to schedule the timeout, the error is
    # re-raised to the caller of the event and no timeout is left pending.
    module Timeouts
      # The scheduler used to arm state timeouts.  Must respond to
      # +schedule(delay, &block)+ and return a handle.
      attr_accessor :timeout_scheduler

      # Tracks a single armed timeout for an object.  The registration acts as
      # a token: callbacks only fire while the registration is still the
      # current one for the machine, so stale timers (e.g. from a previous
      # entry into the same state) are discarded.
      class TimeoutRegistration # :nodoc:
        attr_accessor :handle

        def initialize(scheduler)
          @scheduler = scheduler
        end

        def cancel
          handle = @handle
          @handle = nil
          return unless handle

          if handle.respond_to?(:cancel)
            handle.cancel
          elsif @scheduler.respond_to?(:cancel)
            @scheduler.cancel(handle)
          end
        end
      end

      # Whether a state timeout is currently armed for the given object
      def state_timeout_pending?(object)
        !timeout_registrations(object)[name].nil?
      end

      # Cancels any state timeout currently armed for the given object
      def cancel_state_timeout(object)
        registration = timeout_registrations(object).delete(name)
        registration&.cancel
        nil
      end

      private

      # Hooks timeout tracking into successful transitions.  This is enabled
      # lazily the first time a state declares a timeout so that machines
      # without timeouts are completely unaffected.
      def enable_timeout_tracking!
        return if @timeout_tracking_enabled

        @timeout_tracking_enabled = true
        after_transition do |object, transition|
          transition.machine.send(:refresh_state_timeout, object)
        end
      end

      # Re-arms the timeout for the object's current state after a successful
      # transition.  Any previously armed timeout is always cancelled first,
      # so re-entering the same state invalidates the previous timer.
      def refresh_state_timeout(object)
        cancel_state_timeout(object)

        state = states.match!(object)
        schedule_state_timeout(object, state) if state.timeout
      end

      # Computes the timeout duration (once) and arms the scheduler
      def schedule_state_timeout(object, state)
        scheduler = timeout_scheduler
        unless scheduler
          raise StateMachines::Error.new(object,
                                         "Cannot schedule timeout for state #{state.name.inspect}: " +                                         "no timeout_scheduler configured for the #{name.inspect} machine")
        end

        delay = state.timeout.is_a?(Numeric) ? state.timeout : evaluate_method(object, state.timeout)
        unless delay.is_a?(Numeric) && delay >= 0
          raise StateMachines::Error.new(object,
                                         "Cannot schedule timeout for state #{state.name.inspect}: " +                                         "timeout duration must be a non-negative number, got #{delay.inspect}")
        end

        event_name = state.timeout_event || :timeout
        event = events[event_name]
        raise StateMachines::InvalidEvent.new(object, event_name) unless event

        registrations = timeout_registrations(object)
        registration = TimeoutRegistration.new(scheduler)
        registrations[name] = registration

        begin
          registration.handle = scheduler.schedule(delay) do
            fire_state_timeout(object, registration, event, state)
          end
        rescue Exception
          # Don't leave the object looking like a timeout is armed when the
          # scheduler failed to schedule it
          registrations.delete(name) if registrations[name].equal?(registration)
          raise
        end

        registration
      end

      # Fires the timeout event for an armed registration.  Stale
      # registrations (cancelled or replaced by a newer entry into the state)
      # are discarded, guaranteeing that a manual transition racing with the
      # timeout results in exactly one successful transition.
      def fire_state_timeout(object, registration, event, state)
        registrations = timeout_registrations(object)
        return false unless registrations[name].equal?(registration)

        registrations.delete(name)
        return false unless states.matches?(object, state.name)

        event.fire(object)
      end

      # The timeout registrations stored on the object, keyed by machine name
      def timeout_registrations(object)
        if object.instance_variable_defined?(:@_state_machine_timeouts)
          object.instance_variable_get(:@_state_machine_timeouts)
        else
          object.instance_variable_set(:@_state_machine_timeouts, {})
        end
      end
    end
  end
end
