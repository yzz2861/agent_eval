# frozen_string_literal: true

module StateMachines
  module AsyncMode
    # Enhanced machine class with async capabilities
    module AsyncMachine
      # Thread-safe state reading for machines
      def read_safely(object, attribute, ivar = false)
        if object.respond_to?(:read_state_safely)
          object.read_state_safely(self, attribute, ivar)
        else
          read(object, attribute, ivar)
        end
      end

      # Thread-safe state writing for machines
      def write_safely(object, attribute, value, ivar = false)
        if object.respond_to?(:write_state_safely)
          object.write_state_safely(self, attribute, value, ivar)
        else
          write(object, attribute, value, ivar)
        end
      end

      # Fires an event asynchronously on the given object
      # Returns a queryable and waitable TransitionHandle
      def async_fire_event(object, event_name, *args)
        return TransitionHandle.start(object, event_name, *args) if async_mode_enabled?

        raise RuntimeError, "event #{event_name.inspect} is not configured for async execution"
      end

      # Creates an async-aware transition collection
      # Supports concurrent transition execution with proper synchronization
      def create_async_transition_collection(transitions, options = {})
        if defined?(AsyncTransitionCollection)
          AsyncTransitionCollection.new(transitions, options)
        else
          # Fallback to regular collection if async collection isn't available
          TransitionCollection.new(transitions, options)
        end
      end

      # Thread-safe callback execution for async operations
      def run_callbacks_safely(type, object, context, transition)
        if object.respond_to?(:state_machine_mutex)
          object.state_machine_mutex.with_read_lock do
            callbacks[type].each { |callback| callback.call(object, context, transition) }
          end
        else
          callbacks[type].each { |callback| callback.call(object, context, transition) }
        end
      end
    end
  end
end
