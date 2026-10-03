# frozen_string_literal: true

module StateMachines
  module AsyncMode
    # Async-aware event firing capabilities using the async gem
    module AsyncEvents
      # Fires an event asynchronously and returns a TransitionHandle
      #
      # The handle is queryable (status, pending?, claimed?, cancelled?,
      # completed?), awaitable (wait/result return a TransitionResult), and
      # cancellable (cancel) as long as the executor hasn't claimed it yet.
      # Inside an Async reactor the transition runs on an Async child task,
      # otherwise it runs on a background thread.
      #
      # Example:
      #   Async do
      #     handle = vehicle.async_fire_event(:ignite)
      #     result = handle.wait # => #<TransitionResult success>
      #   end
      def async_fire_event(event_name, *args)
        machine = find_machine_for_event!(event_name)

        TransitionHandle.schedule(self, machine, event_name, args)
      end

      # Fires multiple events asynchronously across different state machines
      # Returns an array of TransitionHandles for concurrent execution
      #
      # Example:
      #   Async do
      #     handles = vehicle.async_fire_events(:ignite, :buy_insurance)
      #     results = handles.map(&:wait) # => [#<TransitionResult success>, ...]
      #   end
      def async_fire_events(*event_names)
        event_names.map { |event_name| async_fire_event(event_name) }
      end

      # Fires an event asynchronously and waits for completion
      # This is a convenience method that schedules a handle and waits for it
      #
      # Example:
      #   result = vehicle.fire_event_async(:ignite) # => #<TransitionResult success>
      def fire_event_async(event_name, *args)
        raise NoMethodError, "undefined method `fire_event_async' for #{self}" unless has_async_machines?

        async_fire_event(event_name, *args).wait
      end

      # Fires multiple events asynchronously and waits for all completions
      # Returns TransitionResults in the same order as the input events
      #
      # Example:
      #   results = vehicle.fire_events_async(:ignite, :buy_insurance)
      #   results.map(&:outcome) # => [:success, :success]
      def fire_events_async(*event_names)
        raise NoMethodError, "undefined method `fire_events_async' for #{self}" unless has_async_machines?

        async_fire_events(*event_names).map(&:wait)
      end

      # Fires an event asynchronously and raises exception on failure
      # Returns a TransitionHandle that raises StateMachines::InvalidTransition
      # when awaited and the guard rejects the event or the action fails
      #
      # Example:
      #   Async do
      #     begin
      #       handle = vehicle.async_fire_event!(:ignite)
      #       result = handle.wait
      #       puts "Event fired successfully!"
      #     rescue StateMachines::InvalidTransition => e
      #       puts "Transition failed: #{e.message}"
      #     end
      #   end
      def async_fire_event!(event_name, *args)
        machine = find_machine_for_event!(event_name)

        TransitionHandle.schedule(self, machine, event_name, args, raise_on_failure: true)
      end

      # Fires an event asynchronously and waits for result, raising exceptions on failure
      # This is a convenience method that schedules a handle and waits for it
      #
      # Example:
      #   begin
      #     result = vehicle.fire_event_async!(:ignite)
      #     puts "Event fired successfully!"
      #   rescue StateMachines::InvalidTransition => e
      #     puts "Transition failed: #{e.message}"
      #   end
      def fire_event_async!(event_name, *args)
        raise NoMethodError, "undefined method `fire_event_async!' for #{self}" unless has_async_machines?

        async_fire_event!(event_name, *args).wait
      end

      # Dynamically handle individual event async methods
      # This provides launch_async, launch_async!, arm_weapons_async, etc.
      def method_missing(method_name, *, **, &)
        method_str = method_name.to_s

        # Check if this is an async event method
        if method_str.end_with?('_async!')
          # Remove the _async! suffix to get the base event method
          base_method = method_str.chomp('_async!').to_sym

          # Check if the base method exists and this machine is async-enabled
          if respond_to?(base_method) && async_method_for_event?(base_method)
            return handle_individual_event_async_bang(base_method, *, **)
          end
        elsif method_str.end_with?('_async')
          # Remove the _async suffix to get the base event method
          base_method = method_str.chomp('_async').to_sym

          # Check if the base method exists and this machine is async-enabled
          if respond_to?(base_method) && async_method_for_event?(base_method)
            return handle_individual_event_async(base_method, *, **)
          end
        end

        # If not an async method, call the original method_missing
        super
      end

      # Check if we should respond to async methods for this event
      def respond_to_missing?(method_name, include_private = false)
        # Only provide async methods if this object has async-enabled machines
        return super unless has_async_machines?

        method_str = method_name.to_s

        if method_str.end_with?('_async!') || method_str.end_with?('_async')
          base_method = method_str.chomp('_async!').chomp('_async').to_sym
          return respond_to?(base_method) && async_method_for_event?(base_method)
        end

        super
      end

      # Check if this object has any async-enabled state machines
      def has_async_machines?
        self.class.state_machines.any? { |name, machine| machine.async_mode_enabled? }
      end

      private

      # Finds the machine that defines the given event, raising if none does
      def find_machine_for_event!(event_name)
        machine = self.class.state_machines.values.find { |m| m.events[event_name] }

        unless machine
          raise ArgumentError, "Event #{event_name} not found in any state machine"
        end

        machine
      end

      # Check if this event method should have async versions
      def async_method_for_event?(event_method)
        # Find which machine contains this event
        self.class.state_machines.each do |name, machine|
          if machine.async_mode_enabled?
            # Check if this event method belongs to this machine
            machine.events.each do |event|
              qualified_name = event.qualified_name
              if qualified_name.to_sym == event_method || "#{qualified_name}!".to_sym == event_method
                return true
              end
            end
          end
        end
        false
      end

      # Handle individual event async methods (returns a TransitionHandle)
      def handle_individual_event_async(event_method, *args, **kwargs)
        machine, event_name = find_async_machine_and_event(event_method)

        TransitionHandle.schedule(self, machine, event_name, args, kwargs)
      end

      # Handle individual event async bang methods (returns a TransitionHandle
      # that raises StateMachines::InvalidTransition when awaited on failure)
      def handle_individual_event_async_bang(event_method, *args, **kwargs)
        machine, event_name = find_async_machine_and_event(event_method)

        TransitionHandle.schedule(self, machine, event_name, args, kwargs, raise_on_failure: true)
      end

      # Finds the async-enabled machine and unqualified event name for the
      # given (possibly qualified) event method name
      def find_async_machine_and_event(event_method)
        self.class.state_machines.each_value do |machine|
          next unless machine.async_mode_enabled?

          if (event = machine.events[event_method, :qualified_name])
            return [machine, event.name]
          end
        end

        raise ArgumentError, "Event #{event_method} not found in any async-enabled state machine"
      end

      public

      # Fires multiple events concurrently within an async context
      # This method should be called from within an Async block
      #
      # Example:
      #   Async do
      #     results = vehicle.fire_events_concurrent(:ignite, :buy_insurance)
      #   end
      def fire_events_concurrent(*event_names)
        unless defined?(::Async::Task) && ::Async::Task.current?
          raise RuntimeError, "fire_events_concurrent must be called within an Async context"
        end

        tasks = async_fire_events(*event_names)
        tasks.map(&:wait)
      end
    end
  end
end
