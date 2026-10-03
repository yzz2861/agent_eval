# frozen_string_literal: true

module StateMachines
  module AsyncMode
    module AsyncEvents
      def async_fire_event(event_name, *args, **kwargs)
        async_machine_for_event!(event_name)
        TransitionHandle.start(self, event_name, *args, **kwargs)
      end

      def async_fire_qualified_event(event_name, *args, bang: false, **kwargs)
        async_machine_for_event!(event_name, qualified: true)
        TransitionHandle.start(self, event_name, *args, bang: bang, qualified: true, **kwargs)
      end

      def async_fire_events(*event_names)
        event_names.map { |event_name| async_fire_event(event_name) }
      end

      def fire_event_async(event_name, *args, **kwargs)
        async_fire_event(event_name, *args, **kwargs)
      end

      def fire_events_async(*event_names)
        async_fire_events(*event_names)
      end

      def async_fire_event!(event_name, *args, **kwargs)
        async_machine_for_event!(event_name)
        TransitionHandle.start(self, event_name, *args, bang: true, **kwargs)
      end

      def fire_event_async!(event_name, *args, **kwargs)
        async_fire_event!(event_name, *args, **kwargs)
      end

      def fire_events_concurrent(*event_names)
        async_fire_events(*event_names).map(&:wait)
      end

      def method_missing(method_name, *args, **kwargs, &block)
        method_str = method_name.to_s

        if method_str.end_with?('_async!')
          base_method = method_str.chomp('_async!').to_sym
          if respond_to?(base_method, true) && async_method_for_event?(base_method)
            return async_fire_qualified_event(base_method.to_s, *args, **kwargs, bang: true)
          end
        elsif method_str.end_with?('_async')
          base_method = method_str.chomp('_async').to_sym
          if respond_to?(base_method, true) && async_method_for_event?(base_method)
            return async_fire_qualified_event(base_method.to_s, *args, **kwargs)
          end
        end

        super
      end

      def respond_to_missing?(method_name, include_private = false)
        return super unless has_async_machines?

        method_str = method_name.to_s
        if method_str.end_with?('_async!') || method_str.end_with?('_async')
          base_method = method_str.chomp('_async!').chomp('_async').to_sym
          return respond_to?(base_method, include_private) && async_method_for_event?(base_method)
        end

        super
      end

      def has_async_machines?
        self.class.state_machines.any? { |_name, machine| machine.async_mode_enabled? }
      end

      private

      def async_machine_for_event!(event_name, qualified: false)
        machine = self.class.state_machines.values.find do |candidate|
          candidate.async_mode_enabled? && candidate.events[event_name, qualified ? :qualified_name : :name]
        end
        raise ArgumentError, "Event #{event_name} not found in an async state machine" unless machine

        machine
      end

      def async_method_for_event?(event_method)
        self.class.state_machines.any? do |_name, machine|
          next false unless machine.async_mode_enabled?

          machine.events.any? do |event|
            event.qualified_name == event_method || "#{event.qualified_name}!" == event_method.to_s
          end
        end
      end

    end
  end
end
