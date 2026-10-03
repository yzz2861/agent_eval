# frozen_string_literal: true

module StateMachines
  module AsyncMode
    # Extensions to Event class for async bang methods
    module AsyncEventExtensions
      # Generate async bang methods for events when async mode is enabled
      def define_helper(scope, method, *args, &)
        result = super

        # If this is an async-enabled machine and we're defining an event method
        if scope == :instance && method !~ /_async[!]?$/ && machine.async_mode_enabled?
          qualified_name = method.to_s

          # Create async version that returns a transition handle
          machine.define_helper(scope, "#{qualified_name}_async") do |machine, object, *method_args, **kwargs|
            TransitionHandle.start(object, name, *method_args, **kwargs)
          end

          # Create async bang version that raises exceptions when awaited
          machine.define_helper(scope, "#{qualified_name}_async!") do |machine, object, *method_args, **kwargs|
            TransitionHandle.start(object, name, *method_args, **kwargs, bang: true)
          end
        end

        result
      end
    end
  end
end
