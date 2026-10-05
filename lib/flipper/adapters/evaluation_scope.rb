module Flipper
  module Adapters
    # Internal: Per-thread adapter proxy used by DSL evaluation scopes. Feature
    # instances retain this proxy, so enabling a scope affects checks made
    # through Feature objects that were cached before the scope began.
    class EvaluationScope
      THREAD_LOCAL_KEY = :flipper_evaluation_scope_adapters

      attr_reader :adapter

      def initialize(adapter)
        @adapter = adapter
      end

      def current
        scopes[object_id]&.last || @adapter
      end

      def ==(other)
        current == other
      end
      alias_method :eql?, :==

      def hash
        current.hash
      end

      def push(scope_adapter)
        (scopes[object_id] ||= []) << scope_adapter
      end

      def pop
        stack = scopes[object_id]
        stack&.pop
        scopes.delete(object_id) if stack&.empty?
      end

      if RUBY_VERSION >= '3.0'
        def method_missing(name, *args, **kwargs, &block)
          current.public_send(name, *args, **kwargs, &block)
        end
      else
        def method_missing(name, *args, &block)
          current.public_send(name, *args, &block)
        end
      end

      def respond_to_missing?(name, include_private = false)
        current.respond_to?(name, include_private) || super
      end

      private

      def scopes
        Thread.current[THREAD_LOCAL_KEY] ||= {}
      end
    end
  end
end
