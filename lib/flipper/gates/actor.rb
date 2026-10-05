module Flipper
  module Gates
    class Actor < Gate
      # Internal: The name of the gate. Used for instrumentation, etc.
      def name
        :actor
      end

      # Internal: Name converted to value safe for adapter.
      def key
        :actors
      end

      def data_type
        :set
      end

      def enabled?(value)
        !value.empty?
      end

      # Internal: Checks if the gate is open for an actor.
      #
      # Returns true if gate open for actor, false if not.
      def open?(context)
        return false unless context.actors?

        # When an actor index is configured, defer to it entirely. The index
        # excludes actors that are definitely not on the allowlist without
        # loading the full set, and confirms possible hits with a precise
        # query, so the answer stays authoritative.
        if (index = context.actor_index)
          return context.actors.any? do |actor|
            index.include?(actor.value)
          end
        end

        enabled_actors = context.values.actors
        return false if enabled_actors.empty?

        context.actors.any? do |actor|
          enabled_actors.include?(actor.value)
        end
      end

      def wrap(actor)
        Types::Actor.wrap(actor)
      end

      def protects?(actor)
        Types::Actor.wrappable?(actor)
      end
    end
  end
end
