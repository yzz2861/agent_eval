require "flipper/expression"

module Flipper
  module Gates
    class Expression < Gate
      # Internal: The name of the gate. Used for instrumentation, etc.
      def name
        :expression
      end

      # Internal: Name converted to value safe for adapter.
      def key
        :expression
      end

      def data_type
        :json
      end

      def enabled?(value)
        !value.nil? && !value.empty?
      end

      # Internal: Checks if the gate is open for a thing.
      #
      # Returns true if gate open for thing, false if not.
      def open?(context)
        data = context.values.expression
        return false if data.nil? || data.empty?
        expression = Flipper::Expression.build(data)

        expression_context = {
          feature_name: context.feature_name,
          actors: context.actors,
          original_actors: context.original_actors,
          evaluation: context.evaluation,
          feature_provider: context.feature_provider,
        }

        if context.actors.nil? || context.actors.empty?
          !!expression.evaluate(expression_context.merge(properties: DEFAULT_PROPERTIES, actor: nil))
        else
          context.actors.each_with_index.any? do |actor, index|
            actor_evaluation = context.evaluation.for_actor(actor, index)
            actor_context = expression_context.merge(
              evaluation: actor_evaluation,
              properties: properties(actor),
              actor: actor,
            )
            !!expression.evaluate(actor_context)
          end
        end
      end

      def protects?(thing)
        thing.is_a?(Flipper::Expression) || thing.is_a?(Hash)
      end

      def wrap(thing)
        Flipper::Expression.build(thing)
      end

      private

      # Internal
      DEFAULT_PROPERTIES = {}.freeze

      def properties(actor)
        return DEFAULT_PROPERTIES if actor.nil?

        properties = {}

        if actor.respond_to?(:flipper_properties)
          properties.update(actor.flipper_properties)
        else
          warn "#{actor.inspect} does not respond to `flipper_properties` but should."
        end

        properties.transform_keys!(&:to_s)

        if actor.respond_to?(:flipper_id)
          properties["flipper_id".freeze] = actor.flipper_id
        end

        properties
      end
    end
  end
end
