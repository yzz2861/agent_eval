# frozen_string_literal: true
module GraphQL
  class Subscriptions
    # A process-local subscriptions backend with explicit, indexable event
    # filtering.
    #
    # One event may fan out to many subscriptions, but usually only a few of
    # them (for example, certain tenants or numeric ranges) are interested in
    # any given occurrence. Subscriptions may register a
    # {GraphQL::Subscriptions::Filter} via `context[:subscription_filter]`;
    # triggers then pass event attributes via `attributes:`. The indexable
    # parts of each filter narrow the candidate set, the full predicate runs
    # on the remaining candidates, and only matching subscriptions are
    # executed. Subscriptions without a filter receive every event, and
    # filters with complex or unknown conditions conservatively fall back to
    # being candidates for every event.
    #
    # The index is kept in sync as subscriptions are registered
    # ({#write_subscription}), re-filtered ({#update_subscription_filter}),
    # and terminated ({#delete_subscription}).
    #
    # This implementation keeps all state in memory, so it's suitable for
    # single-process deployments, development, and tests. (Concurrent
    # {#trigger} calls are not synchronized.)
    #
    # @example Adding InMemorySubscriptions to a schema
    #   class MySchema < GraphQL::Schema
    #     use GraphQL::Subscriptions::InMemorySubscriptions
    #   end
    #
    # @example Subscribing with a filter
    #   MySchema.execute("subscription { thingUpdated }", context: {
    #     subscription_filter: GraphQL::Subscriptions::Filter.eq(:tenant_id, 1),
    #   })
    #
    # @example Triggering with event attributes
    #   MySchema.subscriptions.trigger(:thing_updated, {}, object, attributes: { tenant_id: 1 })
    class InMemorySubscriptions < GraphQL::Subscriptions
      # @return [Hash{String => Array}] subscription_id => delivered results
      attr_reader :deliveries

      def initialize(schema:, **rest)
        super
        # { subscription_id => Hash } saved execution state
        @subscriptions = {}
        # { topic => FilterIndex }
        @topics = {}
        # { subscription_id => [topic, ...] }
        @subscription_topics = Hash.new { |h, k| h[k] = [] }
        @deliveries = Hash.new { |h, k| h[k] = [] }
        @trigger_attributes = nil
      end

      # @param attributes [Hash] event attributes matched against subscription filters
      def trigger(event_name, args, object, scope: nil, context: {}, attributes: {})
        @trigger_attributes = attributes
        super(event_name, args, object, scope: scope, context: context)
      ensure
        @trigger_attributes = nil
      end

      def write_subscription(query, events)
        subscription_id = query.context[:subscription_id] = build_id
        @subscriptions[subscription_id] = {
          query_string: query.query_string,
          operation_name: query.operation_name,
          variables: query.provided_variables,
          context: query.context.to_h.dup,
        }
        filter = query.context[:subscription_filter]
        events.each do |event|
          index = (@topics[event.topic] ||= FilterIndex.new)
          index.add(subscription_id, filter)
          @subscription_topics[subscription_id] << event.topic
        end
        nil
      end

      def read_subscription(subscription_id)
        @subscriptions[subscription_id]
      end

      # Replace the filter for an existing subscription, re-indexing it
      # under every topic it's registered for.
      # @param filter [#matches?, nil] a {GraphQL::Subscriptions::Filter} or nil to receive every event
      # @return [Boolean] whether the subscription exists
      def update_subscription_filter(subscription_id, filter)
        return false if !@subscriptions.key?(subscription_id)
        @subscription_topics[subscription_id].each do |topic|
          if (index = @topics[topic])
            index.add(subscription_id, filter)
          end
        end
        true
      end

      def delete_subscription(subscription_id)
        @subscriptions.delete(subscription_id)
        if (topics = @subscription_topics.delete(subscription_id))
          topics.each do |topic|
            if (index = @topics[topic])
              index.remove(subscription_id)
              @topics.delete(topic) if index.empty?
            end
          end
        end
        nil
      end

      def execute_all(event, object)
        index = @topics[event.topic]
        return if index.nil?
        attributes = @trigger_attributes || {}
        index.matching_subscription_ids(attributes).each do |subscription_id|
          execute(subscription_id, event, object)
        end
        nil
      end

      def deliver(subscription_id, result)
        @deliveries[subscription_id] << result
        nil
      end

      # Remove all subscriptions, indexes, and deliveries. (Mostly for tests.)
      # @return [void]
      def reset!
        @subscriptions.clear
        @topics.clear
        @subscription_topics.clear
        @deliveries.clear
        nil
      end

      # @return [FilterIndex, nil] the index for `topic`, for inspection
      def index_for(topic)
        @topics[topic]
      end
    end
  end
end
