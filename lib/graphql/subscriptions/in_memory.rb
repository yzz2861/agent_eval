# frozen_string_literal: true
require "set"
require "graphql/subscriptions/filter"
require "graphql/subscriptions/filtered_registry"

module GraphQL
  class Subscriptions
    # A fully in-process subscriptions implementation backed by a
    # FilteredRegistry. Unlike ActionCableSubscriptions, which broadcasts an
    # event to every subscriber of a topic and lets each client re-evaluate,
    # this backend narrows the candidate subscriptions with per-attribute
    # indexes and only re-runs the matching subscriptions' resolvers.
    #
    # The filter condition for a subscription is provided by
    # .event_filter_for (override it to derive a filter from the field,
    # arguments or context). A nil filter means "no explicit condition": the
    # subscription is indexed only by event name and always evaluated for a
    # matching trigger.
    #
    # @example
    #   class MySchema < GraphQL::Schema
    #     use GraphQL::Subscriptions::InMemory
    #   end
    class InMemory < GraphQL::Subscriptions
      # @return [Integer] number of subscription resolvers executed since init/reset
      attr_reader :resolver_call_count

      def initialize(schema:, **rest)
        super
        @registry = FilteredRegistry.new
        # subscription_id => saved query data
        @queries = {}
        @mutex = Mutex.new
        @deliveries = {}
        @resolver_call_count = 0
      end

      # @!group Standalone registry API
      # These helpers make the filter/index machinery usable without a full
      # GraphQL transport. The resolver is invoked only for confirmed matches.

      # @param subscription_id [String]
      # @param event [String, Symbol]
      # @param filter [Filter::Node, Hash, #call, nil]
      # @param resolver [#call, nil] evaluated with event attributes on a match
      # @return [FilteredRegistry::Entry]
      def register(subscription_id, event, filter = nil, resolver: nil, data: nil, &block)
        @registry.register(subscription_id, event, filter, data: data || resolver || block)
      end

      # Replace a subscription's filter and update the indexes synchronously.
      # @param subscription_id [String]
      # @param filter [Filter::Node, Hash, #call, nil]
      # @return [Array<FilteredRegistry::Entry>, nil]
      def update_filter(subscription_id, filter)
        @registry.update(subscription_id, filter)
      end

      # Narrow candidates via the index, run the full predicate, then invoke the
      # registered resolver once per confirmed match.
      # @param event [String, Symbol]
      # @param attributes [Hash]
      # @return [Array] the resolver results, in registry order
      def trigger_filtered(event, attributes)
        matches = @registry.matching(event, attributes)
        matches.map do |entry|
          increment_resolver_calls
          entry.data.nil? ? nil : entry.data.call(attributes)
        end
      end

      # @return [Array<FilteredRegistry::Entry>] candidates before full predicate
      def candidates_for(event, attributes)
        @registry.candidates_for(event, attributes)
      end

      # @return [Array<FilteredRegistry::Entry>] confirmed matches after the full predicate
      def matching(event, attributes)
        @registry.matching(event, attributes)
      end

      # @return [Array<FilteredRegistry::Entry>] all registrations for one subscription id
      def entries_for(subscription_id)
        @registry.entries_for(subscription_id)
      end

      # @return [Array<String>] registered subscription ids
      def subscription_ids
        @registry.subscription_ids
      end

      # @!endgroup

      def reset
        @mutex.synchronize do
          @registry = FilteredRegistry.new
          @queries.clear
          @deliveries.clear
          @resolver_call_count = 0
        end
      end

      # @return [Hash{String => Array}] deliveries recorded since init/reset
      attr_reader :deliveries

      # GraphQL::Subscriptions integration ---------------------------------

      def write_subscription(query, events)
        subscription_id = query.context[:subscription_id] ||= build_id
        @mutex.synchronize do
          @queries[subscription_id] = {
            query: query,
            query_string: query.query_string,
            variables: query.provided_variables,
            context: query.context.to_h,
            operation_name: query.operation_name,
          }

          events.each do |event|
            filter = self.class.event_filter_for(event, query)
            @registry.register(subscription_id, event.name, filter, data: { query: query })
          end
        end
      end

      def read_subscription(subscription_id)
        data = @mutex.synchronize { @queries[subscription_id] }
        return nil if data.nil?
        {
          query_string: data[:query_string],
          variables: data[:variables],
          context: data[:context],
          operation_name: data[:operation_name],
        }
      end

      def delete_subscription(subscription_id)
        @registry.unregister(subscription_id)
        @mutex.synchronize { @queries.delete(subscription_id) }
      end

      def execute_all(event, object)
        attributes = event.respond_to?(:attributes) ? event.attributes : event.arguments
        entries = @registry.matching(event.name, attributes)
        entries.each do |entry|
          increment_resolver_calls
          execute(entry.id, event, object)
        end
      end

      def deliver(subscription_id, result)
        # No transport in the in-memory backend; record for inspection/tests.
        @mutex.synchronize do
          socket = delivery_socket(subscription_id) || subscription_id
          (@deliveries[socket] ||= []) << result
        end
        result
      end

      # Derive the explicit filter for a subscription. Override to read from
      # field configuration, arguments or context. Defaults to no filter.
      # @param event [GraphQL::Subscriptions::Event]
      # @param query [GraphQL::Query]
      # @return [Filter::Node, Hash, #call, nil]
      def self.event_filter_for(_event, _query)
        nil
      end

      private

      def increment_resolver_calls
        @mutex.synchronize { @resolver_call_count += 1 }
      end

      def delivery_socket(subscription_id)
        data = @queries[subscription_id]
        context = data && data[:context]
        context[:socket] if context
      end
    end
  end
end
