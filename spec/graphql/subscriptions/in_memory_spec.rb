# frozen_string_literal: true
require "spec_helper"

class InMemorySubscriptionsIntegrationSpec < Minitest::Test
  # A Subscription whose +topic_for+ collapses all argument values into one
  # stream, so routing is decided entirely by the explicit indexable filter
  # (rather than by the built-in exact-argument topic matching).
  class PriceAlert < GraphQL::Schema::Subscription
    argument :tenant, String, required: true
    argument :min_amount, Integer, required: false
    field :amount, Integer, null: false
    field :tenant, String, null: false

    def update(tenant:, min_amount: nil)
      object
    end

    def self.topic_for(arguments:, field:, scope:)
      field.graphql_name
    end
  end

  class SubscriptionRoot < GraphQL::Schema::Object
    field :price_alert, subscription: PriceAlert
  end

  class QueryRoot < GraphQL::Schema::Object
    field :ping, Integer
  end

  # Backend that derives an explicit filter from the subscription's arguments.
  class FilteringBackend < GraphQL::Subscriptions::InMemory
    def self.event_filter_for(event, _query)
      args = event.arguments
      conditions = [GraphQL::Subscriptions::Filter.eq("tenant", args[:tenant])]
      if !args[:min_amount].nil?
        conditions << GraphQL::Subscriptions::Filter.gte("amount", args[:min_amount])
      end
      GraphQL::Subscriptions::Filter.and(*conditions)
    end
  end

  class TestSchema < GraphQL::Schema
    query(QueryRoot)
    subscription(SubscriptionRoot)
    use FilteringBackend
  end

  def setup
    TestSchema.subscriptions.reset
    @query_str = <<~GRAPHQL
      subscription ($tenant: String!, $minAmount: Int) {
        priceAlert(tenant: $tenant, minAmount: $minAmount) { amount tenant }
      }
    GRAPHQL
  end

  def subscribe(socket, tenant, min_amount = nil)
    TestSchema.execute(
      @query_str,
      context: { socket: socket },
      variables: { "tenant" => tenant, "minAmount" => min_amount },
      operation_name: nil,
    )
  end

  def trigger(tenant:, amount:)
    TestSchema.subscriptions.trigger(
      :price_alert,
      { "tenant" => tenant },
      OpenStruct.new(tenant: tenant, amount: amount),
      attributes: { "amount" => amount },
    )
  end

  def deliveries_for(socket)
    TestSchema.subscriptions.deliveries[socket] || []
  end

  def test_only_matching_tenant_and_interval_resolvers_run
    subscribe("s-acme-low", "acme", 100)
    subscribe("s-acme-any", "acme")
    subscribe("s-globex", "globex", 0)

    # An event for tenant acme within [100, *]:
    trigger(tenant: "acme", amount: 200)

    # Both acme subscriptions resolve; the globex one never does.
    assert_equal 1, deliveries_for("s-acme-low").length
    assert_equal 1, deliveries_for("s-acme-any").length
    assert_equal 0, deliveries_for("s-globex").length

    # Three subscriptions exist, but only two resolvers were executed.
    assert_equal 2, TestSchema.subscriptions.resolver_call_count

    # A low-amount acme event skips the interval subscription.
    before_low = TestSchema.subscriptions.resolver_call_count
    trigger(tenant: "acme", amount: 50)
    assert_equal before_low + 1, TestSchema.subscriptions.resolver_call_count
    assert_equal 1, deliveries_for("s-acme-low").length
    assert_equal 2, deliveries_for("s-acme-any").length

    # A globex event runs only the globex subscription.
    trigger(tenant: "globex", amount: 50)
    assert_equal 1, deliveries_for("s-globex").length
    assert_equal 1, deliveries_for("s-acme-low").length
  end

  def test_unsubscribe_removes_index_entries
    subscribe("s-acme", "acme")
    sid = deliveries_for("s-acme")

    # The subscription id is exposed on the query context at registration.
    # Delete it the way a transport channel teardown would.
    ids = TestSchema.subscriptions.subscription_ids
    assert_equal 1, ids.length
    TestSchema.subscriptions.delete_subscription(ids.first)

    trigger(tenant: "acme", amount: 200)
    assert_empty TestSchema.subscriptions.deliveries[ids.first] || []
    assert_equal 0, TestSchema.subscriptions.resolver_call_count
  end
end
