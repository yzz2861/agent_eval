# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Subscriptions::InMemorySubscriptions do

  class FilteredSubscriptionSchema < GraphQL::Schema
    def self.resolver_calls
      @resolver_calls ||= Hash.new(0)
    end

    def self.reset_counts!
      resolver_calls.clear
    end

    class SubscriptionRoot < GraphQL::Schema::Object
      field :tenant_event, String, null: false

      def tenant_event
        if context.query.subscription_update?
          # Count one resolver call per subscription label, so tests can prove
          # which subscriptions were (and weren't) executed for an event.
          context.schema.resolver_calls[context[:label]] += 1
          if context[:unsubscribe]
            context.namespace(:subscriptions)[:unsubscribed] = true
          end
        end
        object || "initial"
      end
    end

    class QueryRoot < GraphQL::Schema::Object
      field :dummy, Integer
    end

    query QueryRoot
    subscription SubscriptionRoot
    use GraphQL::Subscriptions::InMemorySubscriptions
  end

  def subscriptions
    FilteredSubscriptionSchema.subscriptions
  end

  def subscribe(label, filter, **extra_context)
    result = FilteredSubscriptionSchema.execute(
      "subscription { tenantEvent }",
      context: { label: label, subscription_filter: filter }.merge(extra_context),
    )
    result.context[:subscription_id]
  end

  def trigger(attributes)
    subscriptions.trigger(:tenant_event, {}, "payload", attributes: attributes)
  end

  def resolver_calls
    FilteredSubscriptionSchema.resolver_calls
  end

  before do
    FilteredSubscriptionSchema.reset_counts!
    subscriptions.reset!
  end

  it "only executes subscriptions whose equality filter matches the event" do
    tenant_1 = subscribe("tenant-1", GraphQL::Subscriptions::Filter.eq(:tenant_id, 1))
    tenant_2 = subscribe("tenant-2", GraphQL::Subscriptions::Filter.eq(:tenant_id, 2))
    unfiltered = subscribe("unfiltered", nil)

    trigger(tenant_id: 1)

    assert_equal 1, resolver_calls["tenant-1"]
    assert_equal 1, resolver_calls["unfiltered"]
    assert_equal 0, resolver_calls["tenant-2"], "expected the unrelated subscription's resolver not to run"
    assert_equal 1, subscriptions.deliveries[tenant_1].size
    assert_equal 1, subscriptions.deliveries[unfiltered].size
    assert_equal 0, subscriptions.deliveries[tenant_2].size

    trigger(tenant_id: 2)
    assert_equal 1, resolver_calls["tenant-1"]
    assert_equal 1, resolver_calls["tenant-2"]
    assert_equal 2, resolver_calls["unfiltered"]
  end

  it "narrows candidates with set membership filters" do
    matching = subscribe("regions", GraphQL::Subscriptions::Filter.in(:region, ["us", "ca"]))
    other = subscribe("other-region", GraphQL::Subscriptions::Filter.in(:region, ["eu"]))

    trigger(region: "us")
    assert_equal 1, resolver_calls["regions"]
    assert_equal 0, resolver_calls["other-region"]

    trigger(region: "eu")
    assert_equal 1, resolver_calls["regions"]
    assert_equal 1, resolver_calls["other-region"]
    assert_equal 1, subscriptions.deliveries[matching].size
    assert_equal 1, subscriptions.deliveries[other].size
  end

  it "narrows candidates with numeric range filters" do
    low = subscribe("low-score", GraphQL::Subscriptions::Filter.range(:score, 0...50))
    high = subscribe("high-score", GraphQL::Subscriptions::Filter.range(:score, 50..100))

    trigger(score: 25)
    assert_equal 1, resolver_calls["low-score"]
    assert_equal 0, resolver_calls["high-score"]

    trigger(score: 50)
    assert_equal 1, resolver_calls["low-score"]
    assert_equal 1, resolver_calls["high-score"]

    trigger(score: 500)
    assert_equal 1, resolver_calls["low-score"]
    assert_equal 1, resolver_calls["high-score"]
    assert_equal 1, subscriptions.deliveries[low].size
    assert_equal 1, subscriptions.deliveries[high].size
  end

  it "supports AND/OR combinations without missing matches" do
    and_sub = subscribe("and", GraphQL::Subscriptions::Filter.eq(:tenant_id, 1) & GraphQL::Subscriptions::Filter.range(:score, 0..100))
    or_sub = subscribe("or", GraphQL::Subscriptions::Filter.eq(:tenant_id, 2) | GraphQL::Subscriptions::Filter.eq(:region, "us"))

    # Only one side of the AND holds:
    trigger(tenant_id: 1, score: 500)
    assert_equal 0, resolver_calls["and"]
    # Both sides hold:
    trigger(tenant_id: 1, score: 50)
    assert_equal 1, resolver_calls["and"]
    # OR matches on either branch:
    trigger(tenant_id: 2)
    trigger(region: "us")
    assert_equal 2, resolver_calls["or"]
    trigger(tenant_id: 3, region: "eu")
    assert_equal 2, resolver_calls["or"]
    assert_equal 1, subscriptions.deliveries[and_sub].size
    assert_equal 2, subscriptions.deliveries[or_sub].size
  end

  it "conservatively runs unknown conditions but still applies their predicate" do
    custom = subscribe("custom", GraphQL::Subscriptions::Filter.custom { |attrs| attrs[:score].is_a?(Integer) && attrs[:score].even? })
    mixed = subscribe("mixed", GraphQL::Subscriptions::Filter.eq(:tenant_id, 1) | GraphQL::Subscriptions::Filter.custom { |attrs| attrs[:lucky] })

    trigger(score: 3)
    assert_equal 0, resolver_calls["custom"]
    trigger(score: 4)
    assert_equal 1, resolver_calls["custom"]

    # The unknown OR-branch makes the filter a candidate for every event,
    # but the full predicate decides:
    trigger(tenant_id: 99)
    assert_equal 0, resolver_calls["mixed"]
    trigger(lucky: true)
    assert_equal 1, resolver_calls["mixed"]
    trigger(tenant_id: 1)
    assert_equal 2, resolver_calls["mixed"]
    assert_equal 1, subscriptions.deliveries[custom].size
    assert_equal 2, subscriptions.deliveries[mixed].size
  end

  it "keeps the index in sync when filters are updated" do
    sub_id = subscribe("moving", GraphQL::Subscriptions::Filter.eq(:tenant_id, 1))

    trigger(tenant_id: 1)
    assert_equal 1, resolver_calls["moving"]

    assert subscriptions.update_subscription_filter(sub_id, GraphQL::Subscriptions::Filter.eq(:tenant_id, 2))
    trigger(tenant_id: 1)
    assert_equal 1, resolver_calls["moving"], "expected no execution after the filter moved to tenant 2"
    trigger(tenant_id: 2)
    assert_equal 2, resolver_calls["moving"]

    assert subscriptions.update_subscription_filter(sub_id, nil)
    trigger(tenant_id: 99)
    assert_equal 3, resolver_calls["moving"]
    refute subscriptions.update_subscription_filter("nope", nil)
  end

  it "removes subscriptions from the index when they're deleted" do
    sub_id = subscribe("short-lived", GraphQL::Subscriptions::Filter.eq(:tenant_id, 1))
    topic = subscriptions.instance_variable_get(:@topics).keys.first
    topic_index = subscriptions.index_for(topic)
    assert topic_index

    subscriptions.delete_subscription(sub_id)
    trigger(tenant_id: 1)
    assert_equal 0, resolver_calls["short-lived"]
    assert_equal 0, subscriptions.deliveries[sub_id].size
    assert topic_index.empty?, "expected the topic index to be cleaned up"
  end

  it "removes subscriptions from the index when they unsubscribe during an update" do
    sub_id = subscribe("unsubscriber", GraphQL::Subscriptions::Filter.eq(:tenant_id, 1), unsubscribe: true)

    trigger(tenant_id: 1)
    assert_equal 1, resolver_calls["unsubscriber"]
    trigger(tenant_id: 1)
    assert_equal 1, resolver_calls["unsubscriber"], "expected the unsubscribed subscription to be gone"
    assert_equal 0, subscriptions.deliveries[sub_id].size
  end
end
