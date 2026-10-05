# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Subscriptions::Filter do

  describe "attribute equality" do
    it "matches only the exact value" do
      filter = GraphQL::Subscriptions::Filter.eq(:tenant_id, 1)
      assert filter.matches?({ tenant_id: 1 })
      refute filter.matches?({ tenant_id: 2 })
      refute filter.matches?({})
    end
  end

  describe "set membership" do
    it "matches any value in the set" do
      filter = GraphQL::Subscriptions::Filter.in(:region, ["us", "ca"])
      assert filter.matches?({ region: "us" })
      assert filter.matches?({ region: "ca" })
      refute filter.matches?({ region: "eu" })
      refute filter.matches?({})
    end
  end

  describe "numeric ranges" do
    it "matches values inside the range" do
      filter = GraphQL::Subscriptions::Filter.range(:score, 10..20)
      assert filter.matches?({ score: 10 })
      assert filter.matches?({ score: 15 })
      assert filter.matches?({ score: 20 })
      refute filter.matches?({ score: 9 })
      refute filter.matches?({ score: 21 })
      refute filter.matches?({})
    end

    it "honors exclusive ends" do
      filter = GraphQL::Subscriptions::Filter.range(:score, 10...20)
      assert filter.matches?({ score: 10 })
      refute filter.matches?({ score: 20 })
    end

    it "supports beginless and endless ranges" do
      assert GraphQL::Subscriptions::Filter.range(:score, ..20).matches?({ score: -100 })
      refute GraphQL::Subscriptions::Filter.range(:score, ..20).matches?({ score: 21 })
      assert GraphQL::Subscriptions::Filter.range(:score, 10..).matches?({ score: 1_000 })
      refute GraphQL::Subscriptions::Filter.range(:score, 10..).matches?({ score: 9 })
    end

    it "doesn't match non-comparable values" do
      filter = GraphQL::Subscriptions::Filter.range(:score, 10..20)
      refute filter.matches?({ score: "lots" })
    end
  end

  describe "AND/OR combinations" do
    it "matches AND when all branches match" do
      filter = GraphQL::Subscriptions::Filter.and(GraphQL::Subscriptions::Filter.eq(:tenant_id, 1), GraphQL::Subscriptions::Filter.range(:score, 10..20))
      assert filter.matches?({ tenant_id: 1, score: 15 })
      refute filter.matches?({ tenant_id: 1, score: 30 })
      refute filter.matches?({ tenant_id: 2, score: 15 })
    end

    it "matches OR when any branch matches" do
      filter = GraphQL::Subscriptions::Filter.or(GraphQL::Subscriptions::Filter.eq(:tenant_id, 1), GraphQL::Subscriptions::Filter.in(:region, ["us"]))
      assert filter.matches?({ tenant_id: 1 })
      assert filter.matches?({ region: "us" })
      refute filter.matches?({ tenant_id: 2, region: "eu" })
    end

    it "supports & and | operators and nesting" do
      filter = GraphQL::Subscriptions::Filter.eq(:tenant_id, 1) & (GraphQL::Subscriptions::Filter.eq(:kind, "a") | GraphQL::Subscriptions::Filter.eq(:kind, "b"))
      assert filter.matches?({ tenant_id: 1, kind: "b" })
      refute filter.matches?({ tenant_id: 1, kind: "c" })
      refute filter.matches?({ tenant_id: 2, kind: "a" })
    end
  end

  describe "custom conditions" do
    it "delegates to the block and is not indexable" do
      filter = GraphQL::Subscriptions::Filter.custom { |attrs| attrs[:score].to_i.even? }
      assert filter.matches?({ score: 2 })
      refute filter.matches?({ score: 3 })
      assert_nil filter.index_plan
    end
  end
end

describe GraphQL::Subscriptions::FilterIndex do

  def build_filters
    {
      "eq" => GraphQL::Subscriptions::Filter.eq(:tenant_id, 1),
      "in" => GraphQL::Subscriptions::Filter.in(:tenant_id, [2, 3]),
      "range" => GraphQL::Subscriptions::Filter.range(:score, 10..20),
      "and" => GraphQL::Subscriptions::Filter.and(GraphQL::Subscriptions::Filter.eq(:tenant_id, 4), GraphQL::Subscriptions::Filter.range(:score, 0..100)),
      "or" => GraphQL::Subscriptions::Filter.or(GraphQL::Subscriptions::Filter.eq(:tenant_id, 5), GraphQL::Subscriptions::Filter.eq(:region, "us")),
      "or-with-unknown" => GraphQL::Subscriptions::Filter.or(GraphQL::Subscriptions::Filter.eq(:tenant_id, 6), GraphQL::Subscriptions::Filter.custom { |a| a[:lucky] }),
      "and-with-unknown" => GraphQL::Subscriptions::Filter.and(GraphQL::Subscriptions::Filter.eq(:tenant_id, 7), GraphQL::Subscriptions::Filter.custom { |a| a[:vip] }),
      "custom" => GraphQL::Subscriptions::Filter.custom { |a| a[:score].to_i > 1_000 },
      "none" => nil,
    }
  end

  def build_index(filters)
    index = GraphQL::Subscriptions::FilterIndex.new
    filters.each { |id, filter| index.add(id, filter) }
    index
  end

  it "returns exactly the subscriptions whose full predicate matches" do
    filters = build_filters
    index = build_index(filters)
    events = [
      {},
      { tenant_id: 1 },
      { tenant_id: 2 },
      { tenant_id: 3 },
      { tenant_id: 4, score: 50 },
      { tenant_id: 4, score: 500 },
      { tenant_id: 5 },
      { tenant_id: 6 },
      { tenant_id: 7, vip: true },
      { tenant_id: 7 },
      { tenant_id: 99, score: 15 },
      { region: "us" },
      { score: 1_500 },
      { lucky: true },
    ]
    events.each do |attrs|
      expected = filters.keys.select { |id| filters[id].nil? || filters[id].matches?(attrs) }.sort
      assert_equal expected, index.matching_subscription_ids(attrs).sort,
        "expected the index to match the brute-force predicate results for #{attrs.inspect}"
    end
  end

  it "uses the index to skip examining unrelated subscriptions" do
    filters = build_filters
    index = build_index(filters)
    # No filter is registered for :unrelated_attr, so nothing can match:
    assert_equal ["none"], index.matching_subscription_ids({ unrelated_attr: 1 }).sort
    # A fully-indexed subscription is only a candidate when its constraint hits:
    assert_equal ["eq", "none"], index.matching_subscription_ids({ tenant_id: 1 }).sort
  end

  it "keeps the index in sync when subscriptions are removed" do
    filters = build_filters
    index = build_index(filters)
    index.remove("eq")
    index.remove("custom")
    index.remove("none")
    assert_equal filters.size - 3, index.size
    assert_equal ["in"], index.matching_subscription_ids({ tenant_id: 2 })
    assert_equal [], index.matching_subscription_ids({ tenant_id: 1 })
    assert_equal [], index.matching_subscription_ids({ score: 1_500 })
    index.remove("in")
    index.remove("range")
    index.remove("and")
    index.remove("or")
    index.remove("or-with-unknown")
    index.remove("and-with-unknown")
    assert index.empty?
    assert_equal [], index.matching_subscription_ids({ tenant_id: 5, score: 15, region: "us", lucky: true })
  end

  it "re-indexes when a subscription's filter is replaced" do
    index = GraphQL::Subscriptions::FilterIndex.new
    index.add("sub", GraphQL::Subscriptions::Filter.eq(:tenant_id, 1))
    assert_equal ["sub"], index.matching_subscription_ids({ tenant_id: 1 })
    index.add("sub", GraphQL::Subscriptions::Filter.range(:score, 0..10))
    assert_equal [], index.matching_subscription_ids({ tenant_id: 1 })
    assert_equal ["sub"], index.matching_subscription_ids({ score: 5 })
    index.add("sub", nil)
    assert_equal ["sub"], index.matching_subscription_ids({})
    assert_equal 1, index.size
  end

  it "treats unknown filter-like objects as conservative fallbacks" do
    unknown = Object.new
    def unknown.matches?(attrs)
      attrs[:ok]
    end
    index = GraphQL::Subscriptions::FilterIndex.new
    index.add("unknown", unknown)
    assert_equal ["unknown"], index.matching_subscription_ids({ ok: true })
    assert_equal [], index.matching_subscription_ids({ ok: false })
    index.remove("unknown")
    assert index.empty?
  end
end
