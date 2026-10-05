# frozen_string_literal: true
require "spec_helper"

class SubscriptionsFilterSpec < Minitest::Test
  F = GraphQL::Subscriptions::Filter

  def test_equality
    filter = F.eq("tenant", "acme")
    assert filter.match?("tenant" => "acme")
    refute filter.match?("tenant" => "globex")
    refute filter.match?({})
    # Symbol keys are accepted too.
    assert filter.match?(tenant: "acme")
  end

  def test_membership
    filter = F.in("region", %w[us eu])
    assert filter.match?("region" => "us")
    assert filter.match?("region" => "eu")
    refute filter.match?("region" => "ap")
    refute filter.match?({})
  end

  def test_numeric_ranges
    filter = F.between("amount", min: 100, max: 500)
    assert filter.match?("amount" => 100)
    assert filter.match?("amount" => 500)
    assert filter.match?("amount" => 250)
    refute filter.match?("amount" => 99)
    refute filter.match?("amount" => 501)

    assert F.gt("amount", 10).match?("amount" => 11)
    refute F.gt("amount", 10).match?("amount" => 10)
    assert F.lte("amount", 10).match?("amount" => 10)
  end

  def test_range_with_non_numeric_event_value_is_not_a_match
    filter = F.gte("amount", 100)
    refute filter.match?("amount" => "lots")
    refute filter.match?({})
  end

  def test_and_or_composition
    filter = F.and(
      F.eq("tenant", "acme"),
      F.or(
        F.in("region", %w[us eu]),
        F.between("amount", min: 1000, max: 2000),
      ),
    )

    assert filter.match?("tenant" => "acme", "region" => "us", "amount" => 0)
    assert filter.match?("tenant" => "acme", "region" => "ap", "amount" => 1500)
    refute filter.match?("tenant" => "acme", "region" => "ap", "amount" => 0)
    refute filter.match?("tenant" => "globex", "region" => "us", "amount" => 0)
  end

  def test_unknown_is_conservative
    filter = F.unknown { |attrs| attrs["tenant"] == "acme" }
    assert filter.match?("tenant" => "acme")
    refute filter.match?("tenant" => "globex")
    assert_equal :unknown, filter.index_expr

    # A predicate that raises or returns nil is treated as a match (safe default).
    assert F.unknown { raise "boom" }.match?("tenant" => "x")
    assert F.unknown { nil }.match?("tenant" => "x")
    assert F.unknown.match?("tenant" => "x")
  end

  def test_non_numeric_bound_still_matches_but_is_not_indexed
    time = Time.new(2020)
    filter = F.gte("created_at", time)
    assert_equal :unknown, filter.index_expr
    assert filter.match?("created_at" => Time.new(2021))
    refute filter.match?("created_at" => Time.new(2019))
  end

  def test_build_from_plain_data
    filter = F.build(
      "and" => [
        { "field" => "tenant", "op" => "eq", "value" => "acme" },
        { "field" => "amount", "op" => "gte", "value" => 100 },
        { "or" => [
          { "field" => "region", "op" => "in", "value" => %w[us eu] },
          { "field" => "amount", "op" => "between", "value" => { "min" => 1000, "max" => 2000 } },
        ] },
      ],
    )
    assert filter.match?("tenant" => "acme", "amount" => 100, "region" => "us")
    refute filter.match?("tenant" => "globex", "amount" => 100, "region" => "us")
    refute filter.match?("tenant" => "acme", "amount" => 99, "region" => "ap")
  end

  def test_build_unknown_operator_falls_back
    filter = F.build("field" => "tenant", "op" => "regex", "value" => "ac.*")
    assert_kind_of F::Unknown, filter
    assert_equal :unknown, filter.index_expr
    assert filter.match?("tenant" => "anything")
  end

  def test_build_accepts_callable_and_node
    node = F.eq("tenant", "acme")
    assert_same node, F.build(node)
    assert_kind_of F::Unknown, F.build(->(attrs) { attrs["x"] })
    assert_kind_of F::Unknown, F.build(nil)
  end
end
