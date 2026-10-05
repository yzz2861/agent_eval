# frozen_string_literal: true
require "spec_helper"

class FilteredRegistrySpec < Minitest::Test
  F = GraphQL::Subscriptions::Filter

  class CountingResolver
    attr_reader :calls, :name

    def initialize(name, result: nil)
      @name = name
      @result = result
      @calls = 0
    end

    def call(attributes)
      @calls += 1
      @result || attributes
    end
  end

  def setup
    @backend = GraphQL::Subscriptions::InMemory.new(schema: Class.new(GraphQL::Schema))
    @resolvers = {}
  end

  # Register one subscription per filter; returns its resolver.
  def register(id, filter, event = "price_changed")
    resolver = CountingResolver.new(id)
    @resolvers[id] = resolver
    @backend.register(id, event, filter, resolver: resolver)
    resolver
  end

  def ids(entries)
    entries.map(&:id)
  end

  def trigger_and_ids(event, attributes)
    @backend.trigger_filtered(event, attributes)
    ids(@backend.matching(event, attributes))
  end

  def test_index_narrows_to_matching_tenant_and_resolvers_skip_irrelevant
    12.times do |i|
      tenant = (i % 4).to_s
      register("s#{i}", F.eq("tenant", tenant))
    end

    attributes = { "tenant" => "1" }
    candidates = ids(@backend.candidates_for("price_changed", attributes))

    # Only the three tenant-1 subscriptions are candidates; the other nine
    # subscriptions never reach their resolver.
    assert_equal %w[s1 s5 s9].sort, candidates.sort
    assert_equal 3, candidates.length

    @backend.trigger_filtered("price_changed", attributes)
    assert_equal 3, @backend.resolver_call_count
    @resolvers.each do |id, resolver|
      if %w[s1 s5 s9].include?(id)
        assert_equal 1, resolver.calls
      else
        assert_equal 0, resolver.calls, "#{id} should not have been executed"
      end
    end
  end

  def test_numeric_range_narrows_interval
    register("low", F.lt("amount", 100))
    register("mid", F.between("amount", min: 100, max: 500))
    register("high", F.gt("amount", 500))

    candidates = ids(@backend.candidates_for("price_changed", "amount" => 250))
    assert_equal ["mid"], candidates
    assert_equal 1, trigger_and_ids("price_changed", "amount" => 250).length

    candidates = ids(@backend.candidates_for("price_changed", "amount" => 100))
    assert_equal ["mid"], candidates

    candidates = ids(@backend.candidates_for("price_changed", "amount" => 500))
    assert_equal ["mid"], candidates

    candidates = ids(@backend.candidates_for("price_changed", "amount" => 501))
    assert_equal ["high"], candidates
  end

  def test_conjunction_requires_all_indexed_terms
    register("a", F.and(F.eq("tenant", "acme"), F.between("amount", min: 100, max: 500)))
    register("b", F.and(F.eq("tenant", "globex"), F.between("amount", min: 100, max: 500)))

    # Right tenant, out of range: not a candidate.
    assert_empty @backend.candidates_for("price_changed", "tenant" => "acme", "amount" => 99)
    # Right range, wrong tenant: not a candidate.
    assert_empty @backend.candidates_for("price_changed", "tenant" => "globex", "amount" => 99)

    candidates = ids(@backend.candidates_for("price_changed", "tenant" => "acme", "amount" => 250))
    assert_equal ["a"], candidates
  end

  def test_disjunction_uses_conservative_fallback_but_full_predicate_is_exact
    register("or", F.or(F.eq("tenant", "acme"), F.gt("amount", 1000)))
    register("plain", F.eq("tenant", "acme"))

    # The OR subscription is always a candidate (can't be narrowed here), ...
    candidates = ids(@backend.candidates_for("price_changed", "tenant" => "other", "amount" => 1))
    assert_includes candidates, "or"
    refute_includes candidates, "plain"

    # ... but the full predicate drops it on execution.
    assert_empty trigger_and_ids("price_changed", "tenant" => "other", "amount" => 1)

    assert_equal ["or"], trigger_and_ids("price_changed", "tenant" => "other", "amount" => 2000)
  end

  def test_unknown_condition_is_candidate_and_evaluated_by_predicate
    register("unknown", F.unknown { |attrs| attrs["tenant"] == "secret" })

    assert_includes ids(@backend.candidates_for("price_changed", "tenant" => "nope")), "unknown"
    assert_empty trigger_and_ids("price_changed", "tenant" => "nope")

    assert_equal ["unknown"], trigger_and_ids("price_changed", "tenant" => "secret")
  end

  def test_index_never_drops_a_true_match
    fields = %w[tenant region]

    # Build a varied set of filters covering every supported shape.
    filters = []
    %w[acme globex initech].each do |tenant|
      filters << F.eq("tenant", tenant)
      filters << F.and(F.eq("tenant", tenant), F.gte("amount", 100))
      filters << F.and(F.eq("tenant", tenant), F.in("region", %w[us eu]))
    end
    filters << F.in("region", %w[us ap])
    filters << F.between("amount", min: 0, max: 1000)
    filters << F.or(F.eq("tenant", "acme"), F.gt("amount", 5000))
    filters << F.unknown { |attrs| attrs["tenant"] == "mystery" }
    filters << F.build("field" => "tenant", "op" => "fuzzy", "value" => "x")

    filters.each_with_index { |filter, i| register("f#{i}", filter) }

    events = [
      { "tenant" => "acme", "region" => "us", "amount" => 200 },
      { "tenant" => "globex", "region" => "eu", "amount" => 50 },
      { "tenant" => "initech", "region" => "ap", "amount" => 9000 },
      { "tenant" => "mystery", "region" => "zz", "amount" => 1 },
      { "tenant" => "zzz", "region" => "zz", "amount" => 1 },
    ]

    events.each do |attributes|
      # Brute-force ground truth from the exact predicates.
      expected = filters.each_with_index.select { |filter, _| filter.match?(attributes) }.map { |_, i| "f#{i}" }

      candidates = ids(@backend.candidates_for("price_changed", attributes))
      actual = ids(@backend.matching("price_changed", attributes))

      # The full result must equal brute force exactly.
      assert_equal expected.sort, actual.sort, "attributes=#{attributes.inspect}"
      # Candidates must be a superset of the true matches (sound over-approximation).
      assert (expected - candidates).empty?,
        "index dropped true matches: #{(expected - candidates).inspect} for #{attributes.inspect}"
    end
  end

  def test_randomized_differential_against_brute_force
    srand(1234)
    tenants = %w[a b c]
    regions = %w[us eu ap]

    filters = Array.new(80) do
      parts = [
        F.eq("tenant", tenants.sample),
        F.in("region", regions.sample(2)),
        F.between("amount", min: rand(10) * 100, max: (rand(10) + 1) * 100),
        F.gt("amount", rand(1200)),
      ].sample(rand(1..3))
      conjunction = F.and(*parts)
      [true, false].sample ? conjunction : F.or(conjunction, F.eq("tenant", "special"))
    end
    filters << F.unknown { |attrs| attrs["region"] == "hidden" }

    filters.each_with_index { |filter, i| register("r#{i}", filter) }

    200.times do
      attributes = {
        "tenant" => (tenants + ["special", "none"]).sample,
        "region" => (regions + ["hidden"]).sample,
        "amount" => rand(1300),
      }

      expected = filters.each_with_index.select { |filter, _| filter.match?(attributes) }.map { |_, i| "r#{i}" }
      candidates = ids(@backend.candidates_for("price_changed", attributes))
      actual = ids(@backend.matching("price_changed", attributes))

      assert_equal expected.sort, actual.sort
      assert (expected - candidates).empty?, "index dropped matches for #{attributes.inspect}"
    end
  end

  def test_unregister_removes_index_entries
    register("a", F.and(F.eq("tenant", "acme"), F.gte("amount", 100)))
    register("b", F.eq("tenant", "acme"))

    @backend.delete_subscription("a")

    candidates = ids(@backend.candidates_for("price_changed", "tenant" => "acme", "amount" => 200))
    assert_equal ["b"], candidates
    assert_empty @backend.entries_for("a")
  end

  def test_update_rebuilds_index_synchronously
    register("a", F.eq("tenant", "acme"))
    assert_includes ids(@backend.candidates_for("price_changed", "tenant" => "acme")), "a"

    @backend.update_filter("a", F.eq("tenant", "globex"))

    refute_includes ids(@backend.candidates_for("price_changed", "tenant" => "acme")), "a"
    assert_includes ids(@backend.candidates_for("price_changed", "tenant" => "globex")), "a"
  end

  def test_events_are_partitioned
    register("a", F.eq("tenant", "acme"), "event_one")
    register("b", F.eq("tenant", "acme"), "event_two")

    assert_equal ["a"], ids(@backend.candidates_for("event_one", "tenant" => "acme"))
    assert_equal ["b"], ids(@backend.candidates_for("event_two", "tenant" => "acme"))
    assert_empty @backend.candidates_for("event_three", "tenant" => "acme")
  end

  def test_nil_filter_matches_every_event
    register("a", nil)
    register("b", F.eq("tenant", "acme"))

    assert_includes ids(@backend.candidates_for("price_changed", "tenant" => "other")), "a"
    refute_includes ids(@backend.candidates_for("price_changed", "tenant" => "other")), "b"
  end
end
