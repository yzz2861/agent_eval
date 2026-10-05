# frozen_string_literal: false
require 'test/unit'
require 'resolv'

class TestSRVSelector < Test::Unit::TestCase
  SRV = Resolv::DNS::Resource::IN::SRV

  # Random source replaying a fixed sequence of values.  Records the
  # limit of every call so tests can assert the exact sampling
  # boundaries instead of relying on probabilities.
  class FixedRandom
    attr_reader :limits

    def initialize(values)
      @values = values.dup
      @limits = []
    end

    def rand(limit)
      @limits << limit
      @values.shift or raise "fixed random sequence exhausted (limit #{limit})"
    end
  end

  def srv(priority, weight, port, target)
    SRV.new(priority, weight, port, target)
  end

  def selector(records, values)
    random = FixedRandom.new(values)
    return Resolv::SRVSelector.new(records, random: random), random
  end

  def test_lower_priority_comes_first_regardless_of_weight
    records = [srv(20, 100, 1, "high.example"), srv(10, 1, 2, "low.example")]
    sel, random = selector(records, [])
    assert_equal(%w[low.example high.example], sel.candidates.map(&:target))
    assert_equal([], random.limits)
  end

  def test_weighted_pick_uses_cumulative_boundaries
    records = [srv(0, 10, 1, "a.example"),
               srv(0, 20, 2, "b.example"),
               srv(0, 30, 3, "c.example")]
    # pick 0 lands in a's range [0, 10); pick 19 lands in b's range [0, 20)
    # of the remaining total 50; c is then the only record left.
    sel, random = selector(records, [0, 19])
    assert_equal(%w[a.example b.example c.example], sel.candidates.map(&:target))
    assert_equal([60, 50], random.limits)
  end

  def test_pick_equal_to_cumulative_weight_selects_next_record
    records = [srv(0, 10, 1, "a.example"), srv(0, 20, 2, "b.example")]
    sel, random = selector(records, [10])
    assert_equal(%w[b.example a.example], sel.candidates.map(&:target))
    assert_equal([30], random.limits)
  end

  def test_last_pick_of_range_selects_last_record
    records = [srv(0, 10, 1, "a.example"), srv(0, 20, 2, "b.example")]
    sel, = selector(records, [29])
    assert_equal(%w[b.example a.example], sel.candidates.map(&:target))
  end

  def test_zero_weight_waits_for_positive_weights
    records = [srv(0, 0, 1, "idle.example"), srv(0, 5, 2, "busy.example")]
    # total is 5, so only busy.example is eligible; the remaining
    # zero-weight record is taken last without drawing a number.
    sel, random = selector(records, [0])
    assert_equal(%w[busy.example idle.example], sel.candidates.map(&:target))
    assert_equal([5], random.limits)
  end

  def test_all_zero_weights_select_uniformly
    records = [srv(0, 0, 1, "a.example"),
               srv(0, 0, 2, "b.example"),
               srv(0, 0, 3, "c.example")]
    sel, random = selector(records, [2, 0])
    assert_equal(%w[c.example a.example b.example], sel.candidates.map(&:target))
    assert_equal([3, 2], random.limits)
  end

  def test_root_target_is_never_a_candidate
    records = [srv(0, 10, 1, "."), srv(0, 1, 2, "real.example")]
    sel, random = selector(records, [])
    assert_equal(%w[real.example], sel.candidates.map(&:target))
    assert_equal([], random.limits)
  end

  def test_candidate_keeps_port_and_record
    record = srv(0, 1, 8080, "svc.example")
    sel, = selector([record], [])
    candidate = sel.candidates.first
    assert_equal(8080, candidate.port)
    assert_same(record, candidate.record)
    assert_equal("svc.example", candidate.target)
  end

  def test_each_candidate_returns_enumerator_without_block
    sel, = selector([srv(0, 1, 1, "a.example")], [])
    assert_kind_of(Enumerator, sel.each_candidate)
  end

  def test_default_random_source
    records = [srv(0, 1, 1, "a.example"), srv(0, 1, 2, "b.example")]
    targets = Resolv::SRVSelector.new(records).candidates.map(&:target)
    assert_equal(%w[a.example b.example], targets.sort)
  end

  def test_each_result_resolves_through_callback
    records = [srv(0, 1, 80, "a.example"), srv(1, 1, 81, "b.example")]
    sel, = selector(records, [])
    resolver = ->(target) { ["10.0.0.1"] }
    results = sel.each_result(resolver).to_a
    assert_equal([80, 81], results.map(&:port))
    assert_equal([true, true], results.map(&:success?))
    assert_equal([["10.0.0.1"], ["10.0.0.1"]], results.map(&:addresses))
  end

  def test_each_result_captures_failure_per_target_and_continues
    records = [srv(0, 1, 80, "bad.example"), srv(1, 1, 81, "good.example")]
    sel, = selector(records, [])
    error = Resolv::ResolvError.new("no address for bad.example")
    resolver = ->(target) { target == "bad.example" ? raise(error) : ["10.0.0.2"] }
    results = sel.each_result(resolver).to_a
    assert_equal([false, true], results.map(&:success?))
    assert_same(error, results[0].error)
    assert_equal("bad.example", results[0].target)
    assert_equal([], results[0].addresses)
    assert_equal(["10.0.0.2"], results[1].addresses)
    assert_nil(results[1].error)
  end

  def test_each_result_returns_enumerator_without_block
    sel, = selector([], [])
    assert_kind_of(Enumerator, sel.each_result(->(_target) { [] }))
  end

  def test_sampling_without_replacement_visits_each_record_once
    records = (0...4).map {|i| srv(0, 10, i, "h#{i}.example") }
    sel, random = selector(records, [39, 20, 0])
    assert_equal(%w[h3.example h2.example h0.example h1.example],
                 sel.candidates.map(&:target))
    assert_equal([40, 30, 20], random.limits)
  end
end
