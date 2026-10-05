# frozen_string_literal: true
require 'test/unit'
require 'resolv'

class TestSRVSelector < Test::Unit::TestCase
  # A randomness source replaying a fixed sequence of draws. It records
  # every bound it is asked for so tests can assert exactly when
  # randomness is consumed.
  class FixedRandom
    attr_reader :bounds

    def initialize(draws)
      @draws = draws
      @bounds = []
    end

    def call(bound)
      @bounds << bound
      @draws.shift or raise "unexpected draw for bound #{bound}"
    end

    def empty?
      @draws.empty?
    end
  end

  def srv(priority, weight, port, target)
    Resolv::DNS::Resource::IN::SRV.new(priority, weight, port, target)
  end

  def targets(selector)
    selector.map {|candidate| candidate.target.to_s }
  end

  def test_lower_priority_first_regardless_of_weight
    records = [
      srv(10, 100, 8080, 'high-priority-weight.example'),
      srv(5, 1, 8081, 'low-priority.example'),
    ]
    random = FixedRandom.new([])
    selector = Resolv::SRVSelector.new(records, random: random)

    assert_equal(['low-priority.example', 'high-priority-weight.example'], targets(selector))
    assert_empty(random.bounds)
  end

  def test_weighted_selection_without_replacement
    records = [
      srv(0, 1, 80, 'a.example'),
      srv(0, 2, 80, 'b.example'),
      srv(0, 3, 80, 'c.example'),
    ]
    # total 6: draw 6 hits c (running sums 1, 3, 6); then total 3 over
    # a, b: draw 2 hits b (running sums 1, 3); a remains last.
    random = FixedRandom.new([6, 2])
    selector = Resolv::SRVSelector.new(records, random: random)

    assert_equal(%w[c.example b.example a.example], targets(selector))
    assert_equal([7, 4], random.bounds)
    assert_predicate(random, :empty?)
  end

  def test_draw_at_running_sum_boundary_selects_that_record
    records = [
      srv(0, 2, 80, 'a.example'),
      srv(0, 3, 80, 'b.example'),
    ]
    # Running sums are 2 and 5: draw 2 selects a, draw 3 selects b.
    assert_equal(%w[a.example b.example],
                 targets(Resolv::SRVSelector.new(records, random: FixedRandom.new([2]))))
    assert_equal(%w[b.example a.example],
                 targets(Resolv::SRVSelector.new(records, random: FixedRandom.new([3]))))
  end

  def test_draw_equal_to_total_selects_last_record
    records = [
      srv(0, 2, 80, 'a.example'),
      srv(0, 3, 80, 'b.example'),
    ]
    assert_equal(%w[b.example a.example],
                 targets(Resolv::SRVSelector.new(records, random: FixedRandom.new([5]))))
  end

  def test_zero_weight_selected_only_on_zero_draw
    records = [
      srv(0, 1, 80, 'a.example'),
      srv(0, 0, 80, 'z.example'),
    ]
    # Weight-0 records are placed first in the running-sum order, so
    # only a draw of exactly 0 picks z first.
    assert_equal(%w[z.example a.example],
                 targets(Resolv::SRVSelector.new(records, random: FixedRandom.new([0]))))
    assert_equal(%w[a.example z.example],
                 targets(Resolv::SRVSelector.new(records, random: FixedRandom.new([1]))))
  end

  def test_all_zero_weights_keep_input_order_without_draws
    records = [
      srv(0, 0, 80, 'a.example'),
      srv(0, 0, 80, 'b.example'),
      srv(0, 0, 80, 'c.example'),
    ]
    random = FixedRandom.new([])
    selector = Resolv::SRVSelector.new(records, random: random)

    assert_equal(%w[a.example b.example c.example], targets(selector))
    assert_empty(random.bounds)
  end

  def test_single_remaining_record_consumes_no_draw
    records = [srv(0, 5, 80, 'a.example')]
    random = FixedRandom.new([])

    assert_equal(%w[a.example], targets(Resolv::SRVSelector.new(records, random: random)))
    assert_empty(random.bounds)
  end

  def test_root_target_is_dropped
    records = [
      srv(0, 0, 80, '.'),
      srv(0, 0, 80, 'a.example'),
      srv(1, 0, 80, '.'),
    ]
    assert_equal(%w[a.example], targets(Resolv::SRVSelector.new(records, random: FixedRandom.new([]))))
  end

  def test_weights_apply_per_priority_level
    records = [
      srv(0, 1, 80, 'a.example'),
      srv(0, 1, 80, 'b.example'),
      srv(1, 1, 80, 'c.example'),
      srv(1, 1, 80, 'd.example'),
    ]
    # Priority 0 draws first (bound 3, draw 2 -> b), then priority 1
    # (bound 3, draw 1 -> c).
    random = FixedRandom.new([2, 1])
    selector = Resolv::SRVSelector.new(records, random: random)

    assert_equal(%w[b.example a.example c.example d.example], targets(selector))
    assert_equal([3, 3], random.bounds)
  end

  def test_candidate_keeps_port_and_source_record
    record = srv(3, 7, 8443, 'a.example')
    candidate = Resolv::SRVSelector.new([record], random: FixedRandom.new([])).first

    assert_same(record, candidate.record)
    assert_equal(3, candidate.priority)
    assert_equal(7, candidate.weight)
    assert_equal(8443, candidate.port)
    assert_equal(Resolv::DNS::Name.create('a.example'), candidate.target)
  end

  def test_each_returns_enumerator_without_block
    records = [srv(0, 0, 80, 'a.example'), srv(0, 0, 80, 'b.example')]
    enum = Resolv::SRVSelector.new(records, random: FixedRandom.new([])).each

    assert_kind_of(Enumerator, enum)
    assert_equal(%w[a.example b.example], enum.map {|candidate| candidate.target.to_s })
  end

  def test_random_object_is_accepted
    records = [
      srv(0, 1, 80, 'a.example'),
      srv(0, 2, 80, 'b.example'),
      srv(0, 3, 80, 'c.example'),
    ]
    result = targets(Resolv::SRVSelector.new(records, random: Random.new(42)))

    assert_equal(%w[a.example b.example c.example].sort, result.sort)
  end

  def test_out_of_range_draw_raises
    records = [
      srv(0, 1, 80, 'a.example'),
      srv(0, 1, 80, 'b.example'),
    ]
    selector = Resolv::SRVSelector.new(records, random: FixedRandom.new([3]))

    assert_raise(ArgumentError) { selector.to_a }
  end

  def test_each_resolution_yields_addresses
    records = [
      srv(0, 0, 389, 'a.example'),
      srv(0, 0, 389, 'b.example'),
    ]
    resolver = ->(target) { ["10.0.0.#{target.to_s == 'a.example' ? 1 : 2}"] }
    resolutions = Resolv::SRVSelector.new(records, random: FixedRandom.new([]))
                                     .each_resolution(resolver).to_a

    assert_equal(%w[a.example b.example],
                 resolutions.map {|resolution| resolution.candidate.target.to_s })
    assert_equal([['10.0.0.1'], ['10.0.0.2']], resolutions.map(&:addresses))
    assert(resolutions.all? {|resolution| resolution.success? })
    assert_equal([389, 389], resolutions.map {|resolution| resolution.candidate.port })
  end

  def test_each_resolution_distinguishes_failed_targets
    records = [
      srv(0, 0, 389, 'down.example'),
      srv(0, 0, 389, 'up.example'),
    ]
    resolver = ->(target) do
      raise Resolv::ResolvError, "unreachable" if target.to_s == 'down.example'
      ['10.0.0.9']
    end
    resolutions = Resolv::SRVSelector.new(records, random: FixedRandom.new([]))
                                     .each_resolution(resolver).to_a

    failed, reachable = resolutions
    assert_not_predicate(failed, :success?)
    assert_kind_of(Resolv::ResolvError, failed.error)
    assert_nil(failed.addresses)
    assert_equal('down.example', failed.candidate.target.to_s)

    assert_predicate(reachable, :success?)
    assert_nil(reachable.error)
    assert_equal(['10.0.0.9'], reachable.addresses)
  end
end
