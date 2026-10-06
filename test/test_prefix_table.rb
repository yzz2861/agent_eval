# frozen_string_literal: true
require 'test/unit'
require 'ipaddr/prefix_table'

class TC_PrefixTable < Test::Unit::TestCase
  def setup
    @table = IPAddr::PrefixTable.new
  end

  def test_longest_prefix_match
    @table.add("10.0.0.0/8", :net8)
    @table.add("10.1.0.0/16", :net16)
    @table.add("10.1.2.0/24", :net24)

    assert_equal(:net24, @table.lookup("10.1.2.9").data)
    assert_equal(:net16, @table.lookup("10.1.3.9").data)
    assert_equal(:net8, @table.lookup("10.2.3.4").data)
    assert_nil(@table.lookup("11.0.0.1"))
  end

  def test_match_exposes_prefix_and_rule_identity
    id = @table.add("192.168.0.0/16", :lan, priority: 3)
    match = @table.lookup("192.168.1.10")

    assert_equal(id, match.rule_id)
    assert_equal(IPAddr.new("192.168.0.0/16"), match.prefix)
    assert_equal(3, match.priority)
    assert_equal(:lan, match.data)
    assert_equal(:lan, @table.rule(match.rule_id).data)
  end

  def test_priority_within_same_prefix
    low = @table.add("10.0.0.0/8", :low, priority: 1)
    high = @table.add("10.0.0.0/8", :high, priority: 10)

    assert_equal(:high, @table.lookup("10.9.9.9").data)
    @table.delete(high)
    assert_equal(:low, @table.lookup("10.9.9.9").data)
  end

  def test_same_priority_duplicates_are_stable
    first = @table.add("10.0.0.0/8", :first)
    second = @table.add("10.0.0.0/8", :second)

    3.times { assert_equal(:first, @table.lookup("10.1.1.1").data) }

    @table.delete(first)
    assert_equal(:second, @table.lookup("10.1.1.1").data)

    @table.add("10.0.0.0/8", :third)
    assert_equal(:second, @table.lookup("10.1.1.1").data)
    @table.delete(second)
    assert_equal(:third, @table.lookup("10.1.1.1").data)
  end

  def test_delete_falls_back_to_ancestor
    a = @table.add("10.0.0.0/8", :net8)
    b = @table.add("10.1.0.0/16", :net16)
    c = @table.add("10.1.2.0/24", :net24)

    assert_equal(:net24, @table.lookup("10.1.2.9").data)
    @table.delete(c)
    assert_equal(:net16, @table.lookup("10.1.2.9").data)
    @table.delete(b)
    assert_equal(:net8, @table.lookup("10.1.2.9").data)
    @table.delete(a)
    assert_nil(@table.lookup("10.1.2.9"))
    assert_nil(@table.delete(a))
  end

  def test_delete_readd_uses_fresh_state
    id = @table.add("10.1.2.0/24", :old)
    @table.add("10.0.0.0/8", :ancestor)
    @table.delete(id)
    @table.add("10.1.2.0/24", :new)
    assert_equal(:new, @table.lookup("10.1.2.9").data)
  end

  def test_default_routes_are_family_independent
    v4_default = @table.add("0.0.0.0/0", :v4_default)

    assert_equal(:v4_default, @table.lookup("203.0.113.7").data)
    assert_nil(@table.lookup("2001:db8::1"))

    v6_default = @table.add("::/0", :v6_default)
    assert_equal(:v6_default, @table.lookup("2001:db8::1").data)
    assert_equal(:v4_default, @table.lookup("203.0.113.7").data)

    @table.delete(v4_default)
    assert_nil(@table.lookup("203.0.113.7"))
    assert_equal(:v6_default, @table.lookup("2001:db8::1").data)
    @table.delete(v6_default)
    assert(@table.empty?)
  end

  def test_ipv6_longest_prefix
    @table.add("2001:db8::/32", :doc)
    @table.add("2001:db8:abcd::/48", :site)

    assert_equal(:site, @table.lookup("2001:db8:abcd:1::5").data)
    assert_equal(:doc, @table.lookup("2001:db8:ffff::5").data)
  end

  def test_host_bits_on_prefix_are_masked
    @table.add("10.1.2.3/8", :masked)
    match = @table.lookup("10.9.9.9")
    assert_equal(:masked, match.data)
    assert_equal(IPAddr.new("10.0.0.0/8"), match.prefix)
  end

  def test_random_table_matches_naive_scan
    rng = Random.new(20261007)
    rules = []

    300.times do |i|
      if rng.rand < 0.5
        plen = rng.rand(0..32)
        net = IPAddr.new(rng.rand(0..0xffffffff), Socket::AF_INET).mask(plen)
      else
        plen = rng.rand(0..128)
        net = IPAddr.new(rng.rand(0..(1 << 128) - 1), Socket::AF_INET6).mask(plen)
      end
      priority = rng.rand(0..3)
      id = @table.add(net, i, priority: priority)
      rules << @table.rule(id)
    end

    1000.times do
      if rng.rand < 0.5
        addr = IPAddr.new(rng.rand(0..0xffffffff), Socket::AF_INET)
      else
        addr = IPAddr.new(rng.rand(0..(1 << 128) - 1), Socket::AF_INET6)
      end

      expected = naive_lookup(rules, addr)
      actual = @table.lookup(addr)
      if expected.nil?
        assert_nil(actual, "expected no match for #{addr}")
      else
        assert_not_nil(actual, "expected a match for #{addr}")
        assert_equal(expected.id, actual.rule_id, "rule mismatch for #{addr}")
      end
    end
  end

  def test_random_table_with_deletions_matches_naive_scan
    rng = Random.new(42)
    ids = []

    200.times do |i|
      plen = rng.rand(0..32)
      net = IPAddr.new(rng.rand(0..0xffffffff), Socket::AF_INET).mask(plen)
      ids << @table.add(net, i, priority: rng.rand(0..2))
    end

    ids.sample(100, random: rng).each { |id| @table.delete(id) }
    remaining = ids.filter_map { |id| @table.rule(id) }

    500.times do
      addr = IPAddr.new(rng.rand(0..0xffffffff), Socket::AF_INET)
      expected = naive_lookup(remaining, addr)
      actual = @table.lookup(addr)
      assert_equal(expected&.id, actual&.rule_id, "mismatch for #{addr}")
    end
  end

  def test_lookup_visits_bounded_nodes
    rng = Random.new(7)
    5000.times do |i|
      plen = rng.rand(8..32)
      net = IPAddr.new(rng.rand(0..0xffffffff), Socket::AF_INET).mask(plen)
      @table.add(net, i)
    end

    match = @table.lookup(IPAddr.new(rng.rand(0..0xffffffff), Socket::AF_INET))
    assert_operator(@table.last_nodes_visited, :<=, 33)
    assert_operator(match.nodes_visited, :<=, 33)
    assert_operator(match.nodes_visited, :<<, @table.size)
  end

  private

  # Reference semantics: longest prefix wins, then highest priority,
  # then earliest declaration (lowest seq).
  def naive_lookup(rules, addr)
    family = addr.ipv4? ? Socket::AF_INET : Socket::AF_INET6
    rules
      .select { |rule| (rule.prefix.ipv4? ? Socket::AF_INET : Socket::AF_INET6) == family }
      .select { |rule| rule.prefix.include?(addr) }
      .max_by { |rule| [rule.prefix.prefix, rule.priority, -rule.seq] }
  end
end
