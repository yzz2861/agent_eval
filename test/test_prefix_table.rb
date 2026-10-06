# frozen_string_literal: true
require 'test/unit'
require 'ipaddr'

class TC_PrefixTable < Test::Unit::TestCase
  def test_longest_prefix_priority_and_tie_order
    table = IPAddr::PrefixTable.new

    assert_nil(table.lookup("10.1.2.3"))

    table.add("0.0.0.0/0", :v4_default, "v4 default")
    table.add("::/0", :v6_default, "v6 default")
    table.add("10.0.0.0/8", :v4_8, "v4 /8")
    table.add("10.1.0.0/16", :v4_16, "v4 /16")
    table.add("10.1.2.0/24", :lower, "lower", priority: 5)
    table.add("10.1.2.0/24", :higher, "higher", priority: 10)
    table.add("10.1.2.3/32", :first, "first")
    table.add("10.1.2.3/32", :second, "second")

    match = table.lookup("10.1.2.3")
    assert_equal(:first, match.rule_id)
    assert_equal("10.1.2.3/32", match.prefix)
    assert_equal("first", match.data)

    match = table.lookup("10.1.2.4")
    assert_equal(:higher, match.rule_id)
    assert_equal("10.1.2.0/24", match.prefix)
    assert_equal(10, match.priority)

    assert_equal(:v4_default, table.lookup("192.0.2.1").rule_id)
    assert_equal(:v6_default, table.lookup("2001:db8::1").rule_id)

    table.delete(:higher)
    assert_equal(:lower, table.lookup("10.1.2.4").rule_id)

    table.delete(:lower)
    assert_equal(:v4_16, table.lookup("10.1.2.4").rule_id)

    table.delete(:v4_16)
    assert_equal(:v4_8, table.lookup("10.1.2.4").rule_id)

    table.delete(:v4_8)
    assert_equal(:v4_default, table.lookup("10.1.2.4").rule_id)

    assert_nil(table.delete(:v4_8))
  end

  def test_replacement_and_duplicate_id_validation
    table = IPAddr::PrefixTable.new
    table.add("2001:db8::/32", :site, "old", priority: 1)

    replaced = table.add("2001:db8::/32", :site, "new", priority: 9)
    assert_equal("new", replaced.data)
    assert_equal(9, replaced.priority)
    assert_equal(0, replaced.sequence)
    assert_equal("new", table.lookup("2001:db8::1").data)

    assert_raise(ArgumentError) do
      table.add("2001:db9::/32", :site, "other")
    end
    assert_raise(ArgumentError) do
      table.add("2001:db8::/32", :site, "bad", priority: "high")
    end
  end

  def test_canonical_prefix_and_visited_nodes
    table = IPAddr::PrefixTable.new
    table.add("0.0.0.0/0", :default)
    table.add("192.0.2.123/24", :network, :data)
    table.add("198.51.100.0/24", :other)

    match = table.lookup("192.0.2.9")
    assert_equal("192.0.2.0/24", match.prefix)
    assert_equal(:data, match.data)
    assert_equal(25, match.visited_nodes)
    assert_predicate(match, :frozen?)

    match = table.lookup("203.0.113.1")
    assert_equal(:default, match.rule_id)
    assert_operator(match.visited_nodes, :<, table.node_count)
  end

  def test_fixed_random_table_matches_naive_scan
    table = IPAddr::PrefixTable.new
    rules = []
    rng = Random.new(0x4d595df4d0f33173)

    table.add("0.0.0.0/0", :v4_default, "v4 default")
    table.add("::/0", :v6_default, "v6 default")
    rules << [IPAddr.new("0.0.0.0/0"), :v4_default, 0, 0]
    rules << [IPAddr.new("::/0"), :v6_default, 0, 1]

    160.times do |index|
      prefix = random_prefix(rng, Socket::AF_INET, 8 + rng.rand(25))
      id = "v4-#{index}".to_sym
      priority = rng.rand(4)
      table.add(prefix.cidr, id, index, priority: priority)
      rules << [prefix, id, priority, table.size - 1]
    end

    160.times do |index|
      prefix = random_prefix(rng, Socket::AF_INET6, 16 + rng.rand(113))
      id = "v6-#{index}".to_sym
      priority = rng.rand(4)
      table.add(prefix.cidr, id, index, priority: priority)
      rules << [prefix, id, priority, table.size - 1]
    end

    100.times do
      address = IPAddr.new(rng.rand(2**32), Socket::AF_INET)
      expected = naive_lookup(rules, address)
      actual = table.lookup(address)

      assert_equal(expected[1], actual.rule_id)
      assert_equal(expected[0].cidr, actual.prefix)
      assert_operator(actual.visited_nodes, :<=, 33)
      assert_operator(actual.visited_nodes, :<, 161)
      assert_operator(actual.visited_nodes, :<, table.node_count)
    end

    100.times do
      address = IPAddr.new(rng.rand(2**128), Socket::AF_INET6)
      expected = naive_lookup(rules, address)
      actual = table.lookup(address)

      assert_equal(expected[1], actual.rule_id)
      assert_equal(expected[0].cidr, actual.prefix)
      assert_operator(actual.visited_nodes, :<=, 129)
      assert_operator(actual.visited_nodes, :<, 161)
      assert_operator(actual.visited_nodes, :<, table.node_count)
    end
  end

  private

  def random_prefix(rng, family, length)
    size = family == Socket::AF_INET ? 2**32 : 2**128
    IPAddr.new(rng.rand(size), family).mask(length)
  end

  def naive_lookup(rules, address)
    candidates = rules.select { |prefix,| prefix.include?(address) }
    candidates.max_by do |prefix, _, priority, sequence|
      [prefix.prefix, priority, -sequence]
    end
  end
end
