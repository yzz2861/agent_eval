# frozen_string_literal: true
require 'test/unit'
require 'ipaddr'

class TC_CIDRSet < Test::Unit::TestCase
  def cidrs(set)
    set.to_a.map(&:cidr)
  end

  def test_normalize_removes_contained_entries
    set = IPAddr::CIDRSet.new(%w[10.1.2.0/24 10.0.0.0/8 10.1.0.0/16])
    assert_equal(%w[10.0.0.0/8], cidrs(set))
  end

  def test_normalize_merges_adjacent_siblings
    set = IPAddr::CIDRSet.new(%w[10.0.0.128/25 10.0.0.0/25])
    assert_equal(%w[10.0.0.0/24], cidrs(set))
  end

  def test_normalize_merges_exactly_only
    set = IPAddr::CIDRSet.new(%w[10.0.0.0/25 10.0.0.192/26])
    assert_equal(%w[10.0.0.0/25 10.0.0.192/26], cidrs(set))
  end

  def test_host_bits_are_masked_off
    assert_equal(%w[10.1.2.0/24], cidrs(IPAddr::CIDRSet.new("10.1.2.3/24")))
  end

  def test_accepts_ipaddr_and_single_cidr
    assert_equal(%w[10.0.0.0/8], cidrs(IPAddr::CIDRSet.new(IPAddr.new("10.0.0.0/8"))))
    assert_equal(%w[10.0.0.0/8], cidrs(IPAddr::CIDRSet.new("10.0.0.0/8")))
  end

  def test_union
    a = IPAddr::CIDRSet.new(%w[10.0.0.0/24 10.0.2.0/24])
    b = IPAddr::CIDRSet.new(%w[10.0.1.0/24 192.168.0.0/16])
    assert_equal(%w[10.0.0.0/23 10.0.2.0/24 192.168.0.0/16], cidrs(a | b))
    assert_equal(cidrs(a | b), cidrs(a + b))
  end

  def test_intersection
    a = IPAddr::CIDRSet.new("10.0.0.0/8")
    b = IPAddr::CIDRSet.new(%w[10.1.0.0/16 192.168.0.0/16])
    assert_equal(%w[10.1.0.0/16], cidrs(a & b))
    assert_empty(a & IPAddr::CIDRSet.new("11.0.0.0/8"))
  end

  def test_difference_splits_at_boundaries
    a = IPAddr::CIDRSet.new("10.0.0.0/24")
    assert_equal(%w[10.0.0.128/25], cidrs(a - "10.0.0.0/25"))
    assert_equal(%w[10.0.0.0/25], cidrs(a - "10.0.0.128/25"))
    assert_equal(%w[10.0.0.0/26 10.0.0.128/25], cidrs(a - "10.0.0.64/26"))
    assert_equal(%w[10.0.0.0/10 10.128.0.0/9],
                 cidrs(IPAddr::CIDRSet.new("10.0.0.0/8") - "10.64.0.0/10"))
  end

  def test_difference_with_multiple_holes
    a = IPAddr::CIDRSet.new("10.0.0.0/24")
    result = a - IPAddr::CIDRSet.new(%w[10.0.0.0/26 10.0.0.192/26])
    assert_equal(%w[10.0.0.64/26 10.0.0.128/26], cidrs(result))
  end

  def test_difference_everything
    a = IPAddr::CIDRSet.new("10.0.0.0/24")
    assert_empty(a - "10.0.0.0/24")
    assert_empty(a - "10.0.0.0/8")
    assert_empty(a - "0.0.0.0/0")
  end

  def test_ipv4_and_ipv6_are_kept_separate
    set = IPAddr::CIDRSet.new(%w[10.0.0.0/8 2001:db8::/32])
    assert_equal(%w[10.0.0.0/8], set.ipv4.map(&:cidr))
    assert_equal(%w[2001:db8::/32], set.ipv6.map(&:cidr))
    assert_equal(%w[10.0.0.0/8 2001:db8::/32], cidrs(set))
  end

  def test_ipv4_mapped_defaults_to_ipv6
    set = IPAddr::CIDRSet.new("::ffff:10.1.2.0/120")
    assert_empty(set.ipv4)
    assert_equal(1, set.ipv6.size)
    assert_equal(120, set.ipv6.first.prefix)
  end

  def test_ipv4_mapped_option_converts_to_ipv4
    set = IPAddr::CIDRSet.new("::ffff:10.1.2.0/120", ipv4_mapped: :ipv4)
    assert_equal(%w[10.1.2.0/24], set.ipv4.map(&:cidr))
    assert_empty(set.ipv6)
    assert_include(set, "::ffff:10.1.2.3")
    assert_not_include(set, "::ffff:10.1.3.3")
  end

  def test_ipv4_mapped_option_validation
    assert_raise(ArgumentError) { IPAddr::CIDRSet.new([], ipv4_mapped: :v4) }
  end

  def test_include
    set = IPAddr::CIDRSet.new(%w[10.0.0.0/8 192.168.0.0/16]) - "10.1.2.0/24"
    assert_include(set, "10.0.0.1")
    assert_include(set, "10.1.1.255")
    assert_not_include(set, "10.1.2.0")
    assert_not_include(set, "10.1.2.255")
    assert_include(set, "10.1.3.0")
    assert_not_include(set, "11.0.0.1")
    assert_include(set, IPAddr.new("192.168.1.1"))
    # a block is included only when fully covered
    assert_include(set, "192.168.0.0/16")
    assert_not_include(set, "10.0.0.0/7")
    assert_not_include(set, "10.1.2.0/24")
  end

  def test_equality
    a = IPAddr::CIDRSet.new(%w[10.0.0.0/25 10.0.0.128/25])
    b = IPAddr::CIDRSet.new("10.0.0.0/24")
    assert_equal(a, b)
    assert_not_equal(a, IPAddr::CIDRSet.new("10.0.0.0/23"))
    assert_not_equal(a, "10.0.0.0/24")
  end

  def test_small_ipv4_range_matches_address_by_address
    allow = IPAddr::CIDRSet.new("192.0.2.0/24")
    deny = IPAddr::CIDRSet.new(%w[192.0.2.16/28 192.0.2.64/26 192.0.2.200/31])
    result = allow - deny

    deny_blocks = deny.to_a
    expected = (0..255).reject do |octet|
      addr = IPAddr.new("192.0.2.#{octet}")
      deny_blocks.any? { |block| block.include?(addr) }
    end
    actual = (0..255).select do |octet|
      result.include?(IPAddr.new("192.0.2.#{octet}"))
    end
    assert_equal(expected, actual)

    covered = result.to_a.flat_map { |block| block.to_range.map(&:to_i) }
    assert_equal(expected.map { |octet| IPAddr.new("192.0.2.#{octet}").to_i }, covered)
  end

  def test_ipv6_difference_stays_proportional_to_prefix_count
    set = IPAddr::CIDRSet.new("2001:db8::/32")
    result = set - IPAddr::CIDRSet.new(%w[2001:db8:1::/64 2001:db8:2::/64 2001:db8:ffff::/64])

    # 2**96 - 3 * 2**64 addresses remain; the result must stay a
    # small list of prefixes instead of per-address entries.
    assert_equal(78, result.size)
    assert_include(result, "2001:db8::1")
    assert_include(result, "2001:db8:3::1")
    assert_include(result, "2001:db8:fffe::1")
    assert_include(result, "2001:db8:1:ffff::")
    assert_include(result, "2001:db8:2:abcd::5")
    assert_include(result, "2001:db8:ffff:ffff::1")
    assert_not_include(result, "2001:db8:1::1")
    assert_not_include(result, "2001:db8:1::ffff")
    assert_not_include(result, "2001:db8:2::abcd")
    assert_not_include(result, "2001:db8:ffff::1")
    assert_not_include(result, "2001:db8:ffff::ffff")
    assert_not_include(result, "2001:db9::1")
    assert_not_include(result, "2001:db7:ffff:ffff::1")
  end

  def test_ipv6_normalize_merges_siblings
    set = IPAddr::CIDRSet.new(%w[2001:db8::/33 2001:db8:8000::/33])
    assert_equal(%w[2001:db8::/32], cidrs(set))
  end

  def test_enumerable
    set = IPAddr::CIDRSet.new(%w[10.0.0.0/24 10.0.1.0/24])
    assert_equal(%w[10.0.0.0/23], set.map(&:cidr))
    assert_kind_of(Enumerator, set.each)
  end
end
