# frozen_string_literal: true
require 'test/unit'
require 'ipaddr'

class TC_IPAddr_NAT64 < Test::Unit::TestCase
  WELL_KNOWN = "64:ff9b::/96"

  # Fixed translation vectors for 192.0.2.33 (0xc0000221), one per
  # prefix length allowed by RFC 6052 Section 2.2.
  VECTORS = [
    ["2001:db8::/32",      "2001:db8:c000:221::"],
    ["2001:db8:100::/40",  "2001:db8:1c0:2:21::"],
    ["2001:db8:122::/48",  "2001:db8:122:c000:2:2100::"],
    ["2001:db8:1200::/56", "2001:db8:1200:c0:0:221::"],
    ["2001:db8:1:2::/64",  "2001:db8:1:2:c0:2:2100:0"],
    ["64:ff9b::/96",       "64:ff9b::c000:221"],
  ].freeze

  def test_s_well_known
    nat64 = IPAddr::NAT64.well_known
    assert_equal(96, nat64.prefix_length)
    assert_equal(WELL_KNOWN, nat64.to_s)
  end

  def test_new_accepts_all_rfc6052_prefix_lengths
    [32, 40, 48, 56, 64, 96].each do |plen|
      nat64 = IPAddr::NAT64.new("2001:db8::/#{plen}")
      assert_equal(plen, nat64.prefix_length)
      assert_equal(IPAddr.new("2001:db8::").mask(plen), nat64.prefix)
    end
  end

  def test_new_accepts_ipaddr_argument
    nat64 = IPAddr::NAT64.new(IPAddr.new(WELL_KNOWN))
    assert_equal(96, nat64.prefix_length)
  end

  def test_new_rejects_disallowed_prefix_lengths
    [0, 8, 24, 31, 33, 72, 95, 97, 128].each do |plen|
      assert_raise(IPAddr::InvalidPrefixError) {
        IPAddr::NAT64.new("2001:db8::/#{plen}")
      }
    end
  end

  def test_new_rejects_ipv4_prefix
    assert_raise(IPAddr::InvalidPrefixError) {
      IPAddr::NAT64.new("192.0.2.0/24")
    }
  end

  def test_embed_standard_vectors
    VECTORS.each do |prefix, expected|
      nat64 = IPAddr::NAT64.new(prefix)
      v6 = nat64.embed("192.0.2.33")
      assert_equal(expected, v6.to_s, "embed into #{prefix}")
      assert_equal(Socket::AF_INET6, v6.family)
    end
  end

  def test_embed_accepts_ipaddr
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_equal("64:ff9b::c000:221", nat64.embed(IPAddr.new("192.0.2.33")).to_s)
  end

  def test_embed_boundary_addresses
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_equal("64:ff9b::", nat64.embed("0.0.0.0").to_s)
    assert_equal("64:ff9b::ffff:ffff", nat64.embed("255.255.255.255").to_s)
  end

  def test_embed_rejects_ipv6_and_networks
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_raise(IPAddr::NAT64::Error) { nat64.embed("64:ff9b::1") }
    assert_raise(IPAddr::NAT64::Error) { nat64.embed("192.0.2.0/24") }
  end

  def test_extract_standard_vectors
    VECTORS.each do |prefix, synthesized|
      nat64 = IPAddr::NAT64.new(prefix)
      v4 = nat64.extract(synthesized)
      assert_equal("192.0.2.33", v4.to_s, "extract from #{prefix}")
      assert_equal(Socket::AF_INET, v4.family)
    end
  end

  def test_extract_accepts_ipaddr
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_equal("192.0.2.33", nat64.extract(IPAddr.new("64:ff9b::c000:221")).to_s)
  end

  def test_extract_rejects_address_outside_prefix
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_raise(IPAddr::NAT64::Error) { nat64.extract("64:ff9c::c000:221") }
    assert_raise(IPAddr::NAT64::Error) { nat64.extract("2001:db8::c000:221") }
  end

  def test_extract_rejects_non_zero_reserved_octet
    # The "u" octet (bits 64-71) must be zero for prefix lengths <= 64.
    {
      "2001:db8::/32"      => "2001:db8:c000:221:100::",
      "2001:db8:100::/40"  => "2001:db8:1c0:2:121::",
      "2001:db8:122::/48"  => "2001:db8:122:c000:ff02:2100::",
      "2001:db8:1200::/56" => "2001:db8:1200:c0:100:221::",
      "2001:db8:1:2::/64"  => "2001:db8:1:2:1c0:2:2100::",
    }.each do |prefix, synthesized|
      nat64 = IPAddr::NAT64.new(prefix)
      assert_raise(IPAddr::NAT64::Error, "u octet in #{synthesized}") {
        nat64.extract(synthesized)
      }
    end
  end

  def test_extract_rejects_non_zero_suffix
    {
      "2001:db8::/32"      => "2001:db8:c000:221::1",
      "2001:db8:100::/40"  => "2001:db8:1c0:2:21::1",
      "2001:db8:122::/48"  => "2001:db8:122:c000:2:2100:0:1",
      "2001:db8:1200::/56" => "2001:db8:1200:c0::221:1",
      "2001:db8:1:2::/64"  => "2001:db8:1:2:c0:2:2100:1",
    }.each do |prefix, synthesized|
      nat64 = IPAddr::NAT64.new(prefix)
      assert_raise(IPAddr::NAT64::Error, "suffix in #{synthesized}") {
        nat64.extract(synthesized)
      }
    end
  end

  def test_extract_rejects_ipv4
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_raise(IPAddr::NAT64::Error) { nat64.extract("192.0.2.33") }
  end

  def test_round_trip
    VECTORS.each do |prefix, _|
      nat64 = IPAddr::NAT64.new(prefix)
      ["0.0.0.0", "192.0.2.33", "10.255.255.255", "255.255.255.255"].each do |v4|
        assert_equal(v4, nat64.extract(nat64.embed(v4)).to_s, "round trip via #{prefix}")
      end
    end
  end

  def test_embed_prefix_with_96_returns_single_prefix
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_equal(["64:ff9b::c000:200/120"], nat64.embed_prefix("192.0.2.0/24").map(&:cidr))
    assert_equal(["64:ff9b::c000:221/128"], nat64.embed_prefix("192.0.2.33").map(&:cidr))
    assert_equal(["64:ff9b::/96"], nat64.embed_prefix("0.0.0.0/0").map(&:cidr))
    assert_equal(["64:ff9b::ffff:ff00/120"], nat64.embed_prefix("255.255.255.0/24").map(&:cidr))
  end

  def test_embed_prefix_host_route_for_shorter_prefixes
    nat64 = IPAddr::NAT64.new("2001:db8:1:2::/64")
    assert_equal(["2001:db8:1:2:c0:2:2100:0/128"], nat64.embed_prefix("192.0.2.33/32").map(&:cidr))
  end

  def test_embed_prefix_masks_host_bits
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_equal(["64:ff9b::c000:200/120"], nat64.embed_prefix("192.0.2.77/24").map(&:cidr))
  end

  def test_embed_prefix_not_expressible_as_single_prefix
    nat64 = IPAddr::NAT64.new("2001:db8:1:2::/64")
    error = assert_raise(IPAddr::NAT64::Error) {
      nat64.embed_prefix("192.0.2.0/24")
    }
    assert_match(/cannot be expressed as a single IPv6 prefix/, error.message)

    nat64 = IPAddr::NAT64.new("2001:db8::/32")
    assert_raise(IPAddr::NAT64::Error) { nat64.embed_prefix("10.0.0.0/8") }
  end

  def test_embed_prefix_rejects_ipv6
    nat64 = IPAddr::NAT64.new(WELL_KNOWN)
    assert_raise(IPAddr::NAT64::Error) { nat64.embed_prefix("64:ff9b::/96") }
  end

  def test_no_guessing_of_arbitrary_ipv6_addresses
    # Translation only happens through an explicitly declared prefix;
    # IPAddr itself gains no transition-format detection.
    addr = IPAddr.new("64:ff9b::c000:221")
    assert_not_respond_to(addr, :nat64)
    assert_not_respond_to(addr, :ipv4_embedded?)
  end

  def test_inspect
    assert_equal("#<IPAddr::NAT64: 64:ff9b::/96>", IPAddr::NAT64.well_known.inspect)
  end
end
