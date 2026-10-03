# frozen_string_literal: false
require 'test/unit'
require 'uri'

class URI::TestOrigin < Test::Unit::TestCase
  def test_origin_value_returns_tuple_origin
    origin = URI('http://example.com/').origin_value
    assert_kind_of(URI::Origin, origin)
    assert_equal('http', origin.scheme)
    assert_equal('example.com', origin.host)
    assert_equal(80, origin.port)
    assert_not_predicate(origin, :opaque?)
  end

  def test_from_uri
    uri = URI('https://example.com/a')
    assert_equal(uri.origin_value, URI::Origin.from_uri(uri))
  end

  def test_ignores_path_query_fragment_and_userinfo
    a = URI('http://user:pass@example.com/a/b?x=1#frag').origin_value
    b = URI('http://example.com/other').origin_value
    assert_equal(a, b)
    assert_equal(a.hash, b.hash)
  end

  def test_normalizes_scheme_and_host_case
    assert_equal(URI('http://example.com/').origin_value,
                 URI('HTTP://EXAMPLE.COM/').origin_value)
    assert_equal(URI('https://example.com/').origin_value,
                 URI::HTTPS.build(host: 'Example.COM').origin_value)
  end

  def test_normalizes_default_port
    assert_equal(URI('http://example.com/').origin_value,
                 URI('http://example.com:80/').origin_value)
    assert_equal(URI('https://example.com/').origin_value,
                 URI('https://example.com:443/').origin_value)
    assert_not_equal(URI('http://example.com/').origin_value,
                     URI('https://example.com:80/').origin_value)
  end

  def test_effective_port
    assert_equal(8080, URI('http://example.com:8080/').origin_value.port)
    assert_equal(443, URI('https://example.com/').origin_value.port)
  end

  def test_distinguishes_scheme_host_and_port
    base = URI('http://example.com/').origin_value
    assert_not_equal(base, URI('https://example.com/').origin_value)
    assert_not_equal(base, URI('http://example.org/').origin_value)
    assert_not_equal(base, URI('http://example.com:8080/').origin_value)
    assert_not_equal(base, URI('ftp://example.com/').origin_value)
  end

  def test_usable_as_hash_key_for_grouping
    pools = Hash.new { |hash, key| hash[key] = [] }
    uris = [
      URI('http://example.com/a'),
      URI('http://EXAMPLE.com:80/b?x=1#f'),
      URI('http://example.com:8080/c'),
      URI('https://example.com/d'),
    ]
    uris.each { |uri| pools[uri.origin_value] << uri }
    assert_equal(3, pools.size)
    assert_equal(uris[0, 2], pools[URI('http://example.com/').origin_value])
  end

  def test_to_s_omits_default_port
    assert_equal('http://example.com', URI('http://example.com:80/').origin_value.to_s)
    assert_equal('https://example.com', URI('https://example.com/').origin_value.to_s)
    assert_equal('http://example.com:8080', URI('http://example.com:8080/').origin_value.to_s)
  end

  def test_to_s_consistent_with_equality
    origins = [
      'http://example.com/',
      'http://example.com:80/a?x=1#f',
      'http://example.com:8080/',
      'https://example.com/',
      'https://example.com:443/',
      'http://other.com/',
    ].map { |str| URI(str).origin_value }
    origins.combination(2) do |a, b|
      assert_equal(a == b, a.to_s == b.to_s,
                   a.inspect + ' vs ' + b.inspect)
      assert_equal(a.hash == b.hash, a == b,
                   a.inspect + ' vs ' + b.inspect)
    end
  end

  def test_ipv6_host
    origin = URI('http://[::1]:8080/').origin_value
    assert_equal('[::1]', origin.host)
    assert_equal(8080, origin.port)
    assert_equal('http://[::1]:8080', origin.to_s)
    assert_equal('http://[::1]', URI('http://[::1]/').origin_value.to_s)
    assert_equal(URI('http://[FE80::1]/').origin_value,
                 URI('http://[fe80::1]:80/').origin_value)
    assert_not_equal(URI('http://[::1]/').origin_value,
                     URI('http://[::2]/').origin_value)
  end

  def test_opaque_origin_for_non_origin_uris
    assert_predicate(URI('mailto:foo@example.com').origin_value, :opaque?)
    assert_predicate(URI('urn:isbn:0451450523').origin_value, :opaque?)
    assert_predicate(URI('file:///etc/hosts').origin_value, :opaque?)
    assert_predicate(URI::Generic.build(scheme: 'http', path: '/x').origin_value,
                     :opaque?)
  end

  def test_opaque_origins_are_unique
    a = URI('mailto:foo@example.com').origin_value
    b = URI('mailto:foo@example.com').origin_value
    assert_not_equal(a, b)
    assert_not_equal(a.hash, b.hash)
    assert_equal(a, a)
    assert_equal(2, { a => 1, b => 2 }.size)
  end

  def test_opaque_origin_components_and_serialization
    origin = URI('mailto:foo@example.com').origin_value
    assert_nil(origin.scheme)
    assert_nil(origin.host)
    assert_nil(origin.port)
    assert_equal('null', origin.to_s)
    assert_equal('null', URI('urn:isbn:0451450523').origin_value.to_s)
  end

  def test_opaque_origin_never_equals_tuple_origin
    opaque = URI('mailto:foo@example.com').origin_value
    tuple = URI('http://example.com/').origin_value
    assert_not_equal(opaque, tuple)
    assert_not_equal(tuple, opaque)
  end

  def test_not_equal_to_other_types
    origin = URI('http://example.com/').origin_value
    assert_not_equal(origin, 'http://example.com')
    assert_not_equal(origin, nil)
    assert_not_equal(origin, URI('http://example.com/'))
  end

  def test_http_origin_string_matches_origin_value
    uri = URI('http://example.com:8080/a?b=1#c')
    assert_equal(uri.origin_value.to_s, uri.origin)
    assert_equal('http://example.com:8080', uri.origin)
    assert_equal('http://example.com', URI('http://example.com:80/').origin)
  end

  def test_inspect
    assert_equal('#<URI::Origin http://example.com>',
                 URI('http://example.com/').origin_value.inspect)
    assert_equal('#<URI::Origin null>',
                 URI('mailto:foo@example.com').origin_value.inspect)
  end

  def test_origin_is_immutable
    assert_predicate(URI('http://example.com/').origin_value, :frozen?)
    assert_predicate(URI('mailto:foo@example.com').origin_value, :frozen?)
  end
end
