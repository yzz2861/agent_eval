# frozen_string_literal: false
require 'test/unit'
require 'uri'

class URI::TestOrigin < Test::Unit::TestCase
  def origin(s)
    URI(s).origin
  end

  def test_origin_is_value_object
    assert_kind_of(URI::Origin, URI('http://example.com/').origin)
  end

  def test_effective_port
    assert_equal(origin('http://example.com/'), origin('http://example.com:80/'))
    assert_equal(origin('https://example.com/'), origin('https://example.com:443/'))
    refute_equal(origin('http://example.com/'), origin('http://example.com:8080/'))
    refute_equal(origin('http://example.com:443/'), origin('https://example.com:443/'))
    assert_equal(80, URI('http://example.com/').origin.port)
    assert_equal(443, URI('https://example.com/').origin.port)
    assert_equal(8080, URI('http://example.com:8080/').origin.port)
  end

  def test_scheme_and_host_case_insensitive
    assert_equal(origin('HTTP://EXAMPLE.COM/'), origin('http://example.com/'))
    assert_equal(origin('http://Example.COM:80/a'), origin('http://example.com/b'))
  end

  def test_userinfo_path_query_fragment_ignored
    a = origin('http://user:pass@example.com/path?query=1#frag')
    b = origin('http://example.com')
    assert_equal(b, a)
    assert_equal('http://example.com', a.to_s)
  end

  def test_serialization
    assert_equal('http://example.com', origin('http://example.com/').to_s)
    assert_equal('http://example.com:8080', origin('http://example.com:8080/').to_s)
    assert_equal('http://example.com', origin('http://example.com:80/').to_s)
    assert_equal('https://example.com', origin('https://example.com/').to_s)
    assert_equal('https://example.com:8443', origin('https://example.com:8443/').to_s)
    assert_equal('http://example.com:443', origin('http://example.com:443/').to_s)

    a = origin('HTTP://EXAMPLE.COM:80/a?b#c')
    b = origin('http://example.com')
    assert_equal(b.to_s, a.to_s)
  end

  def test_hash_and_eql_consistency
    a = origin('http://example.com/path?a=1#x')
    b = origin('http://EXAMPLE.COM:80/other')
    assert(a.eql?(b))
    assert_equal(a.hash, b.hash)

    groups = {a => 1}
    assert_equal(1, groups[b])
    groups[b] += 1
    assert_equal(2, groups[a])

    refute_equal(origin('http://example.com/'), origin('https://example.com/'))
    refute_equal(origin('http://example.com/'), Object.new)
  end

  def test_ipv6
    assert_equal(origin('http://[::1]/'), origin('http://[0:0:0:0:0:0:0:1]:80/'))
    assert_equal(origin('http://[2001:db8::1]/'),
                 origin('http://[2001:DB8:0:0:0:0:0:1]/'))
    assert_equal('http://[::1]', origin('http://[::1]/').to_s)
    assert_equal('http://[2001:db8::1]:8080',
                 origin('http://[2001:DB8::1]:8080/').to_s)
    assert_equal('[::1]', URI('http://[::1]/').origin.host)
  end

  def test_ipvfuture_and_zone_kept
    assert_equal('http://[v1.fe]:8080',
                 URI::Origin.new('http', '[v1.FE]', 8080).to_s)
    zone = URI::Origin.new('http', '[FE80::1%eth0]', nil)
    assert_equal('[fe80::1%eth0]', zone.host)
    assert_equal('http://[fe80::1%eth0]', zone.to_s)
  end

  def test_non_http_schemes_have_opaque_origin
    %w[mailto:foo@example.com file:///tmp/x ftp://example.com/ data:text/plain,h].each do |s|
      o = origin(s)
      assert_kind_of(URI::OpaqueOrigin, o, s)
      assert_predicate(o, :opaque?)
      assert_equal('null', o.to_s, s)
    end
  end

  def test_http_without_host_has_opaque_origin
    %w[http:foo http:///path].each do |s|
      o = origin(s)
      assert_kind_of(URI::OpaqueOrigin, o, s)
      assert_equal('null', o.to_s, s)
    end
    refute_predicate(origin('http://example.com/'), :opaque?)
  end

  def test_opaque_origins_are_distinct
    a = origin('mailto:foo@example.com')
    b = origin('mailto:foo@example.com')
    c = origin('file:///tmp/x')

    assert_equal('null', a.to_s)
    assert_equal(a.to_s, b.to_s)
    assert_equal(a, a)
    assert(a.eql?(a))
    refute_equal(a, b)
    refute_equal(a, c)
    refute_equal(b, c)
    assert_not_equal(a.hash, b.hash)

    groups = {a => 1}
    assert_equal(1, groups[a])
    assert_nil(groups[b])
  end

  def test_direct_construction
    o = URI::Origin.new('HTTP', 'EXAMPLE.COM', nil)
    assert_equal('http', o.scheme)
    assert_equal('example.com', o.host)
    assert_equal(80, o.port)
    assert_equal('http://example.com', o.to_s)

    assert_equal(443, URI::Origin.new('https', 'example.com', '443').port)
    custom = URI::Origin.new('ws', 'example.com', nil, default_port: 80)
    assert_equal(80, custom.port)
    assert_equal('ws://example.com', custom.to_s)
    assert_equal('ws://example.com:81',
                 URI::Origin.new('ws', 'example.com', 81, default_port: 80).to_s)

    assert_raise(ArgumentError) { URI::Origin.new(nil, 'example.com', 80) }
    assert_raise(ArgumentError) { URI::Origin.new('http', nil, 80) }
    assert_raise(ArgumentError) { URI::Origin.new('http', '', 80) }
  end

  def test_frozen
    o = origin('http://example.com/')
    assert_predicate(o, :frozen?)
    assert_predicate(o.scheme, :frozen?)
    assert_predicate(o.host, :frozen?)
    assert_predicate(o.to_s, :frozen?)
  end
end
