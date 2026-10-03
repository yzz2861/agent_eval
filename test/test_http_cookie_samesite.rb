# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))
require 'yaml'
require 'stringio'

class TestHTTPCookieSameSite < Test::Unit::TestCase
  ORIGIN = 'https://www.example.com/'

  def setup
    @jar = HTTP::CookieJar.new
    @jar.parse('strict=1; SameSite=Strict; Path=/', ORIGIN)
    @jar.parse('lax=1; SameSite=Lax; Path=/', ORIGIN)
    @jar.parse('none=1; SameSite=None; Secure; Path=/', ORIGIN)
    @jar.parse('plain=1; Path=/', ORIGIN)
  end

  def cookie_names_for(uri, **context)
    @jar.cookies_for(uri, **context).map(&:name).sort
  end

  # Table-driven request scenarios.  Each entry maps a description to
  # the request URI, the request context and the names of the cookies
  # expected to be sent.
  SCENARIOS = [
    [
      'same-site subresource GET',
      'https://www.example.com/api',
      { :method => 'GET', :top_level_site => 'https://www.example.com/' },
      %w[lax none plain strict],
    ],
    [
      'cross-site POST',
      'https://www.example.com/login',
      { :method => 'POST', :top_level_site => 'https://other.example/' },
      %w[none plain],
    ],
    [
      'cross-site top-level navigation with safe method',
      'https://www.example.com/landing',
      { :method => 'GET', :top_level_site => 'https://other.example/',
        :top_level_navigation => true },
      %w[lax none plain],
    ],
    [
      'cross-site top-level navigation with unsafe method',
      'https://www.example.com/landing',
      { :method => 'POST', :top_level_site => 'https://other.example/',
        :top_level_navigation => true },
      %w[none plain],
    ],
    [
      'same-site but different scheme (schemeful site)',
      'http://www.example.com/api',
      { :method => 'GET', :top_level_site => 'https://www.example.com/' },
      # Not same-site because the scheme differs; the SameSite=None
      # cookie is Secure and thus not sent over plain HTTP either.
      %w[plain],
    ],
    [
      'same-site but different scheme, top-level safe navigation',
      'http://www.example.com/landing',
      { :method => 'GET', :top_level_site => 'https://www.example.com/',
        :top_level_navigation => true },
      %w[lax plain],
    ],
    [
      'same-site request through a cross-site redirect',
      'https://www.example.com/back',
      { :method => 'GET', :top_level_site => 'https://www.example.com/',
        :redirect_chain => ['https://other.example/'] },
      %w[none plain],
    ],
    [
      'same-site request through a same-site redirect',
      'https://www.example.com/back',
      { :method => 'GET', :top_level_site => 'https://www.example.com/',
        :redirect_chain => ['https://static.example.com/'] },
      %w[lax none plain strict],
    ],
    [
      'unknown top-level site is never same-site',
      'https://www.example.com/api',
      { :method => 'GET', :top_level_site => nil },
      %w[none plain],
    ],
  ]

  def test_request_scenarios
    SCENARIOS.each { |description, uri, context, expected|
      assert_equal expected, cookie_names_for(uri, **context), description
    }
  end

  def test_legacy_cookies_interface_keeps_compatibility_mode
    # The URI-only interface must not guess a permissive context; it
    # simply does not enforce SameSite at all.
    assert_equal %w[lax none plain strict],
      @jar.cookies('https://www.example.com/').map(&:name).sort
  end

  def test_cookies_for_accepts_a_request_context_object
    context = HTTP::Cookie::RequestContext.new(
      :method => 'POST', :top_level_site => 'https://other.example/')
    assert_equal %w[none plain],
      @jar.cookies_for('https://www.example.com/', context).map(&:name).sort
  end

  def test_cookies_for_requires_an_explicit_top_level_site
    assert_raise(ArgumentError) do
      @jar.cookies_for('https://www.example.com/')
    end
  end

  def test_parse_samesite_values
    [
      ['SameSite=Strict', :strict],
      ['SameSite=Lax', :lax],
      ['SameSite=None; Secure', :none],
      ['samesite=STRICT', :strict],
      ['SameSite=lax', :lax],
    ].each { |attribute, expected|
      cookie, = HTTP::Cookie.parse("n=v; #{attribute}", ORIGIN)
      assert_not_nil cookie, attribute
      assert_equal expected, cookie.samesite, attribute
    }
  end

  def test_parse_rejects_samesite_none_without_secure
    assert_equal [], HTTP::Cookie.parse('n=v; SameSite=None', ORIGIN)
    assert_equal 1,
      HTTP::Cookie.parse('n=v; SameSite=None; Secure', ORIGIN).size
  end

  def test_parse_ignores_invalid_samesite_value
    cookie, = HTTP::Cookie.parse('n=v; SameSite=Bogus', ORIGIN)
    assert_not_nil cookie
    assert_nil cookie.samesite
  end

  def test_samesite_setter_validation
    cookie = HTTP::Cookie.new('n', 'v', :samesite => 'Strict')
    assert_equal :strict, cookie.samesite
    cookie.samesite = :none
    assert_equal :none, cookie.samesite
    cookie.samesite = nil
    assert_nil cookie.samesite
    assert_raise(ArgumentError) { cookie.samesite = 'bogus' }
    assert_raise(TypeError) { cookie.samesite = 42 }
  end

  def test_samesite_none_without_secure_is_not_acceptable
    cookie = HTTP::Cookie.new('n', 'v',
      :domain => 'www.example.com', :path => '/', :samesite => :none)
    assert_equal false, cookie.acceptable?
    cookie.secure = true
    assert_equal true, cookie.acceptable?
  end

  def test_set_cookie_value_includes_samesite
    cookie, = HTTP::Cookie.parse(
      'n=v; SameSite=Lax; Path=/', ORIGIN)
    assert_match(/; SameSite=Lax\z/, cookie.set_cookie_value)
    cookie, = HTTP::Cookie.parse('n=v; Path=/', ORIGIN)
    assert_no_match(/SameSite/, cookie.set_cookie_value)
  end

  def test_schemeful_site
    [
      ['https://www.example.co.uk/path?q=1', 'https://example.co.uk'],
      ['http://example.co.uk/', 'http://example.co.uk'],
      ['https://example.com/', 'https://example.com'],
      ['http://127.0.0.1:8080/', 'http://127.0.0.1'],
      ['https://localhost/', 'https://localhost'],
    ].each { |uri, expected|
      assert_equal expected, HTTP::Cookie.schemeful_site(uri), uri
    }
    # The scheme is significant: different schemes are different sites.
    assert_not_equal HTTP::Cookie.schemeful_site('http://example.com/'),
      HTTP::Cookie.schemeful_site('https://example.com/')
  end

  def test_samesite_persistence_via_yaml
    io = StringIO.new
    @jar.save(io, :session => true)
    io.rewind
    jar = HTTP::CookieJar.new
    jar.load(io)
    assert_equal %i[lax none strict],
      jar.select(&:samesite).map(&:samesite).sort
  end

  def test_samesite_persistence_via_to_h
    cookie, = HTTP::Cookie.parse('n=v; SameSite=Strict; Path=/', ORIGIN)
    assert_equal :strict, cookie.to_h[:samesite]
    restored = HTTP::Cookie.new(cookie.to_h)
    assert_equal :strict, restored.samesite
  end
end
