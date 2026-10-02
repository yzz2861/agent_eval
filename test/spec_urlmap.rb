# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/urlmap'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
end

describe Rack::URLMap do
  it "dispatches paths correctly" do
    app = lambda { |env|
      [200, {
        'x-scriptname' => env['SCRIPT_NAME'],
        'x-pathinfo' => env['PATH_INFO'],
        'content-type' => 'text/plain'
      }, [""]]
    }
    map = Rack::Lint.new(Rack::URLMap.new({
      'http://foo.org/bar' => app,
      '/foo' => app,
      '/foo/bar' => app
    }))

    res = Rack::MockRequest.new(map).get("/")
    res.must_be :not_found?

    res = Rack::MockRequest.new(map).get("/qux")
    res.must_be :not_found?

    res = Rack::MockRequest.new(map).get("/foo")
    res.must_be :ok?
    res["x-scriptname"].must_equal "/foo"
    res["x-pathinfo"].must_equal ""

    res = Rack::MockRequest.new(map).get("/foo/")
    res.must_be :ok?
    res["x-scriptname"].must_equal "/foo"
    res["x-pathinfo"].must_equal "/"

    res = Rack::MockRequest.new(map).get("/foo/bar")
    res.must_be :ok?
    res["x-scriptname"].must_equal "/foo/bar"
    res["x-pathinfo"].must_equal ""

    res = Rack::MockRequest.new(map).get("/foo/bard")
    res.must_be :ok?
    res["x-scriptname"].must_equal "/foo"
    res["x-pathinfo"].must_equal "/bard"

    res = Rack::MockRequest.new(map).get("/foo/bar/")
    res.must_be :ok?
    res["x-scriptname"].must_equal "/foo/bar"
    res["x-pathinfo"].must_equal "/"

    res = Rack::MockRequest.new(map).get("/foo///bar//quux")
    res.status.must_equal 200
    res.must_be :ok?
    res["x-scriptname"].must_equal "/foo/bar"
    res["x-pathinfo"].must_equal "//quux"

    res = Rack::MockRequest.new(map).get("/foo/quux", "SCRIPT_NAME" => "/bleh")
    res.must_be :ok?
    res["x-scriptname"].must_equal "/bleh/foo"
    res["x-pathinfo"].must_equal "/quux"

    res = Rack::MockRequest.new(map).get("/bar", 'HTTP_HOST' => 'foo.org')
    res.must_be :ok?
    res["x-scriptname"].must_equal "/bar"
    res["x-pathinfo"].must_be :empty?

    res = Rack::MockRequest.new(map).get("/bar/", 'HTTP_HOST' => 'foo.org')
    res.must_be :ok?
    res["x-scriptname"].must_equal "/bar"
    res["x-pathinfo"].must_equal '/'
  end


  it "dispatches hosts correctly" do
    map = Rack::Lint.new(Rack::URLMap.new("http://foo.org/" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "foo.org",
                                "x-host" => env["HTTP_HOST"] || env["SERVER_NAME"],
                              }, [""]]},
                           "http://subdomain.foo.org/" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "subdomain.foo.org",
                                "x-host" => env["HTTP_HOST"] || env["SERVER_NAME"],
                              }, [""]]},
                           "http://bar.org/" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "bar.org",
                                "x-host" => env["HTTP_HOST"] || env["SERVER_NAME"],
                              }, [""]]},
                           "/" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "default.org",
                                "x-host" => env["HTTP_HOST"] || env["SERVER_NAME"],
                              }, [""]]}
                           ))

    res = Rack::MockRequest.new(map).get("/")
    res.must_be :ok?
    res["x-position"].must_equal "default.org"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "bar.org")
    res.must_be :ok?
    res["x-position"].must_equal "bar.org"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "foo.org")
    res.must_be :ok?
    res["x-position"].must_equal "foo.org"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "subdomain.foo.org", "SERVER_NAME" => "foo.org")
    res.must_be :ok?
    res["x-position"].must_equal "subdomain.foo.org"

    res = Rack::MockRequest.new(map).get("http://foo.org/")
    res.must_be :ok?
    res["x-position"].must_equal "foo.org"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "example.org")
    res.must_be :ok?
    res["x-position"].must_equal "default.org"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "any-host.org")
    res.must_be :ok?
    res["x-position"].must_equal "default.org"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "any-host.org", "HTTP_X_FORWARDED_HOST" => "any-host.org")
    res.must_be :ok?
    res["x-position"].must_equal "default.org"

    res = Rack::MockRequest.new(map).get("/",
                                         "HTTP_HOST" => "example.org:9292",
                                         "SERVER_PORT" => "9292")
    res.must_be :ok?
    res["x-position"].must_equal "default.org"
  end

  it "be nestable" do
    map = Rack::Lint.new(Rack::URLMap.new("/foo" =>
      Rack::URLMap.new("/bar" =>
        Rack::URLMap.new("/quux" => lambda { |env|
                           [200,
                            { "content-type" => "text/plain",
                              "x-position" => "/foo/bar/quux",
                              "x-pathinfo" => env["PATH_INFO"],
                              "x-scriptname" => env["SCRIPT_NAME"],
                            }, [""]]}
                         ))))

    res = Rack::MockRequest.new(map).get("/foo/bar")
    res.must_be :not_found?

    res = Rack::MockRequest.new(map).get("/foo/bar/quux")
    res.must_be :ok?
    res["x-position"].must_equal "/foo/bar/quux"
    res["x-pathinfo"].must_equal ""
    res["x-scriptname"].must_equal "/foo/bar/quux"
  end

  it "route root apps correctly" do
    map = Rack::Lint.new(Rack::URLMap.new("/" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "root",
                                "x-pathinfo" => env["PATH_INFO"],
                                "x-scriptname" => env["SCRIPT_NAME"]
                              }, [""]]},
                           "/foo" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "foo",
                                "x-pathinfo" => env["PATH_INFO"],
                                "x-scriptname" => env["SCRIPT_NAME"]
                              }, [""]]}
                           ))

    res = Rack::MockRequest.new(map).get("/foo/bar")
    res.must_be :ok?
    res["x-position"].must_equal "foo"
    res["x-pathinfo"].must_equal "/bar"
    res["x-scriptname"].must_equal "/foo"

    res = Rack::MockRequest.new(map).get("/foo")
    res.must_be :ok?
    res["x-position"].must_equal "foo"
    res["x-pathinfo"].must_equal ""
    res["x-scriptname"].must_equal "/foo"

    res = Rack::MockRequest.new(map).get("/bar")
    res.must_be :ok?
    res["x-position"].must_equal "root"
    res["x-pathinfo"].must_equal "/bar"
    res["x-scriptname"].must_equal ""

    res = Rack::MockRequest.new(map).get("")
    res.must_be :ok?
    res["x-position"].must_equal "root"
    res["x-pathinfo"].must_equal "/"
    res["x-scriptname"].must_equal ""
  end

  it "not squeeze slashes" do
    map = Rack::Lint.new(Rack::URLMap.new("/" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "root",
                                "x-pathinfo" => env["PATH_INFO"],
                                "x-scriptname" => env["SCRIPT_NAME"]
                              }, [""]]},
                           "/foo" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "foo",
                                "x-pathinfo" => env["PATH_INFO"],
                                "x-scriptname" => env["SCRIPT_NAME"]
                              }, [""]]}
                           ))

    res = Rack::MockRequest.new(map).get("/http://example.org/bar")
    res.must_be :ok?
    res["x-position"].must_equal "root"
    res["x-pathinfo"].must_equal "/http://example.org/bar"
    res["x-scriptname"].must_equal ""
  end

  it "not be case sensitive with hosts" do
    map = Rack::Lint.new(Rack::URLMap.new("http://example.org/" => lambda { |env|
                             [200,
                              { "content-type" => "text/plain",
                                "x-position" => "root",
                                "x-pathinfo" => env["PATH_INFO"],
                                "x-scriptname" => env["SCRIPT_NAME"]
                              }, [""]]}
                           ))

    res = Rack::MockRequest.new(map).get("http://example.org/")
    res.must_be :ok?
    res["x-position"].must_equal "root"
    res["x-pathinfo"].must_equal "/"
    res["x-scriptname"].must_equal ""

    res = Rack::MockRequest.new(map).get("http://EXAMPLE.ORG/")
    res.must_be :ok?
    res["x-position"].must_equal "root"
    res["x-pathinfo"].must_equal "/"
    res["x-scriptname"].must_equal ""
  end

  it "not allow locations unless they start with /" do
    lambda do
      Rack::URLMap.new("a/" => lambda { |env| })
    end.must_raise ArgumentError
  end

  def position_app(position)
    lambda { |env|
      [200, {
        'content-type' => 'text/plain',
        'x-position' => position,
        'x-scriptname' => env['SCRIPT_NAME'],
        'x-pathinfo' => env['PATH_INFO'],
      }, [""]]
    }
  end

  it "supports hash keys with an explicit authority and path" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com', path: '/api' } => position_app('api')))

    res = Rack::MockRequest.new(map).get('/api/users', 'HTTP_HOST' => 'example.com')
    res.must_be :ok?
    res['x-position'].must_equal 'api'
    res['x-scriptname'].must_equal '/api'
    res['x-pathinfo'].must_equal '/users'

    Rack::MockRequest.new(map).get('/api', 'HTTP_HOST' => 'other.org').must_be :not_found?
  end

  it "dispatches authorities with explicit ports" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com:9292' } => position_app('port'),
      '/' => position_app('default')))

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com:9292')
    res['x-position'].must_equal 'port'

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com', 'SERVER_PORT' => '9292')
    res['x-position'].must_equal 'port'

    # A different port does not match the authority.
    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com:8080')
    res['x-position'].must_equal 'default'

    # The default port does not match a :9292 authority.
    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com')
    res['x-position'].must_equal 'default'
  end

  it "treats an omitted request port as the server port" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com:80' } => position_app('eighty')))

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com')
    res['x-position'].must_equal 'eighty'

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com:80')
    res['x-position'].must_equal 'eighty'

    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com:81').must_be :not_found?
  end

  it "dispatches single-level wildcard authorities" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: '*.example.com' } => position_app('wild')))

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'a.example.com')
    res['x-position'].must_equal 'wild'

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'A.Example.COM')
    res['x-position'].must_equal 'wild'

    # The apex itself does not match.
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com').must_be :not_found?

    # Deeper subdomains do not match.
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'a.b.example.com').must_be :not_found?

    # Lookalike hosts do not match.
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'badexample.com').must_be :not_found?
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'a.example.com.evil.org').must_be :not_found?
  end

  it "supports wildcards and ports in URL string keys" do
    map = Rack::Lint.new(Rack::URLMap.new(
      'http://*.example.com:8080/api' => position_app('wild')))

    res = Rack::MockRequest.new(map).get('/api/x', 'HTTP_HOST' => 'a.example.com:8080')
    res['x-position'].must_equal 'wild'
    res['x-scriptname'].must_equal '/api'
    res['x-pathinfo'].must_equal '/x'

    Rack::MockRequest.new(map).get('/api', 'HTTP_HOST' => 'a.example.com:9292').must_be :not_found?
    Rack::MockRequest.new(map).get('/api', 'HTTP_HOST' => 'example.com:8080').must_be :not_found?
  end

  it "dispatches IPv6 authorities" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: '[::1]:8080' } => position_app('v6')))

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => '[::1]:8080')
    res['x-position'].must_equal 'v6'

    res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => '[::1]', 'SERVER_PORT' => '8080')
    res['x-position'].must_equal 'v6'

    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => '[::1]:80').must_be :not_found?
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => '[::2]:8080').must_be :not_found?
  end

  it "prioritizes exact authorities over wildcards and wildcards over hostless entries" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: '*.example.com' } => position_app('wild'),
      { authority: 'foo.example.com' } => position_app('exact'),
      '/' => position_app('default')))

    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'foo.example.com')['x-position'].must_equal 'exact'
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'bar.example.com')['x-position'].must_equal 'wild'
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'other.org')['x-position'].must_equal 'default'
  end

  it "prioritizes authorities with ports over port-less authorities" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com' } => position_app('plain'),
      { authority: 'example.com:9292' } => position_app('port')))

    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com:9292')['x-position'].must_equal 'port'
    Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => 'example.com')['x-position'].must_equal 'plain'
  end

  it "prioritizes authority entries over hostless entries regardless of path length" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com', path: '/' } => position_app('auth'),
      '/foo' => position_app('hostless')))

    Rack::MockRequest.new(map).get('/foo', 'HTTP_HOST' => 'example.com')['x-position'].must_equal 'auth'
    Rack::MockRequest.new(map).get('/foo', 'HTTP_HOST' => 'other.org')['x-position'].must_equal 'hostless'
  end

  it "prioritizes longer paths within the same authority" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com', path: '/' } => position_app('root'),
      { authority: 'example.com', path: '/foo' } => position_app('foo')))

    Rack::MockRequest.new(map).get('/foo', 'HTTP_HOST' => 'example.com')['x-position'].must_equal 'foo'
    Rack::MockRequest.new(map).get('/bar', 'HTTP_HOST' => 'example.com')['x-position'].must_equal 'root'
  end

  it "matches authorities against SERVER_NAME when HTTP_HOST differs" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com' } => position_app('auth')))

    res = Rack::MockRequest.new(map).get('/', 'SERVER_NAME' => 'example.com')
    res['x-position'].must_equal 'auth'
  end

  it "ignores forwarded headers when matching authorities" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: 'example.com' } => position_app('auth'),
      '/' => position_app('default')))

    res = Rack::MockRequest.new(map).get('/',
      'HTTP_HOST' => 'other.org',
      'HTTP_X_FORWARDED_HOST' => 'example.com',
      'HTTP_X_FORWARDED_SERVER' => 'example.com')
    res['x-position'].must_equal 'default'
  end

  it "does not match malformed request authorities" do
    # No Rack::Lint here: Lint itself rejects malformed HTTP_HOST values,
    # but a real server may still pass them through to the app.
    map = Rack::URLMap.new(
      { authority: '*.example.com' } => position_app('wild'),
      '/' => position_app('default'))

    ['.example.com', 'a..example.com', 'a b.example.com', 'example.com:abc'].each do |host|
      res = Rack::MockRequest.new(map).get('/', 'HTTP_HOST' => host)
      res['x-position'].must_equal 'default'
    end
  end

  it "rejects invalid authorities" do
    app = lambda { |env| [200, {}, ['']] }

    [
      'http://exa mple.com/',
      'http://example.com:abc/',
      'http://example.com:0/',
      'http://example.com:65536/',
      'http://example.com:80:90/',
      'http://foo.*.com/',
      'http://*/',
      'http://*.:8080/',
      'http://[::1/',
      'http://::1/',
      'http://:8080/',
      'http://user@example.com/',
    ].each do |location|
      lambda { Rack::URLMap.new(location => app) }.must_raise ArgumentError
    end

    lambda { Rack::URLMap.new({ authority: '' } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: 'exa mple.com' } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ path: '/' } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: 'example.com', bogus: 1 } => app) }.must_raise ArgumentError
  end

  it "restores SCRIPT_NAME and PATH_INFO after nested dispatch" do
    inner = Rack::URLMap.new('/bar' => lambda { |env| [200, { 'content-type' => 'text/plain' }, ['ok']] })
    outer = Rack::URLMap.new('/foo' => inner)

    env = Rack::MockRequest.env_for('/foo/bar')
    env['SCRIPT_NAME'] = '/base'
    status, = outer.call(env)
    status.must_equal 200
    env['SCRIPT_NAME'].must_equal '/base'
    env['PATH_INFO'].must_equal '/foo/bar'
  end

  it "restores SCRIPT_NAME and PATH_INFO when a nested app raises" do
    inner = Rack::URLMap.new('/bar' => lambda { |env| raise 'boom' })
    outer = Rack::URLMap.new('/foo' => inner)

    env = Rack::MockRequest.env_for('/foo/bar')
    env['SCRIPT_NAME'] = '/base'
    lambda { outer.call(env) }.must_raise RuntimeError
    env['SCRIPT_NAME'].must_equal '/base'
    env['PATH_INFO'].must_equal '/foo/bar'
  end
end
