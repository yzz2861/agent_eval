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
      [200,
       { "content-type" => "text/plain",
         "x-position" => position,
         "x-pathinfo" => env["PATH_INFO"],
         "x-scriptname" => env["SCRIPT_NAME"],
       }, [""]]
    }
  end

  it "dispatches explicit authorities by host, wildcard and port" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: "example.com" } => position_app("exact"),
      { authority: "example.com:9292" } => position_app("exact-port"),
      { authority: "*.example.com" } => position_app("wildcard"),
      "/" => position_app("default")
    ))

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "example.com")
    res.must_be :ok?
    res["x-position"].must_equal "exact"

    # Host case is irrelevant.
    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "ExAmPlE.CoM")
    res["x-position"].must_equal "exact"

    # An explicit port beats the same host without one.
    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "example.com:9292", "SERVER_PORT" => "9292")
    res["x-position"].must_equal "exact-port"

    # A request omitting the port takes it from SERVER_PORT.
    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "example.com", "SERVER_PORT" => "9292")
    res["x-position"].must_equal "exact-port"

    # An authority without a port matches any request port.
    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "example.com:8080", "SERVER_PORT" => "8080")
    res["x-position"].must_equal "exact"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "www.example.com")
    res["x-position"].must_equal "wildcard"

    # The wildcard covers exactly one label.
    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "a.b.example.com")
    res["x-position"].must_equal "default"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "unknown.org")
    res["x-position"].must_equal "default"
  end

  it "matches authorities against SERVER_NAME and SERVER_PORT when HTTP_HOST is absent" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: "example.com:9292" } => position_app("exact-port"),
      "/" => position_app("default")
    ))

    env = Rack::MockRequest.env_for("/",
                                    "SERVER_NAME" => "example.com",
                                    "SERVER_PORT" => "9292")
    env.delete("HTTP_HOST")

    status, headers, _body = map.call(env)
    status.must_equal 200
    headers["x-position"].must_equal "exact-port"

    # Forwarded headers are never consulted.
    res = Rack::MockRequest.new(map).get("/",
                                         "HTTP_HOST" => "unknown.org",
                                         "SERVER_PORT" => "9292",
                                         "HTTP_X_FORWARDED_HOST" => "example.com",
                                         "HTTP_X_FORWARDED_SERVER" => "example.com")
    res.must_be :ok?
    res["x-position"].must_equal "default"
  end

  it "dispatches authorities with IPv6 literals" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: "[::1]:8080" } => position_app("v6-port"),
      { authority: "[2001:db8::1]" } => position_app("v6"),
      "/" => position_app("default")
    ))

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "[::1]:8080")
    res.must_be :ok?
    res["x-position"].must_equal "v6-port"

    # The port falls back to SERVER_PORT when the host header omits it.
    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "[::1]", "SERVER_PORT" => "8080")
    res["x-position"].must_equal "v6-port"

    # Hex case in IPv6 literals is irrelevant.
    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "[2001:DB8::1]")
    res["x-position"].must_equal "v6"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "[::1]:9090", "SERVER_PORT" => "9090")
    res["x-position"].must_equal "default"
  end

  it "prioritizes authorities over path prefixes" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: "example.com", path: "/app" } => position_app("authority"),
      "/app/deep" => position_app("deep-path"),
      "/" => position_app("default")
    ))

    # A matching authority wins over a longer host-less path.
    res = Rack::MockRequest.new(map).get("/app/deep", "HTTP_HOST" => "example.com")
    res.must_be :ok?
    res["x-position"].must_equal "authority"
    res["x-scriptname"].must_equal "/app"
    res["x-pathinfo"].must_equal "/deep"

    # Without a matching authority the longer path wins.
    res = Rack::MockRequest.new(map).get("/app/deep", "HTTP_HOST" => "other.org")
    res["x-position"].must_equal "deep-path"
    res["x-scriptname"].must_equal "/app/deep"
    res["x-pathinfo"].must_equal ""
  end

  it "supports authorities in http(s) url keys, including wildcards and ports" do
    map = Rack::Lint.new(Rack::URLMap.new(
      "http://*.example.com/sub" => position_app("wildcard"),
      "http://example.com:9292/" => position_app("exact-port")
    ))

    res = Rack::MockRequest.new(map).get("/sub", "HTTP_HOST" => "a.example.com")
    res.must_be :ok?
    res["x-position"].must_equal "wildcard"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "example.com:9292", "SERVER_PORT" => "9292")
    res.must_be :ok?
    res["x-position"].must_equal "exact-port"

    res = Rack::MockRequest.new(map).get("/", "HTTP_HOST" => "example.com")
    res.must_be :not_found?
  end

  it "does not route requests for a known authority to another site" do
    map = Rack::Lint.new(Rack::URLMap.new(
      { authority: "*.example.com", path: "/only" } => position_app("wildcard"),
      "/" => position_app("default")
    ))

    res = Rack::MockRequest.new(map).get("/only", "HTTP_HOST" => "a.example.com")
    res.must_be :ok?
    res["x-position"].must_equal "wildcard"

    # The host matches an authority but the path does not: 404, not the default site.
    res = Rack::MockRequest.new(map).get("/other", "HTTP_HOST" => "a.example.com")
    res.must_be :not_found?

    # A malformed host header never matches an authority; it is
    # treated like any other unknown host and lands on the default.
    bare = Rack::URLMap.new(
      { authority: "*.example.com", path: "/only" } => position_app("wildcard"),
      "/" => position_app("default")
    )
    env = Rack::MockRequest.env_for("/only", "HTTP_HOST" => "a.example.com:bad", "SERVER_NAME" => "example.org")
    status, headers, _body = bare.call(env)
    status.must_equal 200
    headers["x-position"].must_equal "default"
  end

  it "rejects invalid authorities instead of falling to an unexpected site" do
    app = lambda { |env| [200, {}, []] }

    lambda { Rack::URLMap.new({ authority: nil } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "exa mple.com" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "http://example.com" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "example.com/path" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "example.com:abc" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "example.com:70000" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "*" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "*." } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "foo.*.com" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "f*.example.com" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "::1" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "[::1" } => app) }.must_raise ArgumentError
    lambda { Rack::URLMap.new({ authority: "[::1]x" } => app) }.must_raise ArgumentError
  end

  it "restores SCRIPT_NAME and PATH_INFO after nested dispatch" do
    map = Rack::Lint.new(Rack::URLMap.new("/foo" =>
      Rack::URLMap.new("/bar" => position_app("nested"))))

    env = Rack::MockRequest.env_for("/foo/bar/baz")
    env["SCRIPT_NAME"] = "/base"

    status, _headers, _body = map.call(env)
    status.must_equal 200
    env["SCRIPT_NAME"].must_equal "/base"
    env["PATH_INFO"].must_equal "/foo/bar/baz"
  end

  it "restores SCRIPT_NAME and PATH_INFO when a nested map raises" do
    inner = Rack::URLMap.new("/boom" => lambda { |env| raise "boom" })
    map = Rack::URLMap.new("/foo" => inner)

    env = Rack::MockRequest.env_for("/foo/boom")
    env["SCRIPT_NAME"] = "/base"

    lambda { map.call(env) }.must_raise RuntimeError
    env["SCRIPT_NAME"].must_equal "/base"
    env["PATH_INFO"].must_equal "/foo/boom"
  end
end
