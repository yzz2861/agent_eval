# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/body_proxy'
  require_relative '../lib/rack/head'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/prefer'
  require_relative '../lib/rack/request'
end

class CloseTrackingBody
  attr_reader :closed

  def initialize(chunks = ["object"])
    @chunks = chunks
    @closed = false
  end

  def each(&block)
    @chunks.each(&block)
  end

  def close
    @closed = true
  end

  def closed?
    @closed
  end
end

describe Rack::Prefer do
  def env_for(prefer = nil, method = "GET")
    headers = {}
    headers["HTTP_PREFER"] = prefer if prefer
    Rack::MockRequest.env_for("/", method: method, **headers)
  end

  def response(app, env)
    Rack::Lint.new(Rack::Prefer.new(app)).call(env)
  end

  it "parses return preferences and quoted extension parameters" do
    request = Rack::Request.new(env_for(
      'return=minimal, respond-async; report="hello, world"; depth="2", wait=100'
    ))

    request.preferences.value(:return).must_equal "minimal"
    request.preferences[:return].must_be_kind_of Rack::Prefer::Preference
    request.preferences.must_be :minimal?
    request.preferences["respond-async"].params["report"].must_equal "hello, world"
    request.preferences["respond-async"].params["depth"].must_equal "2"
    request.preferences.value("wait").must_equal "100"
    request.preferences.to_a.length.must_equal 3
  end

  it "keeps unknown preferences available for applications" do
    request = Rack::Request.new(env_for('handle-errors; severity="high"'))

    request.preferences.must_include "handle-errors"
    request.preferences["handle-errors"].params["severity"].must_equal "high"
  end

  it "uses the first occurrence for conflicting preference values and parameters" do
    request = Rack::Request.new(env_for(
      'return=minimal; foo=1, return=representation; foo=2, foo=bar; x=1; y=2, foo=bar; x=3'
    ))

    request.preferences.value(:return).must_equal "minimal"
    request.preferences[:return].params["foo"].must_equal "1"
    request.preferences["foo"].params["x"].must_equal "1"
    request.preferences["foo"].params["y"].must_equal "2"
    request.preferences.to_a.length.must_equal 4
  end

  it "does not echo preferences that the application did not apply" do
    body = CloseTrackingBody.new
    app = lambda do |env|
      [201, {"content-type" => "application/json"}, body]
    end

    status, headers, response_body = Rack::Prefer.new(app).call(env_for("return=minimal, foo"))

    status.must_equal 201
    headers.wont_include "preference-applied"
    response_body.must_equal body
    body.wont_be :closed?
  end

  it "returns the representation and applies the explicit representation preference" do
    body = CloseTrackingBody.new
    app = lambda do |env|
      request = Rack::Request.new(env)
      request.prefer(:return, :representation)
      [201, {
        "content-type" => "application/json",
        "content-length" => "6",
        "location" => "/objects/1"
      }, body]
    end

    status, headers, response_body = response(app, env_for("return=minimal, return=representation"))

    status.must_equal 201
    headers["preference-applied"].must_equal "return=representation"
    headers["content-type"].must_equal "application/json"
    headers["content-length"].must_equal "6"
    headers["location"].must_equal "/objects/1"
    response_body.to_enum.to_a.must_equal ["object"]
    body.wont_be :closed?
  end

  it "minimizes the response and closes the original body" do
    body = CloseTrackingBody.new
    app = lambda do |env|
      request = Rack::Request.new(env)
      request.prefer(:return, :minimal)
      [201, {
        "content-type" => "application/json",
        "content-length" => "6",
        "content-location" => "/objects/1",
        "content-encoding" => "identity",
        "etag" => '"v1"',
        "location" => "/objects/1",
        "x-metadata" => "kept"
      }, body]
    end

    status, headers, response_body = Rack::Prefer.new(app).call(env_for("return=minimal"))

    status.must_equal 201
    headers["preference-applied"].must_equal "return=minimal"
    headers["location"].must_equal "/objects/1"
    headers["etag"].must_equal '"v1"'
    headers["x-metadata"].must_equal "kept"
    headers.wont_include "content-type"
    headers.wont_include "content-length"
    headers.wont_include "content-location"
    headers.wont_include "content-encoding"
    response_body.to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "keeps status metadata such as Content-Range for a minimal partial response" do
    body = CloseTrackingBody.new
    app = lambda do |env|
      Rack::Request.new(env).prefer(:return, :minimal)
      [206, {
        "content-type" => "application/json",
        "content-length" => "6",
        "content-range" => "bytes 0-5/100",
        "etag" => '"v1"'
      }, body]
    end

    status, headers, response_body = Rack::Prefer.new(app).call(env_for("return=minimal"))

    status.must_equal 206
    headers["content-range"].must_equal "bytes 0-5/100"
    headers["etag"].must_equal '"v1"'
    headers.wont_include "content-type"
    headers.wont_include "content-length"
    response_body.must_equal []
    body.must_be :closed?
  end

  it "uses explicitly supplied values when acknowledging an unknown preference" do
    app = lambda do |env|
      request = Rack::Request.new(env)
      request.prefer(:foo, "bar", baz: "a;b")
      [200, {}, []]
    end

    _, headers, _ = response(app, env_for('foo=client; baz="client value"'))

    headers["preference-applied"].must_equal 'foo=bar; baz="a;b"'
  end

  it "handles a frozen response and headers" do
    body = CloseTrackingBody.new
    original_headers = {
      "content-type" => "application/json",
      "preference-applied" => "return=representation"
    }.freeze
    app = lambda do |env|
      Rack::Request.new(env).prefer(:return, :minimal)
      [201, original_headers, body].freeze
    end

    status, headers, response_body = Rack::Prefer.new(app).call(env_for("return=minimal"))

    status.must_equal 201
    headers.wont_be :frozen?
    headers["preference-applied"].must_equal "return=minimal"
    headers.wont_include "content-type"
    response_body.to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "removes entity headers for a minimal 204 response" do
    body = CloseTrackingBody.new
    app = lambda do |env|
      Rack::Request.new(env).prefer(:return, :minimal)
      [204, {
        "content-type" => "application/json",
        "content-length" => "6",
        "content-encoding" => "identity",
        "content-range" => "bytes 0-5/6",
        "transfer-encoding" => "chunked",
        "etag" => '"v1"'
      }, body]
    end

    status, headers, response_body = response(app, env_for("return=minimal"))

    status.must_equal 204
    headers["preference-applied"].must_equal "return=minimal"
    headers["etag"].must_equal '"v1"'
    headers.wont_include "content-type"
    headers.wont_include "content-length"
    headers.wont_include "content-encoding"
    headers.wont_include "content-range"
    headers.wont_include "transfer-encoding"
    response_body.to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "works with Rack::Head for a minimal HEAD request" do
    body = CloseTrackingBody.new
    app = lambda do |env|
      Rack::Request.new(env).prefer(:return, :minimal)
      [200, {
        "content-type" => "text/plain",
        "content-length" => "6"
      }, body]
    end
    middleware = Rack::Lint.new(Rack::Prefer.new(Rack::Head.new(app)))

    status, headers, response_body = middleware.call(env_for("return=minimal", "HEAD"))

    status.must_equal 200
    headers["preference-applied"].must_equal "return=minimal"
    headers["content-type"].must_equal "text/plain"
    headers["content-length"].must_equal "6"
    response_body.to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "handles a minimal HEAD request without Rack::Head" do
    body = CloseTrackingBody.new
    app = lambda do |env|
      Rack::Request.new(env).prefer(:return, :minimal)
      [200, {
        "content-type" => "text/plain",
        "content-length" => "6"
      }, body]
    end

    status, headers, response_body = Rack::Prefer.new(app).call(env_for("return=minimal", "HEAD"))

    status.must_equal 200
    headers["preference-applied"].must_equal "return=minimal"
    headers["content-type"].must_equal "text/plain"
    headers["content-length"].must_equal "6"
    response_body.must_equal []
    body.must_be :closed?
  end

  it "closes a response body that has been rewrapped by another middleware" do
    inner_body = CloseTrackingBody.new
    wrapped_body = Rack::BodyProxy.new(inner_body) {}
    app = lambda do |env|
      Rack::Request.new(env).prefer(:return, :minimal)
      [201, {"content-type" => "application/json"}, wrapped_body]
    end

    _, _, response_body = Rack::Prefer.new(app).call(env_for("return=minimal"))

    response_body.must_equal []
    wrapped_body.must_be :closed?
    inner_body.must_be :closed?
  end
end
