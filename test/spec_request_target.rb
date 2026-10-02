# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/request_target'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
end

describe Rack::RequestTarget do
  def response(target = "/", options = {}, env_options = {})
    env = Rack::MockRequest.env_for("/", env_options)
    env["REQUEST_URI"] = target unless env_options.key?("REQUEST_URI")
    env["PATH_INFO"] = target.split("?", 2).first if target.start_with?("/")
    app = lambda do |request_env|
      [200, { "content-type" => "text/plain" }, [
        request_env["PATH_INFO"],
        "|",
        request_env["rack.request_target"],
        "|",
        request_env["rack.request_target.source"].to_s
      ]]
    end
    middleware = Rack::RequestTarget.new(Rack::Lint.new(app), **options)
    middleware.call(env)
  end

  def body(target = "/", options = {}, env_options = {})
    response(target, options, env_options)[2].to_enum.to_a.join
  end

  it "preserves valid encoded UTF-8 paths and records the raw request target" do
    status, _, parts = response("/caf%C3%A9?q=1")

    status.must_equal 200
    parts.to_enum.to_a.join.must_equal "/caf%C3%A9|/caf%C3%A9?q=1|REQUEST_URI"
  end

  it "accepts direct UTF-8 path bytes without decoding the path" do
    target = "/caf\u00e9".b
    status, _, parts = response(target)

    status.must_equal 200
    parts.to_enum.to_a.join.must_equal "#{target}|#{target}|REQUEST_URI"
  end

  it "does not apply path checks to the query string" do
    target = "/search?q=%2F..%5C%252F&x=%E3"
    status, _, parts = response(target)

    status.must_equal 200
    parts.to_enum.to_a.must_include target
  end

  {
    "/a%2Fb" => [:encoded_slash_not_allowed, "a%2Fb"],
    "/a%5Cb" => [:backslash_not_allowed, "a%5Cb"],
    "/a/\\b" => [:backslash_not_allowed, "\\b"],
    "/a/.." => [:dot_segment_not_allowed, ".."],
    "/a/%2E%2E" => [:dot_segment_not_allowed, "%2E%2E"],
    "/a/%252F" => [:double_percent_encoding_not_allowed, "%252F"]
  }.each do |target, (reason, segment)|
    it "rejects #{reason} in path segment #{segment}" do
      status, headers, parts = response(target)
      text = parts.to_enum.to_a.join

      status.must_equal 400
      headers["x-request-target-error"].must_equal reason.to_s.tr("_", "-")
      text.must_include "Reason:"
      text.must_include "Component: path"
      expected_index = target.start_with?("/a/") ? 2 : 1
      text.must_include "Segment index: #{expected_index}"
      text.must_include "Segment: #{segment.b.dump}"
      text.must_include "Request target: #{target.b.dump}"
    end
  end

  it "rejects invalid UTF-8 in a decoded path segment" do
    status, headers, parts = response("/caf%E3")
    text = parts.to_enum.to_a.join

    status.must_equal 400
    headers["x-request-target-error"].must_equal "invalid-utf8"
    text.must_include "Component: path"
    text.must_include "Segment: \"caf%E3\""
  end

  it "rejects malformed percent sequences in the path" do
    status, headers, parts = response("/100%")
    text = parts.to_enum.to_a.join

    status.must_equal 400
    headers["x-request-target-error"].must_equal "invalid-percent-sequence"
    text.must_include "Segment: \"100%\""
  end

  it "allows each configured ambiguity independently" do
    targets = [
      "/a%2Fb",
      "/a%5Cb",
      "/a/..",
      "/a/%252F"
    ]
    options = {
      encoded_slash: :allow,
      backslash: :allow,
      dot_segments: :allow,
      double_percent_encoding: :allow
    }

    targets.each do |target|
      status, = response(target, options)
      status.must_equal 200
    end
  end

  it "keeps repeated encoding separate from encoded slash checks" do
    status, = response("/a/%252F", encoded_slash: :reject, double_percent_encoding: :allow)
    status.must_equal 200

    status, = response("/a/%2F", encoded_slash: :allow, double_percent_encoding: :reject)
    status.must_equal 200

    status, headers, parts = response("/a/%25%32%46")
    text = parts.to_enum.to_a.join
    status.must_equal 400
    headers["x-request-target-error"].must_equal "double-percent-encoding-not-allowed"
    text.must_include "Segment: \"%25%32%46\""

    status, = response("/a/%25%32%46", double_percent_encoding: :allow)
    status.must_equal 200
  end

  it "validates the configured mount prefix and the remaining path separately" do
    status, _, parts = response("/admin/users/a%2Fb", mount_prefix: "/admin")
    text = parts.to_enum.to_a.join

    status.must_equal 400
    text.must_include "Component: path"
    text.must_include "Segment index: 1"
    text.must_include "Segment: \"a%2Fb\""

    status, = response("/admin/users", mount_prefix: "/admin")
    status.must_equal 200

    status, _, parts = response("/adminx/users", mount_prefix: "/admin")
    text = parts.to_enum.to_a.join
    status.must_equal 400
    text.must_include "Component: mount-prefix"
  end

  it "uses SCRIPT_NAME as the mount prefix when mount_prefix is true" do
    env = Rack::MockRequest.env_for("/", "SCRIPT_NAME" => "/admin")
    env["REQUEST_URI"] = "/admin/users"
    env["PATH_INFO"] = "/admin/users"
    app = proc { [200, { "content-type" => "text/plain" }, ["ok"]] }
    status, = Rack::RequestTarget.new(Rack::Lint.new(app), mount_prefix: true).call(env)

    status.must_equal 200
  end

  it "rejects absolute-form targets and reports the absolute-form component" do
    status, headers, parts = response("http://example.com/users/a%2Fb")
    text = parts.to_enum.to_a.join

    status.must_equal 400
    headers["x-request-target-error"].must_equal "absolute-form-not-allowed"
    text.must_include "Component: absolute-form"
    text.must_include "http://example.com/users/a%2Fb"
  end

  it "can allow absolute-form targets while still validating their path" do
    status, = response("http://example.com/users/a%2Fb", absolute_form: :allow)
    status.must_equal 400

    status, = response("http://example.com/users", absolute_form: :allow)
    status.must_equal 200
  end

  it "reports malformed absolute-form targets structurally" do
    status, headers, parts = response("http://example.com/a%zz", absolute_form: :allow)
    text = parts.to_enum.to_a.join

    status.must_equal 400
    headers["x-request-target-error"].must_equal "invalid-request-target-form"
    text.must_include "Component: absolute-form"
  end

  it "accepts asterisk form only for OPTIONS and authority form only for CONNECT" do
    status, = response("*", {}, "REQUEST_METHOD" => "OPTIONS")
    status.must_equal 200

    status, = response("*", {}, "REQUEST_METHOD" => "GET")
    status.must_equal 400

    status, = response("example.com:443", {}, "REQUEST_METHOD" => "CONNECT")
    status.must_equal 200

    status, = response("example.com:443", {}, "REQUEST_METHOD" => "GET")
    status.must_equal 400
  end

  it "rejects request targets containing fragments" do
    status, headers, parts = response("/users#a%2Fb")
    text = parts.to_enum.to_a.join

    status.must_equal 400
    headers["x-request-target-error"].must_equal "request-target-contains-fragment"
    text.must_include "Component: fragment"
  end

  it "rejects missing raw request targets by default" do
    env = Rack::MockRequest.env_for("/")
    env.delete("REQUEST_URI")
    app = proc { [200, { "content-type" => "text/plain" }, ["ok"]] }
    status, headers, parts = Rack::RequestTarget.new(app).call(env)
    text = parts.to_enum.to_a.join

    status.must_equal 400
    headers["x-request-target-error"].must_equal "missing-request-target"
    text.must_include "request target is not available"
  end

  it "passes and warns when missing request targets are explicitly allowed" do
    errors = StringIO.new
    env = Rack::MockRequest.env_for("/", "rack.errors" => errors)
    env.delete("REQUEST_URI")
    app = lambda do |request_env|
      [200, { "content-type" => "text/plain" }, [request_env["rack.request_target.source"].to_s]]
    end
    status, _, parts = Rack::RequestTarget.new(
      app,
      missing_request_target: :pass
    ).call(env)

    status.must_equal 200
    parts.to_enum.to_a.join.must_equal "missing"
    errors.string.must_include "request target checks were skipped"
  end

  it "reconstructs a REQUEST_PATH target with QUERY_STRING and preserves PATH_INFO" do
    env = Rack::MockRequest.env_for("/users/a%2Fb?q=%2F")
    env.delete("REQUEST_URI")
    env["REQUEST_PATH"] = "/users/a%2Fb"
    env["PATH_INFO"] = "/users/a%2Fb"
    app = lambda do |request_env|
      [200, { "content-type" => "text/plain" }, [
        request_env["rack.request_target"],
        "|",
        request_env["rack.request_target.source"]
      ]]
    end
    status, _, parts = Rack::RequestTarget.new(
      app,
      encoded_slash: :allow
    ).call(env)

    status.must_equal 200
    parts.to_enum.to_a.join.must_equal "/users/a%2Fb?q=%2F|REQUEST_PATH+QUERY_STRING"
  end

  it "provides a direct checker that raises structured errors" do
    error = assert_raises(Rack::RequestTarget::InvalidRequestTarget) do
      Rack::RequestTarget.check("/admin/a%2Fb?x=..", mount_prefix: "/admin")
    end

    error.code.must_equal :encoded_slash_not_allowed
    error.component.must_equal "path"
    error.segment.must_equal "a%2Fb"
    error.segment_index.must_equal 0
    error.target.must_equal "/admin/a%2Fb?x=.."
  end

  it "supports a custom invalid target handler" do
    handler = lambda do |error|
      [400, { "content-type" => "text/plain" }, [error.code.to_s]]
    end
    status, _, parts = response("/a%2Fb", on_invalid: handler)

    status.must_equal 400
    parts.to_enum.to_a.join.must_equal "encoded_slash_not_allowed"
  end
end
