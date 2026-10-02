# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/request_target_validator'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
end

describe Rack::RequestTargetValidator do
  def build_app(**options, &inner)
    inner ||= lambda { |env| [200, { 'content-type' => 'text/plain' }, ['OK']] }
    Rack::Lint.new(Rack::RequestTargetValidator.new(inner, **options))
  end

  def env_for(target, **opts)
    Rack::MockRequest.env_for('/', 'REQUEST_URI' => target, **opts)
  end

  def body_of(response)
    chunks = []
    response[2].each { |chunk| chunks << chunk }
    chunks.join
  end

  it "passes a plain request through and stores the raw target" do
    env = env_for('/a/b?x=1')
    status, = build_app.call(env)
    status.must_equal 200
    env['rack.request_target'].must_equal '/a/b?x=1'
  end

  it "does not rewrite PATH_INFO, SCRIPT_NAME or QUERY_STRING" do
    seen = nil
    app = build_app { |env| seen = env.dup; [200, { 'content-type' => 'text/plain' }, []] }
    env = Rack::MockRequest.env_for('/caf%C3%A9?q=%2F', 'REQUEST_URI' => '/caf%C3%A9?q=%2F')
    app.call(env)
    seen[Rack::PATH_INFO].must_equal '/caf%C3%A9'
    seen[Rack::SCRIPT_NAME].must_equal ''
    seen[Rack::QUERY_STRING].must_equal 'q=%2F'
  end

  it "rejects percent-encoded slashes and reports the offending segment" do
    env = env_for('/files/a%2Fb')
    response = build_app.call(env)
    status = response[0]
    body = body_of(response)
    status.must_equal 400
    body.must_include 'encoded_slash'
    body.must_include '"a%2Fb"'

    rejection = env['rack.request_target_validator.rejection']
    rejection.rule.must_equal :encoded_slash
    rejection.segment.must_equal 'a%2Fb'
    rejection.segment_index.must_equal 1
    rejection.target.must_equal '/files/a%2Fb'

    build_app.call(env_for('/FILES/A%2fb'))[0].must_equal 400
  end

  it "allows encoded slashes when configured" do
    build_app(encoded_slash: :allow).call(env_for('/files/a%2Fb'))[0].must_equal 200
  end

  it "rejects literal and percent-encoded backslashes" do
    env = env_for('/files\\..\\secret')
    status, _, body = build_app.call(env)
    status.must_equal 400
    env['rack.request_target_validator.rejection'].rule.must_equal :backslash

    build_app.call(env_for('/files%5Csecret'))[0].must_equal 400
    build_app.call(env_for('/files%5csecret'))[0].must_equal 400
    build_app(backslash: :allow).call(env_for('/files%5Csecret'))[0].must_equal 200
  end

  it "rejects dot segments in raw and singly encoded forms" do
    ['/a/../b', '/a/./b', '/a/%2e%2e/b', '/a/%2E/b', '/a/.%2e/b', '/a/%2e./b'].each do |target|
      env = env_for(target)
      status, = build_app.call(env)
      status.must_equal 400, "expected #{target} to be rejected"
      env['rack.request_target_validator.rejection'].rule.must_equal :dot_segments
    end
    build_app(dot_segments: :allow).call(env_for('/a/../b'))[0].must_equal 200
  end

  it "allows segments that merely contain dots" do
    ['/.well-known/openid-configuration', '/foo..bar', '/a.b', '/...'].each do |target|
      build_app.call(env_for(target))[0].must_equal 200, "expected #{target} to pass"
    end
  end

  it "rejects repeated percent-encoding" do
    env = env_for('/files/%252Fetc')
    status, = build_app.call(env)
    status.must_equal 400
    env['rack.request_target_validator.rejection'].rule.must_equal :double_encoding

    build_app.call(env_for('/a/%25252e/b'))[0].must_equal 400
    build_app(double_encoding: :allow).call(env_for('/files/%252Fetc'))[0].must_equal 200
  end

  it "reports multiply encoded dot segments as double_encoding" do
    env = env_for('/a/%252e%252e/b')
    build_app.call(env)
    rejection = env['rack.request_target_validator.rejection']
    rejection.rule.must_equal :double_encoding
    rejection.segment.must_equal '%252e%252e'
  end

  it "allows percent-encoded and raw UTF-8 paths" do
    ['/caf%C3%A9', '/%E6%97%A5%E6%9C%AC', '/100%25off'].each do |target|
      build_app.call(env_for(target))[0].must_equal 200, "expected #{target} to pass"
    end
    build_app.call(env_for("/caf\u00e9".b))[0].must_equal 200
  end

  it "does not apply path rules to the query string" do
    env = env_for('/search?q=%2F%5C..%252F&next=/a/../b')
    status, = build_app.call(env)
    status.must_equal 200
    env['rack.request_target'].must_equal '/search?q=%2F%5C..%252F&next=/a/../b'
  end

  it "validates the path of absolute-form targets and ignores the query" do
    env = env_for('http://example.org/a/%2F/b?x=%2F')
    status, = build_app.call(env)
    status.must_equal 400
    rejection = env['rack.request_target_validator.rejection']
    rejection.rule.must_equal :encoded_slash
    rejection.segment.must_equal '%2F'
    rejection.segment_index.must_equal 1

    build_app.call(env_for('http://example.org/a/b?x=%2F%5C..%252F'))[0].must_equal 200
    build_app.call(env_for('http://example.org'))[0].must_equal 200
  end

  it "reports segment indexes within a mount prefix" do
    env = env_for('/app/../secret', script_name: '/app')
    status, = build_app.call(env)
    status.must_equal 400
    rejection = env['rack.request_target_validator.rejection']
    rejection.rule.must_equal :dot_segments
    rejection.segment.must_equal '..'
    rejection.segment_index.must_equal 1

    env = env_for('/app/files/%252Fetc', script_name: '/app')
    build_app.call(env)
    rejection = env['rack.request_target_validator.rejection']
    rejection.rule.must_equal :double_encoding
    rejection.segment.must_equal '%252Fetc'
    rejection.segment_index.must_equal 2

    build_app.call(env_for('/app/files/report.pdf', script_name: '/app'))[0].must_equal 200
  end

  it "falls back to REQUEST_PATH when REQUEST_URI is missing" do
    env = Rack::MockRequest.env_for('/', 'REQUEST_PATH' => '/a/%2F/b')
    status, = build_app.call(env)
    status.must_equal 400
    env['rack.request_target'].must_equal '/a/%2F/b'
  end

  it "prefers REQUEST_URI over REQUEST_PATH" do
    env = Rack::MockRequest.env_for('/',
      'REQUEST_URI' => '/ok', 'REQUEST_PATH' => '/a/%2F/b')
    build_app.call(env)[0].must_equal 200
    env['rack.request_target'].must_equal '/ok'
  end

  it "passes the request through when no raw target is available by default" do
    env = Rack::MockRequest.env_for('/')
    status, = build_app.call(env)
    status.must_equal 200
    env['rack.request_target'].must_be_nil
  end

  it "rejects when no raw target is available and fallback is :reject" do
    env = Rack::MockRequest.env_for('/')
    status, _, body = build_app(fallback: :reject).call(env)
    status.must_equal 400
    body_of([status, _, body]).must_include 'no raw request target'
    env['rack.request_target_validator.rejection'].rule.must_equal :missing_target
  end

  it "allows asterisk-form targets" do
    env = env_for('*', method: 'OPTIONS')
    build_app.call(env)[0].must_equal 200
  end

  it "invokes on_reject with the env and rejection" do
    captured = nil
    on_reject = lambda do |env, rejection|
      captured = [env, rejection]
      [403, { 'content-type' => 'text/plain' }, ['custom']]
    end
    env = env_for('/a/../b')
    status, _, body = build_app(on_reject: on_reject).call(env)
    status.must_equal 403
    body_of([status, _, body]).must_equal 'custom'
    captured[0].must_equal env
    captured[1].rule.must_equal :dot_segments
  end

  it "raises ArgumentError for invalid actions" do
    lambda { build_app(encoded_slash: :strip) }.must_raise ArgumentError
    lambda { build_app(fallback: :decode) }.must_raise ArgumentError
  end
end
