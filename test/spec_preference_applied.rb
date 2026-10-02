# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/preference_applied'
  require_relative '../lib/rack/body_proxy'
  require_relative '../lib/rack/head'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/request'
end

describe Rack::PreferenceApplied do
  # A response body that records whether it was closed, used to show
  # the two return forms: with return=minimal the body is closed and
  # discarded, with return=representation it is left intact.
  class CloseRecordingBody
    def initialize(*chunks)
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

  def build_app(inner)
    Rack::Lint.new(Rack::PreferenceApplied.new(inner))
  end

  def request(prefer = nil, method: 'POST')
    headers = { 'REQUEST_METHOD' => method }
    headers['HTTP_PREFER'] = prefer if prefer
    Rack::MockRequest.env_for('/resource', headers)
  end

  it "does nothing when no preferences were applied" do
    body = CloseRecordingBody.new('full representation')
    inner = lambda do |env|
      [201, { 'content-type' => 'text/plain', 'location' => '/resource/1' }, body]
    end
    response = build_app(inner).call(request('return=minimal'))

    response[0].must_equal 201
    response[1].must_equal 'content-type' => 'text/plain', 'location' => '/resource/1'
    response[2].to_enum.to_a.must_equal ['full representation']
    body.wont_be :closed?
  end

  it "does not echo the client Prefer header back" do
    inner = lambda do |env|
      [200, {}, []]
    end
    response = build_app(inner).call(request('return=minimal, respond-async'))

    response[1].wont_include 'preference-applied'
  end

  it "returns status and metadata only when return=minimal is applied" do
    body = CloseRecordingBody.new('full representation')
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [201, {
        'content-type' => 'application/json',
        'content-length' => '20',
        'etag' => '"abc"',
        'last-modified' => 'Thu, 01 Oct 2026 00:00:00 GMT',
        'location' => '/resource/1',
      }, body]
    end
    response = build_app(inner).call(request('return=minimal'))

    response[0].must_equal 201
    response[1].must_equal 'location' => '/resource/1',
      'preference-applied' => 'return=minimal'
    response[2].to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "keeps the full representation when return=representation is applied" do
    body = CloseRecordingBody.new('full representation')
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [200, { 'content-type' => 'text/plain', 'content-length' => '19' }, body]
    end
    response = build_app(inner).call(request('return=representation'))

    response[0].must_equal 200
    response[1].must_equal 'content-type' => 'text/plain',
      'content-length' => '19',
      'preference-applied' => 'return=representation'
    response[2].to_enum.to_a.must_equal ['full representation']
    body.wont_be :closed?
  end

  it "resolves conflicting return values in favor of the first" do
    body = CloseRecordingBody.new('full representation')
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [200, { 'content-type' => 'text/plain' }, body]
    end
    response = build_app(inner).call(request('return=minimal, return=representation'))

    response[1]['preference-applied'].must_equal 'return=minimal'
    response[1].wont_include 'content-type'
    response[2].to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "emits unknown preferences the application applied" do
    body = CloseRecordingBody.new('full representation')
    inner = lambda do |env|
      env['rack.preferences'].apply('respond-async')
      env['rack.preferences'].apply('wait')
      [202, { 'content-type' => 'text/plain' }, body]
    end
    response = build_app(inner).call(request('respond-async, wait="10"'))

    response[1]['preference-applied'].must_equal 'respond-async, wait=10'
    response[1]['content-type'].must_equal 'text/plain'
    response[2].to_enum.to_a.must_equal ['full representation']
    body.wont_be :closed?
  end

  it "ignores applied preferences that were not requested" do
    inner = lambda do |env|
      env['rack.preferences'].apply('respond-async').must_equal false
      env['rack.preferences'].apply('return', 'representation').must_equal false
      [200, {}, []]
    end
    response = build_app(inner).call(request('return=minimal'))

    response[1].wont_include 'preference-applied'
  end

  it "works with frozen response headers" do
    body = CloseRecordingBody.new('full representation')
    headers = { 'content-type' => 'text/plain', 'location' => '/resource/1' }.freeze
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [201, headers, body]
    end
    response = build_app(inner).call(request('return=minimal'))

    response[0].must_equal 201
    response[1].must_equal 'location' => '/resource/1',
      'preference-applied' => 'return=minimal'
    response[2].to_enum.to_a.must_equal []
    headers.must_equal 'content-type' => 'text/plain', 'location' => '/resource/1'
    body.must_be :closed?
  end

  it "works for HEAD requests" do
    body = CloseRecordingBody.new('full representation')
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [200, { 'content-type' => 'text/plain', 'content-length' => '20' }, body]
    end
    stack = Rack::Lint.new(Rack::Head.new(Rack::PreferenceApplied.new(inner)))
    response = stack.call(request('return=minimal', method: 'HEAD'))

    response[0].must_equal 200
    response[1]['preference-applied'].must_equal 'return=minimal'
    response[2].to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "works for 204 responses" do
    body = CloseRecordingBody.new
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [204, {}, body]
    end
    response = build_app(inner).call(request('return=minimal'))

    response[0].must_equal 204
    response[1].must_equal 'preference-applied' => 'return=minimal'
    response[2].to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "closes the original body when it was re-wrapped by middleware" do
    body = CloseRecordingBody.new('full representation')
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [200, { 'content-type' => 'text/plain' }, body]
    end
    wrapper = lambda do |app|
      lambda do |env|
        status, headers, wrapped = app.call(env)
        [status, headers, Rack::BodyProxy.new(wrapped) {}]
      end
    end
    response = build_app(wrapper.call(inner)).call(request('return=minimal'))

    response[1]['preference-applied'].must_equal 'return=minimal'
    response[2].to_enum.to_a.must_equal []
    body.must_be :closed?
  end

  it "merges with a preference-applied header set by the application" do
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [200, { 'preference-applied' => 'respond-async' }, []]
    end
    response = build_app(inner).call(request('return=minimal, respond-async'))

    response[1]['preference-applied'].must_equal 'respond-async, return=minimal'
  end

  it "does not duplicate preferences already present in the response header" do
    inner = lambda do |env|
      env['rack.preferences'].apply('return')
      [200, { 'preference-applied' => 'return=minimal' }, []]
    end
    response = build_app(inner).call(request('return=minimal'))

    response[1]['preference-applied'].must_equal 'return=minimal'
  end

  it "shares the parsed preferences with Rack::Request" do
    inner = lambda do |env|
      request = Rack::Request.new(env)
      request.preferences.must_be_same_as env['rack.preferences']
      request.preferences.apply('return')
      [200, {}, []]
    end
    response = build_app(inner).call(request('return=minimal'))

    response[1]['preference-applied'].must_equal 'return=minimal'
  end
end
