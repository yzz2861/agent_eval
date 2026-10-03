# frozen_string_literal: true

# Released under the MIT License.

require_relative 'helper'

require 'rack/mock'
require 'rack/response'
require 'securerandom'

require_relative '../lib/rack/session'

class FakeClock
  attr_accessor :current

  def initialize(current = 1000)
    @current = current.to_f
  end

  def now
    @current
  end

  def call
    @current
  end

  def advance(seconds)
    @current += seconds
  end

  def rollback(seconds)
    @current -= seconds
  end
end

class SessionLifetimeTestCase < Minitest::Spec
  IDLE_TIMEOUT = 20 * 60
  ABSOLUTE_TIMEOUT = 8 * 60 * 60
  TEST_APP = lambda do |env|
    session = env['rack.session']

    if env['rack.session.lifetime.app'] == :reader
      body = session.key?('counter') ? "counter=#{session['counter']}" : 'fresh'
    else
      session['counter'] = session['counter'].to_i + 1
      body = session.to_hash.inspect
    end

    Rack::Response.new(body).to_a
  end

  def self.runnable_methods
    name == 'SessionLifetimeTestCase' ? [] : super
  end

  def request(store, action = :increment, cookie = nil, **request_options)
    mock = Rack::MockRequest.new(store)
    app_header = action == :reader ? { 'rack.session.lifetime.app' => :reader } : {}
    mock.get('/', request_options.merge(app_header).merge('HTTP_COOKIE' => cookie || ''))
  end

  def counter(response)
    response.body[/"counter"\s*=>\s*(\d+)/, 1]&.to_i
  end

  def cookie_value(response)
    response['Set-Cookie']&.[](/rack\.session=([^;]+)/) { "rack.session=#{$1}" }
  end

  def create_counter_session(store)
    response = request(store)
    cookie_value(response)
  end

  def expect_new_cookie?(response, old_cookie)
    response['Set-Cookie'].wont_equal old_cookie
  end

  it 'creates a server timestamp with a fake clock' do
    clock = FakeClock.new(1000)
    store = make_store(clock: clock)

    response = request(store)
    response['Set-Cookie'].wont_be_nil
    counter(response).must_equal 1
  end

  it 'keeps an active session alive immediately before the idle limit' do
    clock = FakeClock.new(1000)
    store = make_store(clock: clock, idle_timeout: IDLE_TIMEOUT)
    cookie = create_counter_session(store)

    clock.advance(IDLE_TIMEOUT - 1)
    response = request(store, :increment, cookie)

    counter(response).must_equal 2
  end

  it 'expires an idle session at exactly the idle limit' do
    clock = FakeClock.new(1000)
    store = make_store(clock: clock, idle_timeout: IDLE_TIMEOUT)
    cookie = create_counter_session(store)

    clock.advance(IDLE_TIMEOUT)
    response = request(store, :increment, cookie)

    counter(response).must_equal 1
    expect_new_cookie?(response, cookie)
  end

  it 'slides the idle deadline on ordinary activity' do
    clock = FakeClock.new(1000)
    store = make_store(clock: clock, idle_timeout: IDLE_TIMEOUT)
    cookie = create_counter_session(store)

    clock.advance(IDLE_TIMEOUT - 1)
    response = request(store, :increment, cookie)
    counter(response).must_equal 2
    cookie = response['Set-Cookie'] || cookie

    clock.advance(IDLE_TIMEOUT - 1)
    response = request(store, :increment, cookie)
    counter(response).must_equal 3
  end

  it 'allows a polling request to read a session but not renew idleness' do
    clock = FakeClock.new(1000)
    store = make_store(clock: clock, idle_timeout: IDLE_TIMEOUT)
    cookie = create_counter_session(store)

    clock.advance(IDLE_TIMEOUT - 1)
    response = request(store, :reader, cookie,
      Rack::Session::RACK_SESSION_SKIP_IDLE_RENEWAL => true
    )
    response.body.must_include 'counter'
    cookie = response['Set-Cookie'] || cookie

    clock.advance(1)
    response = request(store, :increment, cookie)
    counter(response).must_equal 1
    expect_new_cookie?(response, cookie)
  end

  it 'keeps an active session alive immediately before the absolute limit' do
    clock = FakeClock.new(1000)
    store = make_store(
      clock: clock,
      idle_timeout: IDLE_TIMEOUT,
      absolute_timeout: ABSOLUTE_TIMEOUT
    )
    cookie = create_counter_session(store)

    48.times do
      clock.advance(600 - 1)
      response = request(store, :increment, cookie)
      counter(response).must_be :>, 1
      cookie = response['Set-Cookie'] || cookie
    end

    clock.advance(ABSOLUTE_TIMEOUT - 48 * (600 - 1) - 1)
    response = request(store, :increment, cookie)
    counter(response).must_equal 50
  end

  it 'requires reauthentication at exactly the absolute limit despite activity' do
    clock = FakeClock.new(1000)
    store = make_store(
      clock: clock,
      idle_timeout: IDLE_TIMEOUT,
      absolute_timeout: ABSOLUTE_TIMEOUT
    )
    cookie = create_counter_session(store)

    clock.advance(IDLE_TIMEOUT - 1)
    response = request(store, :increment, cookie)
    counter(response).must_equal 2
    cookie = response['Set-Cookie'] || cookie

    clock.advance(ABSOLUTE_TIMEOUT - (IDLE_TIMEOUT - 1))
    response = request(store, :increment, cookie)
    counter(response).must_equal 1
    expect_new_cookie?(response, cookie)
  end

  it 'does not widen the idle deadline after a clock rollback' do
    clock = FakeClock.new(1000)
    store = make_store(clock: clock, idle_timeout: IDLE_TIMEOUT)
    cookie = create_counter_session(store)

    clock.advance(1000)
    response = request(store, :increment, cookie)
    counter(response).must_equal 2
    cookie = response['Set-Cookie'] || cookie

    clock.rollback(1000)
    response = request(store, :increment, cookie)
    counter(response).must_equal 3
    cookie = response['Set-Cookie'] || cookie

    clock.advance(IDLE_TIMEOUT)
    response = request(store, :increment, cookie)
    counter(response).must_equal 1
    expect_new_cookie?(response, cookie)
  end

  it 'does not hand expired data to the application' do
    clock = FakeClock.new(1000)
    store = make_store(clock: clock, idle_timeout: IDLE_TIMEOUT)
    cookie = create_counter_session(store)

    clock.advance(IDLE_TIMEOUT)
    response = request(store, :reader, cookie)

    response.body.must_equal 'fresh'
  end
end

class PoolLifetimeTest < SessionLifetimeTestCase

  def make_store(**options)
    Rack::Session::Pool.new(TEST_APP, options)
  end

  it 'stores server timestamps outside application data' do
    store = make_store(
      clock: FakeClock.new,
      idle_timeout: IDLE_TIMEOUT,
      absolute_timeout: ABSOLUTE_TIMEOUT
    )

    response = request(store, :reader)
    response.body.wont_include 'rack_session'
  end
end

class CookieLifetimeTest < SessionLifetimeTestCase

  def secret
    @secret ||= SecureRandom.random_bytes(64)
  end

  def make_store(**options)
    Rack::Session::Cookie.new(TEST_APP, { secrets: secret }.merge(options))
  end

  it 'throttles cookie renewal without widening expiry' do
    clock = FakeClock.new(1000)
    store = make_store(
      clock: clock,
      idle_timeout: IDLE_TIMEOUT,
      renew_cookie_after: 60
    )

    cookie = create_counter_session(store)
    clock.advance(30)
    response = request(store, :reader, cookie)
    response['Set-Cookie'].must_be_nil

    clock.advance(IDLE_TIMEOUT - 30)
    response = request(store, :increment, cookie)
    counter(response).must_equal 1
  end

  it 'renews a throttled cookie after the throttle interval' do
    clock = FakeClock.new(1000)
    store = make_store(
      clock: clock,
      idle_timeout: IDLE_TIMEOUT,
      renew_cookie_after: 60
    )

    cookie = create_counter_session(store)
    clock.advance(61)
    response = request(store, :increment, cookie)

    response['Set-Cookie'].wont_be_nil
  end

  it 'does not trust a future timestamp in an unsigned cookie' do
    clock = FakeClock.new(1000)
    store = Rack::Session::Cookie.new(TEST_APP,
      coder: Rack::Session::Cookie::Base64::JSON.new,
      let_coder_handle_secure_encoding: true,
      clock: clock,
      idle_timeout: IDLE_TIMEOUT
    )

    payload = {
      'session_id' => SecureRandom.hex(32),
      'counter' => 99,
      Rack::Session::Cookie::CREATED_AT_KEY => 1000.0,
      Rack::Session::Cookie::LAST_ACCESSED_AT_KEY => 1000.0 + IDLE_TIMEOUT * 10
    }
    encoded = [Rack::Session::Cookie::Base64::JSON.new.encode(payload)].pack('m0').strip
    cookie = "#{Rack::Session::Cookie::DEFAULT_OPTIONS[:key]}=#{encoded}"

    response = request(store, :increment, cookie)
    counter(response).must_equal 1
  end
end
