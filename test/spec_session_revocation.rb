# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative 'helper'
require 'rack/response'
require 'rack/lint'
require 'rack/mock'

require_relative '../lib/rack/session/cookie'

describe Rack::Session::Revocation::Memory do
  it 'defaults the generation of unknown subjects to 0' do
    store = Rack::Session::Revocation::Memory.new
    store.current_generation("alice").must_equal 0
  end

  it 'increments the generation on revoke and returns the new value' do
    store = Rack::Session::Revocation::Memory.new
    store.revoke!("alice").must_equal 1
    store.revoke!("alice").must_equal 2
    store.current_generation("alice").must_equal 2
    store.current_generation("bob").must_equal 0
  end

  it 'increments atomically under concurrent revocation' do
    store = Rack::Session::Revocation::Memory.new
    threads = 10.times.map do
      Thread.new { 100.times { store.revoke!("alice") } }
    end
    threads.each(&:join)
    store.current_generation("alice").must_equal 1000
  end
end

describe 'Rack::Session::Cookie revocation' do
  whoami = lambda do |env|
    Rack::Response.new(env["rack.session"]["user_id"].inspect).to_a
  end

  login_alice = lambda do |env|
    env["rack.session"]["user_id"] = "alice"
    Rack::Response.new("logged in").to_a
  end

  switch_to_bob = lambda do |env|
    env["rack.session"]["user_id"] = "bob"
    Rack::Response.new("switched").to_a
  end

  incrementor = lambda do |env|
    env["rack.session"]["counter"] ||= 0
    env["rack.session"]["counter"] += 1
    Rack::Response.new(env["rack.session"]["counter"].to_s).to_a
  end

  echo_errors = lambda do |env|
    env["rack.session"]["user_id"]
    Rack::Response.new(env[Rack::RACK_ERRORS].flush.tap(&:rewind).read).to_a
  end

  # A store wrapper that records how often the generation was read.
  counting_store = lambda do |inner|
    Class.new(Rack::Session::Revocation::Store) do
      attr_reader :reads

      def initialize(inner)
        @inner = inner
        @reads = 0
      end

      def current_generation(subject)
        @reads += 1
        @inner.current_generation(subject)
      end

      def revoke!(subject)
        @inner.revoke!(subject)
      end
    end.new(inner)
  end

  # A store that always fails.
  failing_store = Class.new(Rack::Session::Revocation::Store) do
    def current_generation(subject)
      raise Rack::Session::Revocation::Error, "storage is down"
    end

    def revoke!(subject)
      raise Rack::Session::Revocation::Error, "storage is down"
    end
  end.new

  def response_for(options = {})
    request_options = options.fetch(:request, {})
    cookie = if options[:cookie].is_a?(Rack::Response)
      options[:cookie]["Set-Cookie"]
    else
      options[:cookie]
    end
    request_options["HTTP_COOKIE"] = cookie || ""

    app_with_cookie = Rack::Session::Cookie.new(*options[:app])
    app_with_cookie = Rack::Lint.new(app_with_cookie)
    Rack::MockRequest.new(app_with_cookie).get("/", request_options)
  end

  def decrypt_cookie(response)
    value = response["Set-Cookie"].split('=', 2).last.split(';').first
    encryptor = Rack::Session::Encryptor.new(@secret)
    encryptor.decrypt(Rack::Utils.unescape(value))
  end

  before do
    @secret = SecureRandom.random_bytes(64)
    @store = Rack::Session::Revocation::Memory.new
    @app_options = { secrets: @secret, revocation_store: @store }
  end

  it 'does not stamp sessions when no revocation store is configured' do
    response = response_for(app: [login_alice, { secrets: @secret }])
    decrypt_cookie(response).wont_include "session_generation"
  end

  it 'stamps the current generation of the subject at login' do
    response = response_for(app: [login_alice, @app_options])
    decrypt_cookie(response)["session_generation"].must_equal 0

    @store.revoke!("alice")

    response = response_for(app: [login_alice, @app_options])
    decrypt_cookie(response)["session_generation"].must_equal 1
  end

  it 'does not stamp anonymous sessions' do
    response = response_for(app: [incrementor, @app_options])
    decrypt_cookie(response).wont_include "session_generation"
  end

  it 'never consults the store for anonymous sessions' do
    store = counting_store.call(@store)
    options = { secrets: @secret, revocation_store: store }

    response = response_for(app: [incrementor, options])
    response = response_for(app: [incrementor, options], cookie: response)
    response.body.must_equal "2"
    store.reads.must_equal 0
  end

  it 'rejects sessions issued before a revocation' do
    response = response_for(app: [login_alice, @app_options])
    cookie = response["Set-Cookie"]

    response = response_for(app: [whoami, @app_options], cookie: cookie)
    response.body.must_equal '"alice"'

    @store.revoke!("alice")

    response = response_for(app: [whoami, @app_options], cookie: cookie)
    response.body.must_equal "nil"

    # The rejected session is replaced by a fresh anonymous one.
    session = decrypt_cookie(response)
    session.wont_include "user_id"
    session.wont_include "session_generation"
  end

  it 'does not affect other subjects when one is revoked' do
    response = response_for(app: [login_alice, @app_options])
    alice_cookie = response["Set-Cookie"]

    response = response_for(app: [switch_to_bob, @app_options])
    bob_cookie = response["Set-Cookie"]

    @store.revoke!("alice")

    response = response_for(app: [whoami, @app_options], cookie: bob_cookie)
    response.body.must_equal '"bob"'

    response = response_for(app: [whoami, @app_options], cookie: alice_cookie)
    response.body.must_equal "nil"
  end

  it 'accepts a new login immediately after revocation' do
    response = response_for(app: [login_alice, @app_options])
    old_cookie = response["Set-Cookie"]

    @store.revoke!("alice")

    response = response_for(app: [login_alice, @app_options])
    new_cookie = response["Set-Cookie"]
    decrypt_cookie(response)["session_generation"].must_equal 1

    response = response_for(app: [whoami, @app_options], cookie: new_cookie)
    response.body.must_equal '"alice"'

    # The pre-revocation cookie stays rejected.
    response = response_for(app: [whoami, @app_options], cookie: old_cookie)
    response.body.must_equal "nil"
  end

  it 're-stamps the generation when the subject switches' do
    @store.revoke!("bob")

    response = response_for(app: [login_alice, @app_options])
    cookie = response["Set-Cookie"]
    decrypt_cookie(response)["session_generation"].must_equal 0

    response = response_for(app: [switch_to_bob, @app_options], cookie: cookie)
    session = decrypt_cookie(response)
    session["user_id"].must_equal "bob"
    session["session_generation"].must_equal 1
  end

  it 'keeps the issuance generation on ordinary renewal' do
    store = counting_store.call(@store)
    options = { secrets: @secret, revocation_store: store }

    response = response_for(app: [login_alice, options])
    cookie = response["Set-Cookie"]

    response = response_for(app: [incrementor, options], cookie: cookie)
    response.body.must_equal "1"
    decrypt_cookie(response)["session_generation"].must_equal 0

    # Renewal validates against the store on load, but never re-stamps.
    store.reads.must_equal 2
  end

  it 'treats sessions issued before the feature was enabled as generation 0' do
    # Issued by an app without a revocation store: no generation recorded.
    response = response_for(app: [login_alice, { secrets: @secret }])
    legacy_cookie = response["Set-Cookie"]

    response = response_for(app: [whoami, @app_options], cookie: legacy_cookie)
    response.body.must_equal '"alice"'

    @store.revoke!("alice")

    response = response_for(app: [whoami, @app_options], cookie: legacy_cookie)
    response.body.must_equal "nil"
  end

  it 'fails closed when the store fails while checking a session' do
    response = response_for(app: [login_alice, @app_options])
    cookie = response["Set-Cookie"]

    failing_options = { secrets: @secret, revocation_store: failing_store }
    response = response_for(app: [echo_errors, failing_options], cookie: cookie)
    response.body.must_include "Session revocation store error: storage is down"

    response = response_for(app: [whoami, failing_options], cookie: cookie)
    response.body.must_equal "nil"
  end

  it 'does not save the session when the store fails while stamping a login' do
    failing_options = { secrets: @secret, revocation_store: failing_store }
    response = response_for(app: [login_alice, failing_options])
    response["Set-Cookie"].must_be_nil
  end

  it 'does not let an old session gain the new generation through renewal during concurrent revocation' do
    response = response_for(app: [login_alice, @app_options])
    cookie = response["Set-Cookie"]

    # Coordinate a revocation with the validation read of a renewal request,
    # so the revocation lands after the request was validated (with the old
    # generation) but before its response cookie is written.
    read_started = Queue.new
    finish_read = Queue.new
    store = @store
    barrier = Class.new(Rack::Session::Revocation::Store) do
      define_method(:current_generation) do |subject|
        generation = store.current_generation(subject)
        read_started << true
        finish_read.pop
        generation
      end

      define_method(:revoke!) do |subject|
        store.revoke!(subject)
      end
    end.new

    barrier_options = { secrets: @secret, revocation_store: barrier }

    request_thread = Thread.new do
      response_for(app: [incrementor, barrier_options], cookie: cookie)
    end

    # Wait until the renewal request has started its validation read, then
    # revoke before letting the read complete.
    read_started.pop
    barrier.revoke!("alice").must_equal 1
    finish_read << true

    renewed = request_thread.value
    renewed.body.must_equal "1"

    # The renewed cookie must still carry the generation from issuance: an
    # ordinary renewal never upgrades the generation.
    decrypt_cookie(renewed)["session_generation"].must_equal 0

    # And it is therefore rejected on its next use.
    response = response_for(app: [whoami, @app_options], cookie: renewed)
    response.body.must_equal "nil"
  end
end
