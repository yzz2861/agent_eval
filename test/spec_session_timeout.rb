# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.

require_relative 'helper'

require 'rack/response'
require 'rack/mock'
require 'rack/utils'

require_relative '../lib/rack/session/cookie'
require_relative '../lib/rack/session/pool'

# A controllable clock so timeout behavior can be tested without ever
# actually waiting.
class FakeClock
  def initialize(now = Time.at(1_600_000_000))
    @now = now
  end

  def call
    @now
  end

  def to_f
    @now.to_f
  end

  def advance(seconds)
    @now += seconds
  end

  def rewind(seconds)
    @now -= seconds
  end
end

describe "session timeouts" do
  # Routes:
  #   "/"     increments and returns the counter
  #   "/read" returns the counter without modifying the session
  #   "/poll" reads the session without extending the idle timeout
  #   "/renew" increments and renews the session id
  #   "/keys" returns the session keys visible to the application
  app = lambda do |env|
    session = env["rack.session"]

    case env["PATH_INFO"]
    when "/poll"
      env["rack.session.options"][:skip_touch] = true
    when "/renew"
      env["rack.session.options"][:renew] = true
    when "/keys"
      session["counter"] ||= 0
      next Rack::Response.new(session.keys.sort.inspect).to_a
    end

    unless env["PATH_INFO"] == "/read" || env["PATH_INFO"] == "/poll"
      session["counter"] = (session["counter"] || 0) + 1
    end

    Rack::Response.new(session["counter"].to_s).to_a
  end

  secret = "s" * 64

  stores = {
    "Cookie" => lambda do |**options|
      Rack::Session::Cookie.new(app, **options, secrets: secret)
    end,
    "Pool" => lambda do |**options|
      Rack::Session::Pool.new(app, **options)
    end,
  }

  stores.each do |store_name, build|
    describe "#{store_name} store" do
      it "keeps the session alive while active within the idle timeout" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(idle_timeout: 1200, clock: clock))

        res = req.get("/")
        res.body.must_equal "1"
        cookie = res["Set-Cookie"]

        3.times do |index|
          clock.advance(600)
          res = req.get("/", "HTTP_COOKIE" => cookie)
          res.body.must_equal (index + 2).to_s
          cookie = res["Set-Cookie"] if res["Set-Cookie"]
        end
      end

      it "treats the session as valid just before the idle timeout" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(idle_timeout: 1200, clock: clock))

        cookie = req.get("/")["Set-Cookie"]

        clock.advance(1199)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "2"
      end

      it "expires the session exactly at the idle timeout" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(idle_timeout: 1200, clock: clock))

        cookie = req.get("/")["Set-Cookie"]

        clock.advance(1200)
        res = req.get("/", "HTTP_COOKIE" => cookie)

        # The stale session is not exposed; a fresh session starts over.
        res.body.must_equal "1"
        res["Set-Cookie"].wont_be_nil
      end

      it "expires at the absolute timeout regardless of activity" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(
          idle_timeout: 1200, absolute_timeout: 3600, clock: clock
        ))

        res = req.get("/")
        res.body.must_equal "1"
        cookie = res["Set-Cookie"]

        # Stay active every 10 minutes: the idle timeout never kicks in.
        5.times do |index|
          clock.advance(600)
          res = req.get("/", "HTTP_COOKIE" => cookie)
          res.body.must_equal (index + 2).to_s
          cookie = res["Set-Cookie"] if res["Set-Cookie"]
        end

        clock.advance(599)
        res = req.get("/", "HTTP_COOKIE" => cookie)
        res.body.must_equal "7"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        # One hour after creation, the session must be re-authenticated.
        clock.advance(1)
        res = req.get("/", "HTTP_COOKIE" => cookie)
        res.body.must_equal "1"
      end

      it "enforces the absolute timeout boundary without an idle timeout" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(absolute_timeout: 3600, clock: clock))

        cookie = req.get("/")["Set-Cookie"]

        clock.advance(3599)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "2"

        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(absolute_timeout: 3600, clock: clock))

        cookie = req.get("/")["Set-Cookie"]

        clock.advance(3600)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "1"
      end

      it "does not extend the idle timeout for :skip_touch polling requests" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(idle_timeout: 1200, clock: clock))

        cookie = req.get("/")["Set-Cookie"]

        clock.advance(600)
        res = req.get("/poll", "HTTP_COOKIE" => cookie)
        res.body.must_equal "1"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        clock.advance(599)
        res = req.get("/poll", "HTTP_COOKIE" => cookie)
        res.body.must_equal "1"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        # Polling never touched the session, so it idles out on schedule.
        clock.advance(1)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "1"
      end

      it "does not let throttled renewal writes widen the idle timeout" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(
          idle_timeout: 1200, touch_throttle: 600, clock: clock
        ))

        cookie = req.get("/")["Set-Cookie"]

        # Within the throttle window the touched timestamp is not persisted.
        clock.advance(500)
        res = req.get("/read", "HTTP_COOKIE" => cookie)
        res.body.must_equal "1"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        # The persisted timestamp still anchors the idle check: the request
        # above did not buy extra time beyond the original deadline.
        clock.advance(700)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "1"
      end

      it "tolerates small clock rollbacks without moving timestamps backwards" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(idle_timeout: 1200, clock: clock))

        res = req.get("/")
        res.body.must_equal "1"
        cookie = res["Set-Cookie"]

        clock.advance(600)
        res = req.get("/", "HTTP_COOKIE" => cookie)
        res.body.must_equal "2"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        # The clock jumps backwards by 30 seconds; the session stays valid.
        clock.rewind(30)
        res = req.get("/", "HTTP_COOKIE" => cookie)
        res.body.must_equal "3"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        # The rollback must not have moved the touched timestamp backwards:
        # 1170 seconds after the last real touch, the session is still valid.
        clock.advance(1200)
        res = req.get("/", "HTTP_COOKIE" => cookie)
        res.body.must_equal "4"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        clock.advance(1200)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "1"
      end

      it "starts a fresh absolute window when the session is renewed" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(absolute_timeout: 3600, clock: clock))

        res = req.get("/")
        res.body.must_equal "1"
        cookie = res["Set-Cookie"]

        clock.advance(3000)
        res = req.get("/renew", "HTTP_COOKIE" => cookie)
        res.body.must_equal "2"
        cookie = res["Set-Cookie"]

        # 6000 seconds after the original login, but only 3000 after renewal.
        clock.advance(3000)
        res = req.get("/", "HTTP_COOKIE" => cookie)
        res.body.must_equal "3"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        clock.advance(3600)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "1"
      end

      it "rejects the session when timestamps are too far ahead of the clock" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(idle_timeout: 1200, clock: clock))

        res = req.get("/")
        res.body.must_equal "1"
        cookie = res["Set-Cookie"]

        clock.advance(600)
        res = req.get("/", "HTTP_COOKIE" => cookie)
        res.body.must_equal "2"
        cookie = res["Set-Cookie"] if res["Set-Cookie"]

        # A large clock rollback makes the stored timestamps untrustworthy;
        # the session fails safe and is discarded.
        clock.rewind(600 + 61)
        req.get("/", "HTTP_COOKIE" => cookie).body.must_equal "1"
      end

      it "does not expose the session timestamps to the application" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(build.call(
          idle_timeout: 1200, absolute_timeout: 3600, clock: clock
        ))

        res = req.get("/keys")
        res.body.must_include "counter"
        res.body.wont_include "rack.session.meta"
      end
    end
  end

  describe Rack::Session::Cookie do
    def cookie_value(response)
      response["Set-Cookie"][/rack\.session=([^;]*)/, 1]
    end

    it "does not rewrite the cookie within the touch throttle window" do
      clock = FakeClock.new
      # A deterministic coder (rather than encrypted cookies, which use a
      # random nonce per message) makes the throttled write observable.
      store = Rack::Session::Cookie.new(app,
        coder: Rack::Session::Cookie::Base64::Marshal.new,
        let_coder_handle_secure_encoding: true,
        idle_timeout: 1200, touch_throttle: 600, clock: clock
      )
      req = Rack::MockRequest.new(store)

      res = req.get("/")
      res.body.must_equal "1"
      cookie = res["Set-Cookie"]

      # Nothing changed and the touched timestamp is throttled: no renewal.
      clock.advance(60)
      res = req.get("/read", "HTTP_COOKIE" => cookie)
      res.body.must_equal "1"
      res["Set-Cookie"].must_be_nil

      # Once the throttle window has elapsed, the renewal is written out.
      clock.advance(600)
      res = req.get("/read", "HTTP_COOKIE" => cookie)
      res.body.must_equal "1"
      res["Set-Cookie"].wont_be_nil
    end

    describe "server-side timestamp validation" do
      def crafted_cookie(secret, data)
        encryptor = Rack::Session::Encryptor.new(secret)
        "rack.session=#{Rack::Utils.escape(encryptor.encrypt(data))}"
      end

      it "rejects timestamps dated far into the future" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(stores.fetch("Cookie").call(
          idle_timeout: 1200, absolute_timeout: 3600, clock: clock
        ))

        now = clock.to_f

        future_touch = crafted_cookie(secret,
          "session_id" => "a" * 32, "counter" => 5,
          "rack.session.meta" => {"created_at" => now - 100, "touched_at" => now + 100_000})
        req.get("/", "HTTP_COOKIE" => future_touch).body.must_equal "1"

        future_create = crafted_cookie(secret,
          "session_id" => "a" * 32, "counter" => 5,
          "rack.session.meta" => {"created_at" => now + 100_000, "touched_at" => now - 100})
        req.get("/", "HTTP_COOKIE" => future_create).body.must_equal "1"
      end

      it "rejects malformed timestamps" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(stores.fetch("Cookie").call(
          idle_timeout: 1200, absolute_timeout: 3600, clock: clock
        ))

        now = clock.to_f

        garbage = crafted_cookie(secret,
          "session_id" => "a" * 32, "counter" => 5,
          "rack.session.meta" => "bogus")
        req.get("/", "HTTP_COOKIE" => garbage).body.must_equal "1"

        non_numeric = crafted_cookie(secret,
          "session_id" => "a" * 32, "counter" => 5,
          "rack.session.meta" => {"created_at" => "x", "touched_at" => now})
        req.get("/", "HTTP_COOKIE" => non_numeric).body.must_equal "1"
      end

      it "accepts legacy cookies without timestamps and starts tracking them" do
        clock = FakeClock.new
        req = Rack::MockRequest.new(stores.fetch("Cookie").call(
          idle_timeout: 1200, clock: clock
        ))

        legacy = crafted_cookie(secret, "session_id" => "a" * 32, "counter" => 5)
        res = req.get("/", "HTTP_COOKIE" => legacy)
        res.body.must_equal "6"

        encryptor = Rack::Session::Encryptor.new(secret)
        data = encryptor.decrypt(Rack::Utils.unescape(cookie_value(res)))
        meta = data["rack.session.meta"]
        meta["created_at"].must_equal clock.to_f
        meta["touched_at"].must_equal clock.to_f
      end
    end
  end

  describe Rack::Session::Pool do
    it "removes the expired entry from the pool" do
      clock = FakeClock.new
      pool = stores.fetch("Pool").call(idle_timeout: 1200, clock: clock)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/")["Set-Cookie"]
      pool.pool.size.must_equal 1

      clock.advance(1200)
      res = req.get("/", "HTTP_COOKIE" => cookie)
      res.body.must_equal "1"

      # The stale entry was replaced, not leaked.
      pool.pool.size.must_equal 1
    end

    it "throttles touched timestamp writes to the pool" do
      clock = FakeClock.new
      pool = stores.fetch("Pool").call(
        idle_timeout: 1200, touch_throttle: 600, clock: clock
      )
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/")["Set-Cookie"]
      touched = -> { pool.pool.values.first["rack.session.meta"]["touched_at"] }
      touched.call.must_equal clock.to_f

      clock.advance(60)
      req.get("/read", "HTTP_COOKIE" => cookie)
      touched.call.must_equal clock.to_f - 60

      clock.advance(600)
      req.get("/read", "HTTP_COOKIE" => cookie)
      touched.call.must_equal clock.to_f
    end
  end
end
