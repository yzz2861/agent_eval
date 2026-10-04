 # frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))
 require 'http/cookie_jar'
 require 'stringio'

 class TestHTTPCookieClock < Test::Unit::TestCase
   # A fake clock providing independently controllable wall and
   # monotonic time sources.
   class FakeClock < HTTP::Cookie::Clock
     attr_accessor :wall, :mono

     def initialize(wall, mono = 0.0)
       @wall = wall
       @mono = mono
     end

     def wall_now
       @wall
     end

     def monotonic_now
       @mono
     end
   end

   def setup
     @epoch = Time.utc(2026, 1, 1, 0, 0, 0)
     @clock = FakeClock.new(@epoch, 1000.0)
     @url = URI.parse('http://example.com/')
   end

   def test_clock_default_system
     assert_kind_of HTTP::Cookie::Clock, HTTP::Cookie.clock
     assert_in_delta Time.now, HTTP::Cookie.clock.wall_now, 2
     assert_in_delta Process.clock_gettime(Process::CLOCK_MONOTONIC),
       HTTP::Cookie.clock.monotonic_now, 2
   end

   def test_max_age_uses_monotonic_clock
     cookie = HTTP::Cookie.parse('name=value; Max-Age=60', @url, :clock => @clock).first

     assert_equal false, cookie.expired?

     # Wall clock rollback (e.g. NTP calibration) must not extend life.
     @clock.wall -= 3600
     @clock.mono += 30
     assert_equal false, cookie.expired?

     # Wall clock fast-forward must not shorten life either; only the
     # monotonic clock matters.
     @clock.wall += 7200
     assert_equal false, cookie.expired?

     @clock.mono += 31
     assert_equal true, cookie.expired?
   end

   def test_max_age_zero_and_negative_expire_immediately
     [0, -1, -3600].each { |age|
       cookie = HTTP::Cookie.parse("name=value; Max-Age=#{age}", @url, :clock => @clock).first
       assert_equal true, cookie.expired?, "Max-Age=#{age} should expire immediately"
     }
   end

   def test_expires_with_server_date_correction
     # The client wall clock is one hour behind the server.
     server_now = @epoch + 3600
     expires = server_now + 30
     cookie = HTTP::Cookie.parse(
       "name=value; Expires=#{expires.httpdate}", @url,
       :clock => @clock, :date => server_now.httpdate
     ).first

     assert_in_delta 3600.0, cookie.server_offset, 0.001
     # Uncorrected, the cookie would seem to live for 1h30m; with the
     # server offset it only has 30 seconds.
     assert_equal false, cookie.expired?
     @clock.mono += 29
     assert_equal false, cookie.expired?
     @clock.mono += 2
     assert_equal true, cookie.expired?
   end

   def test_expires_server_correction_immune_to_wall_calibration
     # The client wall clock is one hour ahead of the server and gets
     # calibrated backwards after the cookie is received.
     server_now = @epoch
     @clock.wall = @epoch + 3600
     expires = server_now + 60
     cookie = HTTP::Cookie.parse(
       "name=value; Expires=#{expires.httpdate}", @url,
       :clock => @clock, :date => server_now.httpdate
     ).first

     assert_equal false, cookie.expired?

     # Calibration must not suddenly increase the remaining lifetime.
     @clock.wall = @epoch
     @clock.mono += 10
     assert_equal false, cookie.expired?
     @clock.mono += 51
     assert_equal true, cookie.expired?
   end

   def test_expires_without_date_uses_wall_clock
     expires = @epoch + 60
     cookie = HTTP::Cookie.parse(
       "name=value; Expires=#{expires.httpdate}", @url, :clock => @clock
     ).first

     assert_nil cookie.server_offset
     assert_equal false, cookie.expired?
     @clock.wall += 61
     assert_equal true, cookie.expired?
   end

   def test_expires_with_invalid_date_falls_back_to_wall_clock
     expires = @epoch + 60
     cookie = HTTP::Cookie.parse(
       "name=value; Expires=#{expires.httpdate}", @url,
       :clock => @clock, :date => 'not a date at all'
     ).first

     assert_nil cookie.server_offset
     assert_equal false, cookie.expired?
     @clock.wall += 61
     assert_equal true, cookie.expired?
   end

   def test_expires_already_expired_value
     expires = @epoch - 1
     cookie = HTTP::Cookie.parse(
       "name=value; Expires=#{expires.httpdate}", @url,
       :clock => @clock, :date => @epoch.httpdate
     ).first
     assert_equal true, cookie.expired?
   end

   def test_max_age_takes_precedence_over_expires
     # Expires says "already expired", Max-Age says 1 hour: the cookie
     # must be alive and governed by the monotonic clock.
     past = @epoch - 3600
     cookie = HTTP::Cookie.parse(
       "name=value; Expires=#{past.httpdate}; Max-Age=3600", @url, :clock => @clock
     ).first
     assert_equal false, cookie.expired?
     @clock.mono += 3601
     assert_equal true, cookie.expired?

     # And the other way around: Expires far in the future, Max-Age
     # already elapsed.
     future = @epoch + 86400
     cookie = HTTP::Cookie.parse(
       "name=value; Max-Age=10; Expires=#{future.httpdate}", @url, :clock => @clock
     ).first
     @clock.mono += 11
     assert_equal true, cookie.expired?
   end

   def test_jar_uses_injected_clock_for_uri_selection
     jar = HTTP::CookieJar.new(:clock => @clock)
     jar.parse('name=value; Max-Age=60', @url)

     assert_equal 1, jar.cookies(@url).size

     # Rolling the wall clock back must not resurrect expired cookies,
     # and monotonic elapsed time is what expires them.
     @clock.wall -= 3600
     @clock.mono += 61
     assert_equal 0, jar.cookies(@url).size
     assert_equal true, jar.empty?(@url)
   end

   def test_jar_parse_passes_date_for_server_correction
     jar = HTTP::CookieJar.new(:clock => @clock)
     server_now = @epoch + 3600
     expires = server_now + 30
     jar.parse("name=value; Expires=#{expires.httpdate}", @url, :date => server_now.httpdate)

     @clock.mono += 31
     assert_equal 0, jar.cookies(@url).size
   end

   def test_save_and_load_reestablishes_max_age_deadline
     jar = HTTP::CookieJar.new(:clock => @clock)
     jar.parse('name=value; Max-Age=100', @url)

     # 40 seconds pass on the monotonic clock before saving.
     @clock.mono += 40

     io = StringIO.new
     jar.save(io)

     # Monotonic timestamps are process-local and must not be
     # persisted; the absolute wall-clock reference is saved instead.
     yaml = io.string
     assert_nil yaml.match(/max_age_anchor|monotonic/), yaml
     assert_match(/max_age: 100/, yaml)

     # Restore in a "new process": a fresh fake clock whose monotonic
     # counter restarted, with 50 seconds of wall time elapsed.
     clock2 = FakeClock.new(@epoch + 50, 0.0)
     jar2 = HTTP::CookieJar.new(:clock => clock2)
     jar2.load(StringIO.new(yaml))

     # 50 of the 100 seconds are gone, 50 remain.
     assert_equal 1, jar2.cookies(@url).size
     clock2.mono += 49
     assert_equal 1, jar2.cookies(@url).size
     clock2.mono += 2
     assert_equal 0, jar2.cookies(@url).size
   end

   def test_save_and_load_expires_after_deadline
     jar = HTTP::CookieJar.new(:clock => @clock)
     jar.parse('name=value; Max-Age=100', @url)

     io = StringIO.new
     jar.save(io)

     # The wall clock has advanced past the deadline while the jar
     # was stored.
     clock2 = FakeClock.new(@epoch + 200, 0.0)
     jar2 = HTTP::CookieJar.new(:clock => clock2)
     jar2.load(StringIO.new(io.string))

     assert_equal 0, jar2.cookies(@url).size
   end

   def test_save_and_load_preserves_server_offset
     server_now = @epoch + 3600
     expires = server_now + 60
     jar = HTTP::CookieJar.new(:clock => @clock)
     jar.parse("name=value; Expires=#{expires.httpdate}", @url, :date => server_now.httpdate)

     io = StringIO.new
     jar.save(io)
     assert_match(/server_offset: 3600/, io.string)

     # 30 seconds of wall time pass while the jar is stored; the
     # client wall clock is still one hour behind.
     clock2 = FakeClock.new(@epoch + 30, 0.0)
     jar2 = HTTP::CookieJar.new(:clock => clock2)
     jar2.load(StringIO.new(io.string))

     cookie = jar2.cookies(@url).first
     assert_not_nil cookie
     assert_in_delta 3600.0, cookie.server_offset, 0.001

     # 30 of the 60 seconds remain on the server clock.
     clock2.mono += 29
     assert_equal 1, jar2.cookies(@url).size
     clock2.mono += 2
     assert_equal 0, jar2.cookies(@url).size
   end

  def test_expired_with_explicit_time_argument
    cookie = HTTP::Cookie.parse('name=value; Max-Age=60', @url, :clock => @clock).first
    assert_equal false, cookie.expired?(cookie.expires - 1)
    assert_equal true, cookie.expired?(cookie.expires + 1)

    expires = @epoch + 60
    cookie = HTTP::Cookie.parse("name=value; Expires=#{expires.httpdate}", @url, :clock => @clock).first
    assert_equal false, cookie.expired?(cookie.expires - 1)
    assert_equal true, cookie.expired?(cookie.expires + 1)
  end

   def test_cookie_clock_transfer_preserves_remaining_lifetime
     cookie = HTTP::Cookie.parse('name=value; Max-Age=60', @url, :clock => @clock).first
     @clock.mono += 45

     # Re-parenting the cookie onto a different clock (as happens
     # when a cookie is added to a jar with its own clock) must keep
     # the remaining 15 seconds.
     clock2 = FakeClock.new(@epoch + 100, 5000.0)
     cookie.clock = clock2
     clock2.mono += 14
     assert_equal false, cookie.expired?
     clock2.mono += 2
     assert_equal true, cookie.expired?
   end

   def test_accessed_at_uses_jar_clock
     jar = HTTP::CookieJar.new(:clock => @clock)
     jar.parse('name=value', @url)
     @clock.wall += 5
     cookie = jar.cookies(@url).first
     assert_equal @epoch + 5, cookie.accessed_at
   end
 end
