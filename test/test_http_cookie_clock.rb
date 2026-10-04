# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))
require 'stringio'
require 'yaml'

# A controllable pair of wall clock and monotonic clock used to
# demonstrate clock calibration and process restart.
class FakeClock
  attr_accessor :wall, :monotonic

  def initialize(wall, monotonic = 1000.0)
    @wall = wall
    @monotonic = monotonic.to_f
  end

  def now
    @wall
  end

  def now_monotonic
    @monotonic
  end

  # Advances both clocks, as normal elapsed time would.
  def advance(seconds)
    @monotonic += seconds
    @wall += seconds
    self
  end

  # Calibrates only the wall clock, leaving monotonic time alone.
  def calibrate_wall(time)
    @wall = time
    self
  end

  def rewind_wall(seconds)
    calibrate_wall(@wall - seconds)
  end

  def fast_forward_wall(seconds)
    calibrate_wall(@wall + seconds)
  end
end

class TestHTTPCookieClock < Test::Unit::TestCase
  BASE = Time.utc(2020, 1, 1, 0, 0, 0)
  ORIGIN = 'http://example.com/'

  def setup
    @clock = FakeClock.new(BASE)
    @jar = HTTP::CookieJar.new(:clock => @clock)
  end

  def jar_with(clock = @clock)
    HTTP::CookieJar.new(:clock => clock)
  end

  # Max-Age follows monotonic elapsed time; setting the wall clock
  # back must not extend the remaining lifetime.
  def test_max_age_unaffected_by_wall_setback
    @jar.parse('a=1; Max-Age=100', ORIGIN)

    @clock.advance(40)
    assert_equal 1, @jar.cookies(ORIGIN).size

    @clock.rewind_wall(86_400)
    assert_equal 1, @jar.cookies(ORIGIN).size,
      'wall setback must not expire the cookie by wall time'

    @clock.advance(59)
    assert_equal 1, @jar.cookies(ORIGIN).size

    @clock.advance(1)
    assert_equal 0, @jar.cookies(ORIGIN).size,
      'cookie expires after 100 monotonic seconds regardless of wall'
  end

  # Moving the wall clock forward also does not change Max-Age life.
  def test_max_age_unaffected_by_wall_fast_forward
    @jar.parse('a=1; Max-Age=100', ORIGIN)

    @clock.fast_forward_wall(3600)
    assert_equal 1, @jar.cookies(ORIGIN).size,
      'wall fast-forward must not expire a Max-Age cookie'

    @clock.advance(100)
    assert_equal 0, @jar.cookies(ORIGIN).size
  end

  # An Expires deadline is an absolute wall time, but is corrected by
  # the server Date offset so a skewed client clock does not change
  # the lifetime intended by the server.
  def test_expires_corrected_by_response_date
    client_clock = FakeClock.new(BASE + 500) # client is 500s fast
    jar = jar_with(client_clock)

    # Server says "now = origin", cookie expires in 100s.
    jar.parse('a=1; Expires=Wed, 01 Jan 2020 00:01:40 GMT', ORIGIN,
              :date => 'Wed, 01 Jan 2020 00:00:00 GMT')

    assert_equal 1, jar.cookies(ORIGIN).size
    cookie = jar.cookies(ORIGIN).first
    assert_equal BASE + 600, cookie.expires,
      'Expires is translated onto the skewed client clock'

    client_clock.advance(99)
    assert_equal 1, jar.cookies(ORIGIN).size
    client_clock.advance(1)
    assert_equal 0, jar.cookies(ORIGIN).size,
      'the intended 100s lifetime is preserved'
  end

  def test_missing_date_means_no_offset
    @jar.parse('a=1; Expires=Wed, 01 Jan 2020 00:01:40 GMT', ORIGIN)
    assert_equal BASE + 100, @jar.cookies(ORIGIN).first.expires
  end

  def test_invalid_date_means_no_offset
    assert_nothing_raised do
      @jar.parse('a=1; Expires=Wed, 01 Jan 2020 00:01:40 GMT', ORIGIN,
                 :date => 'not a date at all')
    end
    assert_equal BASE + 100, @jar.cookies(ORIGIN).first.expires
  end

  # Already-expired Expires cookies are excluded by the URI
  # selection interface.
  def test_already_expired_expires_cookie
    @jar.parse('old=1; Expires=Fri, 01 Jan 1999 00:00:00 GMT', ORIGIN)
    assert_equal 0, @jar.cookies(ORIGIN).size
    @jar.cleanup
    assert_equal 0, @jar.to_a.size
  end

  # A negative Max-Age expires immediately (RFC 6265).
  def test_negative_max_age_expires_immediately
    cookies = HTTP::Cookie.parse('a=1; Max-Age=-1', ORIGIN, :clock => @clock)
    assert_equal 1, cookies.size
    cookie = cookies.first
    assert_equal(-1, cookie.max_age)
    assert_equal true, cookie.expired?
    @jar.add(cookie)
    assert_equal 0, @jar.cookies(ORIGIN).size
  end

  def test_zero_max_age_expires_immediately
    @jar.parse('a=1; Max-Age=0', ORIGIN)
    assert_equal 0, @jar.cookies(ORIGIN).size
  end

  # Max-Age wins when both Max-Age and Expires are present.
  def test_max_age_takes_precedence_under_clock
    @jar.parse('a=1; Max-Age=100; Expires=Fri, 01 Jan 1999 00:00:00 GMT', ORIGIN)
    cookie = @jar.cookies(ORIGIN).first
    assert_equal 100, cookie.max_age
    assert_nil @jar.to_a.first.instance_variable_get(:@expires)

    @jar.parse('b=2; Expires=Fri, 01 Jan 1999 00:00:00 GMT; Max-Age=100', ORIGIN)
    assert_equal 2, @jar.cookies(ORIGIN).size
  end

  # Save/restore: no process-local monotonic value is written; the
  # deadline is rebuilt from the saved wall reference and elapsed
  # seconds.
  def test_yaml_save_restore_rebuilds_monotonic_deadline
    @jar.parse('a=1; Max-Age=100', ORIGIN)
    @clock.advance(40)
    @clock.rewind_wall(86_400)

    yaml = +''
    @jar.save(StringIO.new(yaml), :session => true)
    assert_no_match(/@created_tick/, yaml)
    assert_no_match(/monotonic: \d/, yaml)
    assert_match(/saved_monotonic_elapsed: 40/, yaml)
    assert_match(/saved_wall_reference:/, yaml)

    # A "new process" with its own arbitrary monotonic origin; wall
    # clock equals the calibrated wall time at the save moment.
    new_clock = FakeClock.new(@clock.wall, 999_999.0)
    new_jar = jar_with(new_clock)
    new_jar.load(StringIO.new(yaml))

    cookie = new_jar.cookies(ORIGIN).first
    assert_in_delta BASE - 86_400, cookie.created_at, 1.0
    assert_in_delta BASE + 100 - 86_400, cookie.expires, 1.0
    assert_equal 1, new_jar.cookies(ORIGIN).size

    # Wall changes alone do not extend life; only elapsed time does.
    new_clock.fast_forward_wall(86_400)
    assert_equal 1, new_jar.cookies(ORIGIN).size

    new_clock.advance(59)
    assert_equal 1, new_jar.cookies(ORIGIN).size
    new_clock.advance(1)
    assert_equal 0, new_jar.cookies(ORIGIN).size
  end

  # Expired Max-Age cookies are pruned while saving.
  def test_yaml_save_skips_expired_values
    @jar.parse('a=1; Max-Age=10', ORIGIN)
    @clock.advance(10)
    assert_equal 0, @jar.cookies(ORIGIN).size

    yaml = +''
    @jar.save(StringIO.new(yaml), :session => true)
    refute_match(/name: a/, yaml)
  end

  # The cookies.txt saver uses the jar clock for its expiry cutoff,
  # and loaded cookies adopt the jar's clock.
  def test_cookiestxt_saver_uses_injected_clock
    @jar.parse('a=1; Max-Age=100', ORIGIN)
    @clock.advance(40)

    text = +''
    @jar.save(StringIO.new(text), :cookiestxt, :session => true)
    assert_match(/\ta\t1\n\z/, text)

    new_clock = FakeClock.new(BASE + 40, 700.0)
    new_jar = jar_with(new_clock)
    new_jar.load(StringIO.new(text), :cookiestxt)
    # cookies.txt turns Max-Age into an absolute Expires; advancing
    # only the monotonic clock keeps the wall cutoff unchanged.
    new_clock.monotonic += 9_999
    assert_equal 1, new_jar.cookies(ORIGIN).size

    # The absolute expiry follows the wall clock, as the file
    # format cannot represent a monotonic deadline.
    new_clock.fast_forward_wall(61)
    assert_equal 0, new_jar.cookies(ORIGIN).size
  end

  # A past cookies.txt record is rejected against the injected clock.
  def test_cookiestxt_rejects_expired_under_clock
    record = "example.com\tFALSE\t/\tFALSE\t#{(BASE + 100).to_i}\ta\t1\n"
    @clock.calibrate_wall(BASE + 200)
    @jar.load(StringIO.new(record), :cookiestxt)
    assert_equal 0, @jar.to_a.size
  end

  # Legacy YAML without the elapsed/reference keys still loads.
  def test_yaml_load_legacy_max_age
    legacy = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: a
        value: '1'
        domain: example.com
        for_domain: false
        path: /
        secure: false
        httponly: false
        expires:
        max_age: 100
        created_at: 2020-01-01 00:00:00.000000000 Z
        accessed_at: 2020-01-01 00:00:00.000000000 Z
    YAML
    clock = FakeClock.new(BASE + 20)
    jar = jar_with(clock)
    jar.load(StringIO.new(legacy))
    assert_equal 1, jar.cookies(ORIGIN).size
    clock.advance(99)
    assert_equal 1, jar.cookies(ORIGIN).size
    clock.advance(1)
    assert_equal 0, jar.cookies(ORIGIN).size
  end

  # cookies/each/empty? all share the same expiration judgment.
  def test_uri_selection_interfaces_share_judgment
    @jar.parse('a=1; Max-Age=10', ORIGIN)
    @clock.advance(9)

    assert_equal 1, @jar.cookies(ORIGIN).size
    assert_equal false, @jar.empty?(ORIGIN)
    seen = []
    @jar.each(ORIGIN) { |cookie| seen << cookie.name }
    assert_equal %w[a], seen

    @clock.advance(1)
    assert_equal 0, @jar.cookies(ORIGIN).size
    assert_equal true, @jar.empty?(ORIGIN)
  end

  def test_clock_option_coercion
    assert_same HTTP::Cookie::SYSTEM_CLOCK,
               HTTP::CookieJar.new.store.clock
    assert_raise(TypeError) do
      HTTP::CookieJar.new(:clock => Object.new)
    end
  end

  # A duplicated jar shares the injected clock and keeps the same
  # monotonic expiration.
  def test_duplicated_jar_shares_clock
    @jar.parse('a=1; Max-Age=100', ORIGIN)
    copy = @jar.dup
    @clock.advance(99)
    assert_equal 1, @jar.cookies(ORIGIN).size
    assert_equal 1, copy.cookies(ORIGIN).size
    @clock.advance(1)
    assert_equal 0, @jar.cookies(ORIGIN).size
    assert_equal 0, copy.cookies(ORIGIN).size
  end
end
