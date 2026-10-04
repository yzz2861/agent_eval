# :markup: markdown
# frozen_string_literal: true

class HTTP::Cookie
  # A clock abstraction that provides both a wall clock time and a
  # monotonic time source.
  #
  # The wall clock time (see #wall_now) is an absolute Time value that
  # is subject to system clock adjustments (NTP calibration, manual
  # changes, leap smears, etc.), while the monotonic time (see
  # #monotonic_now) is a Float number of seconds that only moves
  # forward and is unaffected by wall clock changes.
  #
  # Cookie expiration is evaluated with the monotonic clock whenever
  # possible, so that a recalibrated system clock cannot suddenly
  # extend (or shorten) the remaining lifetime of a cookie.  The wall
  # clock is only used where an absolute time reference is
  # unavoidable, such as when interpreting an Expires attribute
  # without any server time information.
  #
  # A custom clock object can be injected for testing or for
  # virtualized environments.  It only has to respond to #wall_now
  # (returning a Time) and #monotonic_now (returning a Float number
  # of seconds):
  #
  #     class FakeClock < HTTP::Cookie::Clock
  #       attr_accessor :wall, :mono
  #       def wall_now; @wall; end
  #       def monotonic_now; @mono; end
  #     end
  #
  #     HTTP::Cookie.clock = FakeClock.new
  #
  # or per cookie jar:
  #
  #     jar = HTTP::CookieJar.new(:clock => FakeClock.new)
  class Clock
    # Returns the current wall clock time as a Time object.
    def wall_now
      Time.now
    end

    # Returns the current monotonic time as a Float number of
    # seconds.  The absolute value is process-local and meaningless
    # outside of the running process; only differences between two
    # readings are significant.
    def monotonic_now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end

  # The default clock based on the system clock.
  SYSTEM_CLOCK = Clock.new

  class << self
    # The default clock used by cookies that have no clock of their
  # own.  Assign a custom clock object (see HTTP::Cookie::Clock) to
  # control how all cookies measure time.
    attr_writer :clock

    def clock
      @clock ||= SYSTEM_CLOCK
    end
  end
end
