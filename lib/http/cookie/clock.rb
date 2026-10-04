# frozen_string_literal: true

class HTTP::Cookie
  # A paired source of time used by cookies and cookie jars.
  #
  # Every clock responds to:
  #
  # * #now — the wall clock time, a Time object.  This may jump
  #   backwards or forwards when the operating system clock is
  #   adjusted (e.g. by NTP).
  # * #now_monotonic — the monotonically increasing elapsed time in
  #   seconds, a Numeric.  This never jumps backwards and is used to
  #   measure elapsed time for the Max-Age attribute so that
  #   calibrating the system clock never extends (or shortens) a
  #   cookie's remaining lifetime.
  #
  # The default clock, HTTP::Cookie::SystemClock, reads the process
  # clocks.  Tests and applications that need deterministic behavior
  # can inject any object implementing the same two methods.
  module Clock
    class << self
      # Coerces +clock+ into a clock object.
      #
      # nil returns the shared system clock.  An object that already
      # responds to #now and #now_monotonic is returned as is.
      def coerce(clock)
        case clock
        when nil
          SYSTEM
        when SystemClock
          clock
        else
          unless clock.respond_to?(:now) && clock.respond_to?(:now_monotonic)
            raise TypeError,
              "clock must respond to #now and #now_monotonic: #{clock.inspect}"
          end
          clock
        end
      end
    end
  end

  # The default clock backed by Time.now and a process-wide monotonic
  # counter.
  class SystemClock
    include Clock

    # Returns the current wall clock time.
    def now
      Time.now
    end

    # Returns the current monotonic time in seconds.
    def now_monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end

  # The shared default clock.
  SYSTEM_CLOCK = SystemClock.new
  Clock.const_set(:SYSTEM, SYSTEM_CLOCK)
end
