module IceCube
  class IcalBuilder
    ICAL_DAYS = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"]

    def initialize
      @hash = {}
    end

    def self.fixnum_to_ical_day(num)
      ICAL_DAYS[num]
    end

    def [](key)
      @hash[key] ||= []
    end

    # Build for a single rule entry
    def to_s
      arr = []
      if (freq = @hash.delete("FREQ"))
        arr << "FREQ=#{freq.join(",")}"
      end
      arr.concat(@hash.map do |key, value|
        if value.is_a?(Array)
          "#{key}=#{value.join(",")}"
        end
      end.compact)
      arr.join(";")
    end

    def self.ical_utc_format(time)
      time = time.dup.utc
      IceCube::I18n.l(time, format: "%Y%m%dT%H%M%SZ") # utc time
    end

    def self.ical_format(time, force_utc)
      time = time.dup.utc if force_utc
      if time.utc?
        ":#{IceCube::I18n.l(time, format: "%Y%m%dT%H%M%SZ")}" # utc time
      else
        ";TZID=#{IceCube::I18n.l(time, format: "%Z:%Y%m%dT%H%M%S")}" # local time specified
      end
    end

    # Format a period (start/end) for an RDATE;VALUE=PERIOD. The end time is
    # rendered in the same zone as the start time.
    def self.ical_period_format(occurrence, force_utc)
      start_time = occurrence.start_time
      end_time = occurrence.end_time
      start_time = start_time.dup.utc if force_utc
      end_time = end_time.dup.utc if force_utc
      same_zone = end_time.utc? == start_time.utc? && end_time.utc_offset == start_time.utc_offset
      end_time = end_time.getlocal(start_time.utc_offset) unless same_zone
      if start_time.utc?
        ":#{IceCube::I18n.l(start_time, format: "%Y%m%dT%H%M%SZ")}/" \
          "#{IceCube::I18n.l(end_time, format: "%Y%m%dT%H%M%SZ")}"
      else
        zone_name = start_time.respond_to?(:time_zone) ? start_time.time_zone.name : IceCube::I18n.l(start_time, format: "%Z")
        ";TZID=#{zone_name}:" \
          "#{IceCube::I18n.l(start_time, format: "%Y%m%dT%H%M%S")}/" \
          "#{IceCube::I18n.l(end_time, format: "%Y%m%dT%H%M%S")}"
      end
    end

    # Parse an iCalendar duration (e.g. PT1H30M, P1D) into seconds
    def self.ical_duration_to_seconds(duration)
      match = duration.match(/\A([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?\z/)
      raise ArgumentError, "Invalid iCal duration: #{duration}" unless match &&
        duration =~ /\d/ && duration !~ /T\z/
      sign = match[1] == "-" ? -1 : 1
      weeks, days, hours, minutes, seconds = match.captures[1..].map(&:to_i)
      sign * (weeks * 7 * 86400 + days * 86400 + hours * 3600 + minutes * 60 + seconds)
    end

    def self.ical_duration(duration)
      hours = duration / 3600
      duration %= 3600
      minutes = duration / 60
      duration %= 60
      repr = ""
      return "PT0S" if hours == 0 && minutes == 0 && duration == 0
      repr << "#{hours}H" if hours > 0
      repr << "#{minutes}M" if minutes > 0
      repr << "#{duration}S" if duration > 0
      "PT#{repr}"
    end
  end
end
