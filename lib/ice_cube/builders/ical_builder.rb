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

    def self.ical_period(start_time, end_time, force_utc, period_duration: nil)
      start_prefix, start_value = ical_format(start_time, force_utc).split(":", 2)
      end_value = period_duration ? ical_duration(period_duration) : ical_time(end_time, force_utc)
      value_params = start_prefix.sub(/\A;/, "")
      params = ["VALUE=PERIOD", value_params].reject(&:empty?).join(";")
      params = ";#{params}" unless params.empty?
      "RDATE#{params}:#{start_value}/#{end_value}"
    end

    def self.ical_time(time, force_utc)
      time = time.dup.utc if force_utc
      format = time.utc? ? "%Y%m%dT%H%M%SZ" : "%Y%m%dT%H%M%S"
      IceCube::I18n.l(time, format: format)
    end

    def self.ical_duration(duration)
      return "PT0S" if duration.zero?

      hours = duration / 3600
      duration %= 3600
      minutes = duration / 60
      duration %= 60
      repr = ""
      repr << "#{hours}H" if hours > 0
      repr << "#{minutes}M" if minutes > 0
      repr << "#{duration.to_i == duration ? duration.to_i : duration}S" if duration > 0
      "PT#{repr}"
    end
  end
end
