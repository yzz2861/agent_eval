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

    # Fold a content line to at most +limit+ octets per physical line,
    # per RFC 5545 section 3.1. Continuation lines start with a single
    # space (which counts toward the limit) and multi-byte UTF-8
    # characters are never split across a fold.
    def self.fold_line(line, limit = 75)
      return line if line.bytesize <= limit
      segments = []
      current = +""
      line.each_char do |char|
        if current.bytesize + char.bytesize > limit
          segments << current
          current = +" "
        end
        current << char
      end
      segments << current
      segments.join("\n")
    end

    def self.ical_duration(duration)
      hours = duration / 3600
      duration %= 3600
      minutes = duration / 60
      duration %= 60
      repr = ""
      repr << "#{hours}H" if hours > 0
      repr << "#{minutes}M" if minutes > 0
      repr << "#{duration}S" if duration > 0
      "PT#{repr}"
    end
  end
end
