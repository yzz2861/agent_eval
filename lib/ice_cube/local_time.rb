module IceCube
  class LocalTime < Time
    attr_reader :time_zone

    def self.from_utc(utc_time, time_zone)
      period = time_zone.period_for_utc(utc_time)
      local = utc_to_parts(utc_time, period.offset)
      time = new(
        local[:year], local[:month], local[:day],
        local[:hour], local[:minute], local[:second], period.offset
      )
      time.set_time_zone(time_zone)
      time
    end

    def self.utc_to_parts(utc_time, offset)
      local = utc_time.getlocal(offset)
      {
        year: local.year, month: local.month, day: local.day,
        hour: local.hour, minute: local.min, second: local.sec + local.subsec
      }
    end

    def set_time_zone(time_zone)
      @time_zone = time_zone
    end

    def period
      time_zone.period_for_utc(Time.at(to_r).utc)
    end

    def utc_offset
      period.offset
    end

    def zone
      period.abbreviation
    end

    def dst?
      period.daylight
    end

    def utc?
      false
    end
    alias_method :gmt?, :utc?

    def +(amount)
      time_zone.time_from_utc!(Time.at(to_r + amount).utc)
    end

    def -(other)
      return super if other.is_a?(Time)

      time_zone.time_from_utc!(Time.at(to_r - other).utc)
    end

    def utc
      Time.at(to_r).utc
    end
    alias_method :getgm, :utc
    alias_method :getutc, :utc

    def getlocal(offset = nil)
      offset.nil? ? self : super
    end

    def localtime(offset = nil)
      offset.nil? ? self : super
    end

    def to_time
      self
    end

    def in_time_zone(zone)
      return self if zone == time_zone || zone == time_zone.name
      super
    end
  end
end
