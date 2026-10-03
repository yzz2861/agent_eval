module IceCube
  class FloatingTime < Time
    def self.local(year, month, day, hour, minute, second)
      new(year, month, day, hour, minute, second, 0)
    end

    def utc?
      false
    end
    alias_method :gmt?, :utc?

    def zone
      nil
    end

    def +(amount)
      result = Time.at(to_r + amount).getlocal(0)
      self.class.local(result.year, result.month, result.day, result.hour, result.min, result.sec + result.subsec)
    end

    def -(other)
      return super if other.is_a?(Time)

      result = Time.at(to_r - other).getlocal(0)
      self.class.local(result.year, result.month, result.day, result.hour, result.min, result.sec + result.subsec)
    end

    def getlocal(offset = nil)
      offset.nil? ? self : super
    end

    def localtime(offset = nil)
      offset.nil? ? self : super
    end

    def to_time
      self
    end

    def utc
      Time.at(to_r).utc
    end
    alias_method :getgm, :utc
    alias_method :getutc, :utc
  end
end
