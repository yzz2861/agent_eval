# frozen_string_literal: true

require "date"

module TomlRB
  # Raised when a local date/time is converted to a Time without saying which
  # time zone its wall-clock components belong to.
  MissingTimeZoneError = Class.new(Error)

  # Raised when converting a value whose fractional seconds keep more
  # precision than the nine nanosecond digits a Ruby Time can represent,
  # unless the caller passes an explicit rounding mode.
  PrecisionError = Class.new(Error)

  # Shared behavior for the exact TOML temporal values. None of these classes
  # is a Ruby Time: the parser keeps every component and every fractional
  # second digit instead of forcing a time zone and nanosecond precision.
  module TemporalValue
    NANO_DIGITS = 9
    ROUNDING_MODES = {
      truncate: ->(fraction) { fraction.floor },
      floor: ->(fraction) { fraction.floor },
      ceil: ->(fraction) { fraction.ceil },
      round: ->(fraction) { fraction.round }
    }.freeze

    def self.normalize_zone(zone)
      case zone
      when :utc, "Z", "z"
        "Z"
      when :local
        nil
      when String
        unless zone.match?(/\A[+-]\d\d:\d\d\z/)
          raise ArgumentError, "Invalid UTC offset: #{zone}"
        end

        zone
      else
        raise ArgumentError, "Invalid time zone: #{zone.inspect}"
      end
    end

    def rounded_seconds(rounding)
      whole_seconds = sec || 0
      if fraction.nil? || fraction.length <= NANO_DIGITS
        raise ArgumentError, "Invalid rounding mode: #{rounding.inspect}" unless rounding.nil? || ROUNDING_MODES.key?(rounding)

        return [whole_seconds, (subsec * 1_000_000_000).to_i]
      end

      mode = ROUNDING_MODES[rounding]
      if mode.nil? && rounding.nil?
        raise PrecisionError,
          "Pass rounding: (:truncate, :ceil or :round) to convert #{fraction.length} fraction digits to nanoseconds"
      end
      raise ArgumentError, "Invalid rounding mode: #{rounding.inspect}" unless mode

      nanos = mode.call(fraction.to_r / (10**(fraction.length - NANO_DIGITS)))
      [whole_seconds + nanos.div(1_000_000_000), nanos % 1_000_000_000]
    end

    def build_time(zone, year, mon, day, hour, min, second, nanos)
      # Rounding up can carry into second 60, which Ruby only accepts as the
      # 23:59:60 leap second. Fold every other carry into the larger
      # wall-clock components.
      if second > 60 || (second == 60 && (hour != 23 || min != 59))
        extra_min, second = second.divmod(60)
        extra_hour, min = (min + extra_min).divmod(60)
        extra_day, hour = (hour + extra_hour).divmod(24)
        date = Date.new(year, mon, day) + extra_day
        year, mon, day = date.year, date.mon, date.day
      end
      second_with_subsec = second + nanos / 1_000_000_000r

      if zone.nil?
        Time.local(year, mon, day, hour, min, second_with_subsec)
      elsif zone == "Z"
        Time.utc(year, mon, day, hour, min, second_with_subsec)
      else
        Time.new(year, mon, day, hour, min, second_with_subsec, zone)
      end
    rescue ArgumentError => e
      raise Error, "Cannot represent #{self} as a Time: #{e.message}"
    end

    def normalized_zone(zone)
      if zone.nil?
        raise MissingTimeZoneError,
          "Pass zone: (:utc, :local or a '+HH:MM' offset) to convert #{self.class} to a Time"
      end

      TemporalValue.normalize_zone(zone)
    end
  end

  module DateComponents
    attr_reader :year, :mon, :day
    alias_method :month, :mon

    def to_date
      Date.new(year, mon, day)
    end

    private

    def date_key
      [year, mon, day]
    end
  end

  module TimeComponents
    attr_reader :hour, :min, :sec, :fraction
    alias_method :minute, :min
    alias_method :second, :sec

    # Returns the exact fractional seconds as a Rational in [0, 1). For a
    # value written as 00:00:00.123456789012 this keeps all twelve digits
    # instead of truncating them to nanoseconds.
    def subsec
      return 0r if fraction.nil? || fraction.empty?

      fraction.to_r / (10**fraction.length)
    end

    private

    def time_key
      [hour, min, sec || 0, subsec]
    end

    def fractional_part
      fraction && !fraction.empty? ? ".#{fraction}" : ""
    end
  end

  # A TOML local date, like 1979-05-27. It has no time and no time zone.
  class LocalDate
    include Comparable
    include TemporalValue
    include DateComponents

    def initialize(year, mon, day)
      @year, @mon, @day = year, mon, day
    end

    def to_s
      format("%04d-%02d-%02d", year, mon, day)
    end
    alias_method :inspect, :to_s

    def <=>(other)
      other.is_a?(LocalDate) ? date_key <=> other.send(:date_key) : nil
    end

    def eql?(other)
      other.is_a?(LocalDate) && date_key == other.send(:date_key)
    end

    def hash
      [self.class, *date_key].hash
    end

    # Builds the Time at midnight of this local date. A local date carries no
    # time zone, so the caller must name the zone explicitly.
    def to_time(zone: nil)
      normalized = normalized_zone(zone)
      build_time(normalized, year, mon, day, 0, 0, 0, 0)
    end
  end

  # A TOML local time, like 07:32:00.999999. It has no date and no time zone.
  class LocalTime
    include Comparable
    include TemporalValue
    include TimeComponents

    def initialize(hour, min, sec = nil, fraction = nil)
      @hour, @min, @sec, @fraction = hour, min, sec, fraction
    end

    def to_s
      base = sec.nil? ? format("%02d:%02d", hour, min) : format("%02d:%02d:%02d", hour, min, sec)
      base + fractional_part
    end
    alias_method :inspect, :to_s

    def <=>(other)
      other.is_a?(LocalTime) ? time_key <=> other.send(:time_key) : nil
    end

    def eql?(other)
      other.is_a?(LocalTime) && time_key == other.send(:time_key)
    end

    def hash
      [self.class, *time_key].hash
    end

    # Attaches this wall-clock time to the given date and zone. The zone is
    # mandatory because a local time has none; rounding is mandatory only when
    # the fraction has more than nine digits.
    def to_time(date: Date.new(1970, 1, 1), zone: nil, rounding: nil)
      normalized = normalized_zone(zone)
      whole_sec, nanos = rounded_seconds(rounding)
      build_time(normalized, date.year, date.mon, date.day, hour, min, whole_sec, nanos)
    end
  end

  # A TOML local date-time, like 1979-05-27T07:32:00. It is deliberately not
  # an instant: without an offset it must never be compared as UTC.
  class LocalDateTime
    include Comparable
    include TemporalValue
    include DateComponents
    include TimeComponents

    def initialize(year, mon, day, hour, min, sec = nil, fraction = nil)
      @year, @mon, @day = year, mon, day
      @hour, @min, @sec, @fraction = hour, min, sec, fraction
    end

    def to_s
      base = format("%04d-%02d-%02dT%02d:%02d", year, mon, day, hour, min)
      base += format(":%02d", sec) unless sec.nil?
      base + fractional_part
    end
    alias_method :inspect, :to_s

    def <=>(other)
      other.is_a?(LocalDateTime) ? [*date_key, *time_key] <=> [*other.send(:date_key), *other.send(:time_key)] : nil
    end

    def eql?(other)
      other.is_a?(LocalDateTime) && date_key == other.send(:date_key) && time_key == other.send(:time_key)
    end

    def hash
      [self.class, *date_key, *time_key].hash
    end

    # Attaches a time zone to the wall-clock components. The caller must name
    # the zone, and a rounding mode whenever more than nine fraction digits
    # would be lost.
    def to_time(zone: nil, rounding: nil)
      normalized = normalized_zone(zone)
      whole_sec, nanos = rounded_seconds(rounding)
      build_time(normalized, year, mon, day, hour, min, whole_sec, nanos)
    end
  end

  # A TOML offset date-time, like 1979-05-27T00:32:00-07:00. It is an exact
  # instant, but it keeps its original wall-clock fields and every fraction
  # digit instead of becoming a nanosecond-precision Ruby Time eagerly.
  class OffsetDateTime
    include Comparable
    include TemporalValue
    include DateComponents
    include TimeComponents

    attr_reader :offset

    def initialize(year, mon, day, hour, min, sec, fraction, offset)
      @year, @mon, @day = year, mon, day
      @hour, @min, @sec, @fraction = hour, min, sec, fraction
      @offset = offset
    end

    def to_s
      base = format("%04d-%02d-%02dT%02d:%02d", year, mon, day, hour, min)
      base += format(":%02d", sec) unless sec.nil?
      base + fractional_part + offset
    end
    alias_method :inspect, :to_s

    def <=>(other)
      other.is_a?(OffsetDateTime) ? instant <=> other.send(:instant) : nil
    end

    def eql?(other)
      other.is_a?(OffsetDateTime) &&
        date_key == other.send(:date_key) && time_key == other.send(:time_key) &&
        normalized_offset == other.send(:normalized_offset)
    end

    def hash
      [self.class, *date_key, *time_key, normalized_offset].hash
    end

    # Explicitly converts to a Ruby Time in the declared offset. A rounding
    # mode is required only when more than nine fraction digits would be lost.
    def to_time(rounding: nil)
      whole_sec, nanos = rounded_seconds(rounding)
      build_time(normalized_build_offset, year, mon, day, hour, min, whole_sec, nanos)
    end

    # UTC offset in seconds, for example -25_200 for -07:00.
    def utc_offset
      normalized = normalized_offset
      sign = normalized.start_with?("-") ? -1 : 1
      sign * (normalized[1, 2].to_i * 3600 + normalized[4, 2].to_i * 60)
    end

    private

    def normalized_build_offset
      offset.casecmp?("Z") ? "Z" : normalized_offset
    end

    def instant
      days = Date.new(year, mon, day) - Date.new(1970, 1, 1)
      (days.to_i * 86_400 + hour * 3600 + min * 60 + (sec || 0) + subsec - utc_offset)
    end

    def normalized_offset
      offset == "Z" ? "+00:00" : offset
    end
  end

  module DatetimeParser
    module_function

    def offset_datetime(year, mon, day, hour, min, sec, sec_frac, offset)
      validate_date(year, mon, day)
      validate_time(hour, min, sec)
      normalized = offset.casecmp?("Z") ? "+00:00" : offset
      unless normalized[1, 2].to_i.between?(0, 23) && normalized[4, 2].to_i.between?(0, 59)
        raise ParseError, "Invalid UTC offset: #{offset}"
      end

      OffsetDateTime.new(
        year.to_i, mon.to_i, day.to_i,
        hour.to_i, min.to_i, sec&.to_i, sec_frac,
        offset
      )
    end

    def local_datetime(year, mon, day, hour, min, sec, sec_frac)
      validate_date(year, mon, day)
      validate_time(hour, min, sec)
      LocalDateTime.new(year.to_i, mon.to_i, day.to_i, hour.to_i, min.to_i, sec&.to_i, sec_frac)
    end

    def local_date(year, mon, day)
      validate_date(year, mon, day)
      LocalDate.new(year.to_i, mon.to_i, day.to_i)
    end

    def local_time(hour, min, sec, sec_frac)
      validate_time(hour, min, sec)
      LocalTime.new(hour.to_i, min.to_i, sec&.to_i, sec_frac)
    end

    def validate_date(year, mon, day)
      unless Date.valid_date?(year.to_i, mon.to_i, day.to_i, Date::GREGORIAN)
        raise ParseError, "Invalid date: #{year}-#{mon}-#{day}"
      end
    end

    def validate_time(hour, min, sec)
      unless hour.to_i.between?(0, 23) && min.to_i.between?(0, 59) && sec.to_i.between?(0, 60)
        raise ParseError, "Invalid time: #{hour}:#{min}:#{sec || 0}"
      end
    end
  end
end
