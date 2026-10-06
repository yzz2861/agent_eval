require "date"

module TomlRB
  LocalDateTime = Class.new(Time)
  LocalDate = Class.new(Time)
  LocalTime = Class.new(Time)

  module Temporal
    class Value
      include Comparable

      private

      def temporal_equal?(other)
        comparison = other <=> self
        comparison = self <=> other if comparison.nil? && other.is_a?(::Time)
        comparison&.zero? == true
      rescue ArgumentError
        false
      end
    end

    class LocalDate < Value
      attr_reader :year, :mon, :day

      def initialize(year, mon, day)
        @year = year.to_i
        @mon = mon.to_i
        @day = day.to_i
      end

      def to_time(timezone:, precision:, rounding:)
        TimeBuilder.new(self, timezone, precision, rounding).time
      end

      def to_s
        format("%04d-%02d-%02d", year, mon, day)
      end

      def inspect
        "#<#{self.class} #{self}>"
      end

      def <=>(other)
        return unless other.is_a?(self.class)

        [year, mon, day] <=> [other.year, other.mon, other.day]
      end

      def ==(other)
        temporal_equal?(other)
      end
      alias eql? ==

      def hash
        [self.class, year, mon, day].hash
      end
    end

    module WallTime
      attr_reader :hour, :min, :sec, :fractional_seconds, :fraction_digits, :seconds_specified

      def initialize_time(hour, min, sec, sec_frac)
        @hour = hour.to_i
        @min = min.to_i
        @seconds_specified = !sec.nil?
        @sec = sec.to_i
        @fraction_digits = sec_frac ? sec_frac.length : 0
        @fractional_seconds = sec_frac ? Rational(sec_frac, 10**fraction_digits) : 0r
        @fraction_text = sec_frac.to_s
      end

      def time_seconds
        hour * 3600 + min * 60 + sec + fractional_seconds
      end

      def comparison_key
        [hour, min, sec, fractional_seconds]
      end

      def time_to_s
        formatted = format("%02d:%02d", hour, min)
        formatted << format(":%02d", sec) if seconds_specified
        formatted << ".#{fraction_text}" if fraction_digits.positive?
        formatted
      end

      def fraction_text
        @fraction_text
      end
    end

    class LocalTime < Value
      include WallTime

      def initialize(hour, min, sec, sec_frac)
        initialize_time(hour, min, sec, sec_frac)
      end

      def to_time(timezone:, precision:, rounding:)
        TimeBuilder.new(self, timezone, precision, rounding).time
      end

      def to_s
        time_to_s
      end

      def inspect
        "#<#{self.class} #{self}>"
      end

      def <=>(other)
        return unless other.is_a?(self.class)

        comparison_key <=> other.comparison_key
      end

      def ==(other)
        temporal_equal?(other)
      end
      alias eql? ==

      def hash
        [self.class, *comparison_key].hash
      end
    end

    class LocalDateTime < Value
      include WallTime

      attr_reader :year, :mon, :day

      def initialize(year, mon, day, hour, min, sec, sec_frac)
        @year = year.to_i
        @mon = mon.to_i
        @day = day.to_i
        initialize_time(hour, min, sec, sec_frac)
      end

      def to_time(timezone:, precision:, rounding:)
        TimeBuilder.new(self, timezone, precision, rounding).time
      end

      def to_s
        format("%04d-%02d-%02d", year, mon, day) + "T" + time_to_s
      end

      def inspect
        "#<#{self.class} #{self}>"
      end

      def <=>(other)
        return unless other.is_a?(self.class)

        [[year, mon, day], *comparison_key] <=> [[other.year, other.mon, other.day], *other.comparison_key]
      end

      def ==(other)
        temporal_equal?(other)
      end
      alias eql? ==

      def hash
        [self.class, year, mon, day, *comparison_key].hash
      end
    end

    class OffsetDateTime < Value
      include WallTime

      attr_reader :year, :mon, :day, :offset

      def initialize(year, mon, day, hour, min, sec, sec_frac, offset)
        @year = year.to_i
        @mon = mon.to_i
        @day = day.to_i
        @offset = offset
        initialize_time(hour, min, sec, sec_frac)
      end

      def to_time(precision:, rounding:)
        TimeBuilder.new(self, nil, precision, rounding).time
      end

      def to_s
        format("%04d-%02d-%02d", year, mon, day) + "T" + time_to_s + offset
      end

      def inspect
        "#<#{self.class} #{self}>"
      end

      def <=>(other)
        if other.is_a?(self.class)
          absolute_seconds <=> other.absolute_seconds
        elsif other.is_a?(::Time)
          absolute_seconds <=> other.to_r
        end
      end

      def ==(other)
        temporal_equal?(other)
      end
      alias eql? ==

      def hash
        Time.at(absolute_seconds, in: "Z").hash
      end

      def absolute_seconds
        days = gregorian_date.jd - Date.new(1970, 1, 1, Date::GREGORIAN).jd
        days * 86_400 + time_seconds - offset_seconds
      end

      def offset_seconds
        return 0 if offset == "Z"

        sign = offset.start_with?("-") ? -1 : 1
        sign * (offset[1, 2].to_i * 3600 + offset[4, 2].to_i * 60)
      end

      def gregorian_date
        Date.new(year, mon, day, Date::GREGORIAN)
      end
    end

    class TimeBuilder
      ROUNDINGS = %i[down up nearest raise].freeze

      def initialize(value, timezone, precision, rounding)
        @value = value
        @timezone = timezone
        @precision = precision == :nanosecond ? 9 : precision
        @rounding = rounding
        if value.respond_to?(:year)
          @date = Date.new(value.year, value.mon, value.day, Date::GREGORIAN)
        end
      end

      def time
        validate_arguments

        seconds = @value.respond_to?(:time_seconds) ? rounded_time : 0r
        year, mon, day, hour, min, sec, nsec = normalized(seconds)
        zone = @value.is_a?(OffsetDateTime) ? @value.offset : time_zone
        ::Time.new(year, mon, day, hour, min, sec + Rational(nsec, 1_000_000_000), zone)
      end

      private

      def validate_arguments
        unless @precision.is_a?(Integer) && @precision.between?(0, 9)
          raise ArgumentError, "precision must be an integer number of fractional digits from 0 to 9"
        end

        unless ROUNDINGS.include?(@rounding)
          raise ArgumentError, "rounding must be one of #{ROUNDINGS.map(&:inspect).join(", ")}"
        end

        return if @value.is_a?(OffsetDateTime)

        unless valid_time_zone?
          raise ArgumentError, "timezone must be a UTC offset for values without a zone, such as '+00:00'"
        end
      end

      def rounded_time
        scale = 10**@precision
        scaled = @value.time_seconds * scale
        unless scaled.denominator == 1
          raise ArgumentError, "value has more than #{@precision} digits of second precision" if @rounding == :raise
        end

        Rational(rounded_scaled_time(scaled), scale)
      end

      def rounded_scaled_time(scaled)
        case @rounding
        when :down
          scaled.floor
        when :up
          scaled.ceil
        when :nearest
          (scaled + Rational(1, 2)).floor
        else
          scaled.to_i
        end
      end

      def normalized(seconds)
        if @date
          normalized_dated(seconds)
        else
          normalized_local_time(seconds)
        end
      end

      def normalized_dated(seconds)
        whole = seconds.floor
        nsec = fractional_nanoseconds(seconds)

        if @value.respond_to?(:sec) && @value.sec == 60 && whole >= 86_400 && seconds < 86_401
          return [@date.year, @date.mon, @date.day, 23, 59, 60, nsec]
        end

        date = @date + whole.div(86_400)
        hour, remainder = whole.modulo(86_400).divmod(3600)
        min, sec = remainder.divmod(60)
        [date.year, date.mon, date.day, hour, min, sec, nsec]
      end

      def normalized_local_time(seconds)
        whole = seconds.floor % 86_400
        hour, remainder = whole.divmod(3600)
        min, sec = remainder.divmod(60)
        nsec = fractional_nanoseconds(seconds)
        if @value.sec == 60 && whole >= 86_400 && seconds < 86_401
          return [1970, 1, 1, 23, 59, 60, nsec]
        end

        [1970, 1, 1, hour, min, sec, nsec]
      end

      def fractional_nanoseconds(seconds)
        ((seconds - seconds.floor) * 1_000_000_000).to_i
      end

      def time_zone
        @timezone
      end

      def valid_time_zone?
        time_zone.is_a?(Integer) || (time_zone.is_a?(String) && !time_zone.empty?)
      end
    end

  end

  module DatetimeParser
    module_function

    def offset_datetime(year, mon, day, hour, min, sec, sec_frac, offset)
      validate_date(year, mon, day)
      validate_time(hour, min, sec)
      offset = "+00:00" if offset.casecmp?("Z")
      unless offset[1, 2].to_i.between?(0, 23) && offset[4, 2].to_i.between?(0, 59)
        raise ParseError, "Invalid UTC offset: #{offset}"
      end

      Time.new(year, mon, day, hour, min, seconds(sec, legacy_fraction(sec_frac)), offset)
    end

    def local_datetime(year, mon, day, hour, min, sec, sec_frac)
      validate_date(year, mon, day)
      validate_time(hour, min, sec)
      LocalDateTime.utc(year, mon, day, hour, min, seconds(sec, legacy_fraction(sec_frac)))
    end

    def local_date(year, mon, day)
      validate_date(year, mon, day)
      LocalDate.utc(year, mon, day)
    end

    def local_time(hour, min, sec, sec_frac)
      validate_time(hour, min, sec)
      LocalTime.utc(1970, 1, 1, hour, min, seconds(sec, legacy_fraction(sec_frac)))
    end

    def offset_datetime_value(year, mon, day, hour, min, sec, sec_frac, offset)
      validate_date(year, mon, day)
      validate_time(hour, min, sec)
      offset = "Z" if offset.casecmp?("Z")
      validate_offset(offset)
      Temporal::OffsetDateTime.new(year, mon, day, hour, min, sec, sec_frac, offset)
    end

    def local_datetime_value(year, mon, day, hour, min, sec, sec_frac)
      validate_date(year, mon, day)
      validate_time(hour, min, sec)
      Temporal::LocalDateTime.new(year, mon, day, hour, min, sec, sec_frac)
    end

    def local_date_value(year, mon, day)
      validate_date(year, mon, day)
      Temporal::LocalDate.new(year, mon, day)
    end

    def local_time_value(hour, min, sec, sec_frac)
      validate_time(hour, min, sec)
      Temporal::LocalTime.new(hour, min, sec, sec_frac)
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

    def validate_offset(offset)
      unless offset == "Z" || (offset.match?(/\A[+-]\d\d:\d\d\z/) &&
          offset[1, 2].to_i.between?(0, 23) &&
          offset[4, 2].to_i.between?(0, 59))
        raise ParseError, "Invalid UTC offset: #{offset}"
      end
    end

    def seconds(sec, sec_frac)
      "#{sec || 0}.#{sec_frac || 0}".to_r
    end

    def legacy_fraction(sec_frac)
      sec_frac&.slice(0, 9)
    end
  end
end
