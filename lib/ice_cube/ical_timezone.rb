require "date"
require "time"

module IceCube
  class IcalTimezone
    Observation = Struct.new(
      :kind, :dtstart, :offset_from, :offset_to,
      :month, :monthday, :weekday, :week
    ) do
      def daylight?
        kind == :daylight
      end
    end

    Transition = Struct.new(:utc_time, :local_wall, :offset_from, :offset_to, :daylight)
    Period = Struct.new(:offset, :dst)

    class ScopedTime < ::Time
      attr_reader :time_zone

      def self.from_utc(time, zone)
        utc_time = ::Time.at(time.to_r).utc
        scoped_time = at(utc_time.to_r).getlocal(zone.period_for_utc(utc_time).offset)
        scoped_time.instance_variable_set(:@time_zone, zone)
        scoped_time
      end

      def floating?
        false
      end

      def ical_tzid
        time_zone.name
      end

      def zone
        time_zone.name
      end

      def dst?
        time_zone.period_for_utc(self).dst
      end
      alias_method :isdst, :dst?

      def utc
        ::Time.at(to_r).utc
      end
      alias_method :getutc, :utc

      def in_time_zone(zone)
        return self if zone.nil? || zone == time_zone || zone == time_zone.name
        return zone.utc_to_local(self) if zone.respond_to?(:utc_to_local)

        utc_time = ::Time.at(to_r).utc
        utc_time.in_time_zone(zone)
      end

      def +(seconds)
        self.class.from_utc(super, time_zone)
      end

      def -(seconds)
        return super unless seconds.is_a?(Numeric)

        self.class.from_utc(super, time_zone)
      end
    end

    class FloatingTime < ::Time
      def self.from_parts(year, month = 1, day = 1, hour = 0, minute = 0, second = 0)
        at(::Time.utc(year, month, day, hour, minute, second).to_r).utc
      end

      def floating?
        true
      end

      def ical_tzid
        nil
      end

      def zone
        nil
      end

      def dst?
        false
      end
      alias_method :isdst, :dst?

      def +(seconds)
        self.class.at(super.to_r).utc
      end

      def -(seconds)
        return super unless seconds.is_a?(Numeric)

        ::Time.at(super.to_r).utc
      end
    end

    def self.floating_time(parts)
      FloatingTime.from_parts(*parts)
    end

    attr_reader :name

    def initialize(name, observations, years)
      years = Array(years).map(&:to_i).uniq.sort
      raise ArgumentError, "a year range is required for VTIMEZONE #{name.inspect}" if years.empty?
      unless years.each_cons(2).all? { |first_year, second_year| second_year == first_year + 1 }
        raise ArgumentError, "VTIMEZONE #{name.inspect} years must be contiguous"
      end
      validate_observations(name, observations)

      @name = name
      @first_year = years.first
      @last_year = years.last
      @transitions = build_transitions(observations, transition_years)
      @initial_offset = @transitions.first.offset_from
    end

    def local(year, month = 1, day = 1, hour = 0, minute = 0, second = 0)
      wall = ::Time.utc(year, month, day, hour, minute, second)
      ensure_supported_year(wall.year)

      transition = transition_before_local(wall)
      offset = transition ? transition.offset_to : @initial_offset
      utc_time = wall - offset

      if transition && period_for_utc(utc_time).offset != offset
        utc_time += transition.offset_to - transition.offset_from
      end

      ScopedTime.from_utc(utc_time, self)
    end

    def local_from_parts(parts)
      local(*parts)
    end

    def utc_to_local(time)
      utc_time = time.utc
      ensure_supported_year((utc_time + period_for_utc(utc_time).offset).year)
      ScopedTime.from_utc(utc_time, self)
    end

    def period_for_utc(time)
      utc_time = time.utc
      transition = @transitions.take_while { |candidate| utc_time >= candidate.utc_time }.last
      offset = transition ? transition.offset_to : @initial_offset

      Period.new(offset, transition ? transition.daylight : false)
    end

    private

    def validate_observations(name, observations)
      unless observations.size == 2 && observations.map(&:kind).sort == [:daylight, :standard]
        raise ArgumentError, "VTIMEZONE #{name.inspect} requires one STANDARD and one DAYLIGHT rule"
      end

      observations.each do |observation|
        if observation.offset_from == observation.offset_to
          raise ArgumentError, "VTIMEZONE #{name.inspect} #{observation.kind} does not change offset"
        end
        validate_dtstart(name, observation)
      end
    end

    def validate_dtstart(name, observation)
      expected = observation_date(name, observation, observation.dtstart.year)
      actual = observation.dtstart
      return if expected.year == actual.year &&
        expected.month == actual.month &&
        expected.day == actual.day

      raise ArgumentError, "VTIMEZONE #{name.inspect} DTSTART does not match its RRULE"
    end

    def observation_date(name, observation, year)
      if observation.monthday
        Date.new(year, observation.month, observation.monthday)
      else
        dates = (
          Date.new(year, observation.month, 1)..
          Date.new(year, observation.month, -1)
        ).select { |date| date.wday == observation.weekday }
        dates.fetch(observation.week.positive? ? observation.week - 1 : observation.week) do
          raise ArgumentError, "VTIMEZONE #{name.inspect} has an invalid BYDAY occurrence"
        end
      end
    end

    def build_transitions(observations, years)
      transitions = years.flat_map do |year|
        observations.map do |observation|
          date = observation_date(name, observation, year)
          wall = ::Time.utc(
            year, date.month, date.day,
            observation.dtstart.hour, observation.dtstart.min, observation.dtstart.sec
          )
          Transition.new(
            wall - observation.offset_from, wall,
            observation.offset_from, observation.offset_to, observation.daylight?
          )
        end
      end.sort_by(&:utc_time)

      validate_transitions(name, transitions)
      transitions
    end

    def validate_transitions(name, transitions)
      previous = nil
      transitions.each do |transition|
        if previous
          if transition.utc_time <= previous.utc_time
            raise ArgumentError, "VTIMEZONE #{name.inspect} has conflicting observations"
          end
          if transition.local_wall == previous.local_wall
            raise ArgumentError, "VTIMEZONE #{name.inspect} has conflicting observations"
          end
          unless transition.offset_from == previous.offset_to
            raise ArgumentError, "VTIMEZONE #{name.inspect} observations do not chain consistently"
          end
        end
        previous = transition
      end
    end

    def transition_before_local(wall)
      @transitions.take_while { |transition| wall >= transition.local_wall }.last
    end

    def transition_years
      (@first_year - 1)..(@last_year + 1)
    end

    def ensure_supported_year(year)
      return if year >= @first_year && year <= @last_year

      raise ArgumentError, "#{name.inspect} is only supported for years #{@first_year} through #{@last_year}"
    end
  end
end
