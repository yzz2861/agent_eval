require "date"

module IceCube
  class LocalTimeZone
    Period = Struct.new(:offset, :abbreviation, :daylight, :starts_at, :ends_at, keyword_init: true)
    Observation = Struct.new(
      :kind, :starts_at, :offset_from, :offset_to, :abbreviation, :rule, :rrule,
      keyword_init: true
    )
    Transition = Struct.new(:at, :offset, :abbreviation, :daylight, :observation, keyword_init: true)

    class InvalidTimezoneError < ArgumentError
    end

    class UnsupportedYearError < ArgumentError
    end

    attr_reader :name, :first_year, :last_year, :observations

    def initialize(name, observations, year_range)
      @name = name
      @observations = observations
      @first_year, @last_year = validate_year_range(year_range)
      @transitions = build_transitions
    end

    def local(year, month, day, hour, minute, second)
      wall_time = Time.utc(year, month, day, hour, minute, second)
      if year < first_year || year > last_year
        raise UnsupportedYearError, unsupported_year_message(year)
      end
      local_for_wall_time(wall_time)
    end

    def local_for_table(year, month, day, hour, minute, second)
      wall_time = Time.utc(year, month, day, hour, minute, second)
      unless year.between?(first_year - 1, last_year + 1)
        raise UnsupportedYearError, unsupported_year_message(year)
      end
      local_for_wall_time(wall_time)
    end

    def validate_supported_wall_year(year)
      unless year.between?(first_year, last_year)
        raise UnsupportedYearError, unsupported_year_message(year)
      end
    end

    def period_for_utc(utc_time)
      transition = @transitions.reverse_each.detect { |candidate| candidate.at <= utc_time }
      if transition.nil?
        raise InvalidTimezoneError, "#{name} has no observation before #{utc_time.iso8601}"
      end

      period_from_transition(transition)
    end

    def time_from_utc(utc_time)
      time = LocalTime.from_utc(utc_time, self)
      year = time.year
      if year < first_year || year > last_year
        raise UnsupportedYearError, unsupported_year_message(year)
      end

      time
    end

    def time_from_utc!(utc_time)
      LocalTime.from_utc(utc_time, self)
    end

    def to_ical
      lines = ["BEGIN:VTIMEZONE", "TZID:#{name}"]
      observations.each do |observation|
        lines << "BEGIN:#{observation.kind}"
        lines << "DTSTART:#{observation.starts_at.strftime("%Y%m%dT%H%M%S")}"
        lines << "RRULE:#{observation.rrule}" if observation.rrule
        lines << "TZNAME:#{observation.abbreviation}" if observation.abbreviation
        lines << "TZOFFSETFROM:#{format_offset(observation.offset_from)}"
        lines << "TZOFFSETTO:#{format_offset(observation.offset_to)}"
        lines << "END:#{observation.kind}"
      end
      lines << "END:VTIMEZONE"
      lines.join("\n")
    end

    private

    def validate_year_range(year_range)
      years =
        case year_range
        when Range then [year_range.first, year_range.last]
        when Integer then [year_range, year_range]
        when Array then [year_range.min, year_range.max]
        else
          raise ArgumentError, "years must be a Range, Integer, or Array of Integers"
        end

      unless years.all? { |year| year.is_a?(Integer) } && years.first <= years.last
        raise ArgumentError, "years must be an ascending range of Integers"
      end

      years
    end

    def build_transitions
      transitions = observations.flat_map { |observation| transitions_for(observation) }.sort_by(&:at)
      validate_transitions(transitions)
      transitions
    end

    def transitions_for(observation)
      years = transition_years(observation)
      years.filter_map do |year|
        date =
          if observation.rule
            recurrence_date(observation, year)
          elsif observation.starts_at.year == year
            Date.new(year, observation.starts_at.month, observation.starts_at.day)
          end

        next unless date

        if observation.rule && year == observation.starts_at.year
          anchor = Date.new(
            observation.starts_at.year, observation.starts_at.month, observation.starts_at.day
          )
          unless anchor == date
            raise InvalidTimezoneError, "DTSTART does not match RRULE for #{observation.kind} in #{name}"
          end
        end

        at = Time.utc(
          date.year, date.month, date.day,
          observation.starts_at.hour, observation.starts_at.min, observation.starts_at.sec
        ) - observation.offset_from
        Transition.new(
          at: at,
          offset: observation.offset_to,
          abbreviation: observation.abbreviation,
          daylight: observation.kind == "DAYLIGHT",
          observation: observation
        )
      end
    end

    def transition_years(observation)
      if observation.rule
        (first_year - 1..last_year + 1).to_a
      else
        [observation.starts_at.year]
      end
    end

    def recurrence_date(observation, year)
      rule = observation.rule
      if rule[:month_day]
        Date.new(year, rule[:month], rule[:month_day])
      else
        month_dates = ((Date.new(year, rule[:month], 1)..Date.new(year, rule[:month], -1))).select do |date|
          date.wday == rule[:weekday]
        end
        index = rule[:week]
        if index.positive?
          month_dates[index - 1]
        else
          month_dates[index]
        end
      end
    rescue Date::Error
      nil
    end

    def validate_transitions(transitions)
      if transitions.empty?
        raise InvalidTimezoneError, "VTIMEZONE #{name} contains no observations in #{first_year}..#{last_year}"
      end

      transitions.each_cons(2) do |previous, transition|
        if previous.at == transition.at
          raise InvalidTimezoneError, "conflicting VTIMEZONE observations in #{name} at #{transition.at.iso8601}"
        elsif previous.observation.offset_to != transition.observation.offset_from
          raise InvalidTimezoneError, "conflicting VTIMEZONE offsets in #{name} at #{transition.at.iso8601}"
        elsif previous.daylight == transition.daylight
          kind = transition.daylight ? "DAYLIGHT" : "STANDARD"
          raise InvalidTimezoneError, "consecutive #{kind} observations in #{name} are not allowed"
        elsif transition.at + transition.observation.offset_from < previous.at + previous.offset
          raise InvalidTimezoneError, "conflicting VTIMEZONE observations in #{name} near #{transition.at.iso8601}"
        end
      end
    end

    def periods_for_wall_time(wall_time)
      periods = []
      @transitions.each do |transition|
        period = period_from_transition(transition)
        utc_time = wall_time - period.offset
        periods << period if period_for_utc(utc_time) == period
      end
      periods
    end

    def period_from_transition(transition)
      next_transition = @transitions[@transitions.index(transition) + 1]
      Period.new(
        offset: transition.offset,
        abbreviation: transition.abbreviation,
        daylight: transition.daylight,
        starts_at: transition.at,
        ends_at: next_transition&.at
      )
    end

    def unsupported_year_message(year)
      "#{year} is outside the supported VTIMEZONE years #{first_year}..#{last_year} for #{name}"
    end

    def local_for_wall_time(wall_time)
      periods = periods_for_wall_time(wall_time)
      if periods.empty?
        raise InvalidTimezoneError, "local time #{wall_time.strftime("%Y-%m-%dT%H:%M:%S")} does not exist in #{name}"
      elsif periods.length > 1
        raise InvalidTimezoneError, "local time #{wall_time.strftime("%Y-%m-%dT%H:%M:%S")} is ambiguous in #{name}"
      end

      period = periods.first
      LocalTime.from_utc(wall_time - period.offset, self)
    end

    def format_offset(offset)
      sign = offset.negative? ? "-" : "+"
      absolute = offset.abs
      hours = absolute / 3600
      minutes = (absolute % 3600) / 60
      seconds = absolute % 60
      value = format("%s%02d%02d", sign, hours, minutes)
      value << format("%02d", seconds) if seconds.nonzero?
      value
    end
  end
end
