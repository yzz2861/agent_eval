require "time"

module IceCube
  class IcalParser
    ICAL_TIME = /\A(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?\z/
    ICAL_OFFSET = /\A([+-])(\d{2})(\d{2})(?:(\d{2}))?\z/
    ICAL_WEEKDAYS = {
      "SU" => :sunday, "MO" => :monday, "TU" => :tuesday, "WE" => :wednesday,
      "TH" => :thursday, "FR" => :friday, "SA" => :saturday
    }.freeze

    def self.schedule_from_ical(ical_string, options = {})
      lines = unfold_lines(ical_string)
      year_range = normalize_year_range(options[:years] || options[:year_range])
      timezones, event_lines = year_range ? scan_calendar(lines, year_range) : [{}, lines]
      data = {}

      event_lines.each do |line|
        property, parameters, value = parse_property(line)
        case property
        when "DTSTART"
          data[:start_time] = schedule_time(value, parameters, timezones, year_range)
        when "DTEND"
          data[:end_time] = schedule_time(value, parameters, timezones, year_range)
        when "RDATE"
          data[:rtimes] ||= []
          data[:rtimes] += value.split(",").map { |item| schedule_time(item, parameters, timezones, year_range) }
        when "EXDATE"
          data[:extimes] ||= []
          data[:extimes] += value.split(",").map { |item| schedule_time(item, parameters, timezones, year_range) }
        when "RRULE"
          data[:rrules] ||= []
          data[:rrules] << rule_from_ical(value, timezones: timezones, year_range: year_range)
        when "DURATION"
          data[:duration]
        end
      end

      Schedule.from_hash data
    end

    def self.rule_from_ical(ical, timezones: {}, year_range: nil)
      raise ArgumentError, "empty ical rule" if ical.nil?

      validations = {}
      params = {validations: validations, interval: 1}

      ical.split(";").each do |rule|
        (name, value) = rule.split("=", 2)
        raise ArgumentError, "Invalid iCal rule component" if value.nil?
        value.strip!
        case name
        when "FREQ"
          params[:rule_type] = "IceCube::#{value[0]}#{value.downcase[1..]}Rule"
        when "INTERVAL"
          params[:interval] = value.to_i
        when "COUNT"
          params[:count] = value.to_i
        when "UNTIL"
      time = year_range ? parse_ical_time(value, {}, timezones, year_range) : TimeUtil.deserialize_time(value)
          params[:until] = time.utc
        when "WKST"
          params[:week_start] = TimeUtil.ical_day_to_symbol(value)
        when "BYSECOND"
          validations[:second_of_minute] = value.split(",").map(&:to_i)
        when "BYMINUTE"
          validations[:minute_of_hour] = value.split(",").map(&:to_i)
        when "BYHOUR"
          validations[:hour_of_day] = value.split(",").map(&:to_i)
        when "BYDAY"
          dows = {}
          days = []
          value.split(",").each do |expr|
            day = TimeUtil.ical_day_to_symbol(expr.strip[-2..])
            if expr.strip.length > 2
              occ = expr[0..-3].to_i
              dows[day].nil? ? dows[day] = [occ] : dows[day].push(occ)
              days.delete(TimeUtil.sym_to_wday(day))
            elsif dows[day].nil?
              days.push TimeUtil.sym_to_wday(day)
            end
          end
          validations[:day_of_week] = dows unless dows.empty?
          validations[:day] = days unless days.empty?
        when "BYMONTHDAY"
          validations[:day_of_month] = value.split(",").map(&:to_i)
        when "BYMONTH"
          validations[:month_of_year] = value.split(",").map(&:to_i)
        when "BYYEARDAY"
          validations[:day_of_year] = value.split(",").map(&:to_i)
        when "BYSETPOS"
          validations[:by_set_pos] = value.split(",").map(&:to_i)
        else
          validations[name] = nil
        end
      end

      Rule.from_hash(params)
    end

    def self.unfold_lines(ical_string)
      lines = []
      ical_string.each_line do |line|
        line = line.chomp
        if lines.any? && line.start_with?(" ", "\t")
          lines[-1] = lines[-1] + line.strip
        else
          lines << line
        end
      end
      lines
    end

    def self.scan_calendar(lines, year_range)
      timezones = {}
      event_lines = []
      timezone_lines = nil

      lines.each do |line|
        property, _parameters, value = parse_property(line)
        if property == "BEGIN" && value == "VTIMEZONE"
          raise LocalTimeZone::InvalidTimezoneError, "nested VTIMEZONE components are not supported" if timezone_lines
          timezone_lines = [line]
        elsif timezone_lines
          timezone_lines << line
          if property == "END" && value == "VTIMEZONE"
            timezone = parse_timezone(timezone_lines, year_range)
            if timezones.key?(timezone.name)
              raise LocalTimeZone::InvalidTimezoneError, "duplicate VTIMEZONE #{timezone.name}"
            end
            timezones[timezone.name] = timezone
            timezone_lines = nil
          end
        else
          event_lines << line
        end
      end

      if timezone_lines
        raise LocalTimeZone::InvalidTimezoneError, "unclosed VTIMEZONE component"
      end

      [timezones, event_lines]
    end

    def self.parse_timezone(lines, year_range)
      name = nil
      observations = []
      observation_lines = nil
      observation_kind = nil

      lines.each do |line|
        property, _parameters, value = parse_property(line)
        if property == "BEGIN" && %w[STANDARD DAYLIGHT].include?(value)
          if observation_lines
            raise LocalTimeZone::InvalidTimezoneError, "nested VTIMEZONE observations are not supported"
          end
          if observations.any? { |observation| observation.kind == value }
            raise LocalTimeZone::InvalidTimezoneError, "duplicate #{value} observation"
          end
          observation_kind = value
          observation_lines = [line]
        elsif observation_lines
          observation_lines << line
          if property == "END" && value == observation_kind
            observations << parse_observation(observation_lines, observation_kind)
            observation_lines = nil
            observation_kind = nil
          end
        elsif property == "TZID"
          name = value
        elsif !%w[BEGIN END VTIMEZONE].include?(property)
          raise LocalTimeZone::InvalidTimezoneError, "unsupported VTIMEZONE property #{property}"
        end
      end

      if name.nil? || name.empty?
        raise LocalTimeZone::InvalidTimezoneError, "VTIMEZONE requires TZID"
      end
      if observations.empty?
        raise LocalTimeZone::InvalidTimezoneError, "VTIMEZONE #{name} requires an observation"
      end
      if observation_lines
        raise LocalTimeZone::InvalidTimezoneError, "unclosed #{observation_kind} observation"
      end

      LocalTimeZone.new(name, observations, year_range)
    end

    def self.parse_observation(lines, kind)
      values = {}
      lines.each do |line|
        property, _parameters, value = parse_property(line)
        next if %w[BEGIN END].include?(property)
        unless %w[DTSTART RRULE TZNAME TZOFFSETFROM TZOFFSETTO].include?(property)
          raise LocalTimeZone::InvalidTimezoneError, "unsupported #{kind} property #{property}"
        end
        if values.key?(property)
          raise LocalTimeZone::InvalidTimezoneError, "duplicate #{kind} property #{property}"
        end
        values[property] = value
      end

      %w[DTSTART TZOFFSETFROM TZOFFSETTO].each do |property|
        unless values.key?(property)
          raise LocalTimeZone::InvalidTimezoneError, "#{kind} observation requires #{property}"
        end
      end

      starts_at = parse_local_observation_time(values["DTSTART"])
      rrule = values["RRULE"]
      rule = rrule && parse_observation_rule(rrule, starts_at)
      LocalTimeZone::Observation.new(
        kind: kind,
        starts_at: starts_at,
        offset_from: parse_offset(values["TZOFFSETFROM"]),
        offset_to: parse_offset(values["TZOFFSETTO"]),
        abbreviation: values["TZNAME"],
        rule: rule,
        rrule: rrule
      )
    end

    def self.parse_observation_rule(value, _starts_at)
      parts = {}
      value.split(";").each do |part|
        key, rule_value = part.split("=", 2)
        raise LocalTimeZone::InvalidTimezoneError, "invalid VTIMEZONE RRULE #{value.inspect}" if rule_value.nil?
        if parts.key?(key)
          raise LocalTimeZone::InvalidTimezoneError, "duplicate VTIMEZONE RRULE key #{key}"
        end
        parts[key] = rule_value
      end
      allowed = %w[FREQ BYMONTH BYDAY BYMONTHDAY]
      unless parts["FREQ"] == "YEARLY" && parts.keys.all? { |key| allowed.include?(key) }
        raise LocalTimeZone::InvalidTimezoneError, "only yearly VTIMEZONE observations are supported"
      end
      unless parts["BYMONTH"] &&
             ((parts.keys - %w[FREQ BYMONTH BYMONTHDAY]).empty? ||
              (parts.keys - %w[FREQ BYMONTH BYDAY]).empty?)
        raise LocalTimeZone::InvalidTimezoneError, "BYDAY and BYMONTHDAY cannot be combined"
      end

      month = parse_single_integer(parts["BYMONTH"], 1..12)
      rule = {month: month}
      if parts["BYMONTHDAY"]
        month_day = parse_single_integer(parts["BYMONTHDAY"], 1..31)
        unless Date.valid_date?(2000, month, month_day)
          raise LocalTimeZone::InvalidTimezoneError, "invalid VTIMEZONE BYMONTHDAY #{month_day}"
        end
        rule[:month_day] = month_day
      elsif parts["BYDAY"]
        match = parts["BYDAY"].match(/\A(-?[1-5])(SU|MO|TU|WE|TH|FR|SA)\z/)
        unless match
          raise LocalTimeZone::InvalidTimezoneError, "unsupported VTIMEZONE BYDAY rule #{parts["BYDAY"]}"
        end
        rule[:week] = match[1].to_i
        rule[:weekday] = TimeUtil.sym_to_wday(ICAL_WEEKDAYS.fetch(match[2]))
      else
        raise LocalTimeZone::InvalidTimezoneError, "VTIMEZONE yearly observations require BYDAY or BYMONTHDAY"
      end

      rule
    end

    def self.parse_single_integer(value, range)
      integer = value && value.match(/\A-?\d+\z/) && value.to_i
      unless integer && range.cover?(integer)
        raise LocalTimeZone::InvalidTimezoneError, "invalid VTIMEZONE value #{value.inspect}"
      end
      integer
    end

    def self.parse_local_observation_time(value)
      time_parts = parse_time_parts(value)
      unless time_parts
        raise LocalTimeZone::InvalidTimezoneError, "invalid VTIMEZONE observation time #{value}"
      end
      if time_parts[3].nil? || time_parts[6]
        raise LocalTimeZone::InvalidTimezoneError, "VTIMEZONE observation time must be floating local time"
      end
      Time.utc(*time_parts.take(6))
    end

    def self.parse_offset(value)
      match = value && ICAL_OFFSET.match(value)
      unless match
        raise LocalTimeZone::InvalidTimezoneError, "invalid VTIMEZONE offset #{value.inspect}"
      end
      seconds = (match[2].to_i * 3600) + (match[3].to_i * 60) + match[4].to_i
      match[1] == "-" ? -seconds : seconds
    end

    def self.schedule_time(value, parameters, timezones, year_range)
      return TimeUtil.deserialize_time(value) if year_range.nil?
      parse_ical_time(value, parameters, timezones, year_range)
    end

    def self.parse_ical_time(value, parameters, timezones, year_range)
      parts = parse_time_parts(value)
      unless parts
        raise ArgumentError, "invalid iCalendar time #{value.inspect}"
      end
      if parameters["TZID"]
        unless parameters.keys == ["TZID"]
          raise ArgumentError, "unsupported iCalendar parameter #{(parameters.keys - ["TZID"]).first.inspect}"
        end
        if parameters["TZID"].to_s.empty?
          raise ArgumentError, "TZID cannot be empty"
        end
        timezone = timezones.fetch(parameters["TZID"]) do
          raise LocalTimeZone::InvalidTimezoneError, "unknown TZID #{parameters["TZID"].inspect}"
        end
      elsif parameters.any?
        raise ArgumentError, "unsupported iCalendar parameter #{parameters.keys.first.inspect}"
      end

      year, month, day, hour, minute, second, utc_marker = parts
      validate_supported_year(year, year_range)

      if parameters["TZID"]
        if utc_marker || hour.nil?
          raise ArgumentError, "UTC or date values cannot include TZID"
        end
        timezone.local(year, month, day, hour, minute, second)
      elsif utc_marker
        Time.utc(year, month, day, hour, minute, second)
      else
        if hour.nil?
          raise ArgumentError, "iCalendar date values are not supported"
        end
        FloatingTime.local(year, month, day, hour || 0, minute || 0, second || 0)
      end
    end

    def self.normalize_year_range(year_range)
      return if year_range.nil?
      return year_range if year_range.is_a?(Range)
      return year_range..year_range if year_range.is_a?(Integer)
      return year_range.min..year_range.max if year_range.is_a?(Array) && year_range.all? { |year| year.is_a?(Integer) }

      raise ArgumentError, "years must be a Range, Integer, or Array of Integers"
    end

    def self.validate_supported_year(year, year_range)
      first_year = year_range.respond_to?(:first) ? year_range.first : year_range.to_i
      last_year = year_range.respond_to?(:last) ? year_range.last : year_range.to_i
      unless year.between?(first_year, last_year)
        raise LocalTimeZone::UnsupportedYearError,
          "#{year} is outside the supported VTIMEZONE years #{first_year}..#{last_year}"
      end
    end

    def self.parse_time_parts(value)
      match = value && ICAL_TIME.match(value)
      return unless match

      year, month, day, hour, minute, second, utc_marker = match.captures
      [
        year.to_i, month.to_i, day.to_i,
        hour && hour.to_i, minute && minute.to_i, second && second.to_i,
        !utc_marker.nil?
      ]
    end

    def self.parse_property(line)
      name_with_parameters, value = line.split(":", 2)
      raise ArgumentError, "invalid iCalendar property #{line.inspect}" if value.nil?
      name, *parameter_strings = name_with_parameters.split(";")
      parameters = {}
      parameter_strings.each do |parameter|
        key, parameter_value = parameter.split("=", 2)
        parameters[key.upcase] = parameter_value&.delete_prefix('"')&.delete_suffix('"')
      end
      [name.upcase, parameters, value]
    end
  end
end
