module IceCube
  class IcalParser
    DATETIME_PATTERN = /\A(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z)?\z/
    DATE_PATTERN = /\A(\d{4})(\d{2})(\d{2})\z/
    OFFSET_PATTERN = /\A([+-])(\d{2})(\d{2})(?:(\d{2}))?\z/

    def self.schedule_from_ical(ical_string, options = {})
      data = {}
      years = options.fetch(:timezone_years, options[:years])
      strict = options.key?(:timezone_years) || options.key?(:years)
      timezones = {}
      timezone = nil
      observation = nil

      unfolded_lines(ical_string).each do |line|
        property_string, value = line.rstrip.split(":", 2)
        next if property_string.nil? || value.nil?

        property, parameters = parse_property(property_string)
        value = value.strip

        if observation
          if property == "END" && %w[STANDARD DAYLIGHT].include?(value)
            timezone[:observations] << observation
            observation = nil
          else
            read_observation_line(observation, property, parameters, value)
          end
          next
        end

        if timezone
          case [property, value]
          when ["END", "VTIMEZONE"]
            zone = build_timezone(timezone, years)
            raise ArgumentError, "duplicate VTIMEZONE #{zone.name.inspect}" if timezones.key?(zone.name)
            timezones[zone.name] = zone
            timezone = nil
          when ["BEGIN", "STANDARD"], ["BEGIN", "DAYLIGHT"]
            observation = new_observation(value)
          else
            read_timezone_line(timezone, property, parameters, value)
          end
          next
        end

        if property == "BEGIN"
          if value == "VTIMEZONE" && !strict
            raise ArgumentError, "pass timezone_years to import an iCalendar with VTIMEZONE"
          end
          unless value == "VCALENDAR" || value == "VEVENT" || value == "VTIMEZONE"
            raise ArgumentError, "unsupported iCalendar component #{value}"
          end
          if value == "VTIMEZONE"
            timezone = {name: nil, observations: []}
          end
          next
        elsif property == "END"
          unless value == "VCALENDAR" || value == "VEVENT" || value == "VTIMEZONE"
            raise ArgumentError, "unsupported iCalendar component #{value}"
          end
          next
        end

        next unless %w[DTSTART DTEND RDATE EXDATE RRULE].include?(property)

        case property
        when "DTSTART"
          data[:start_time] = parse_time(value, parameters, strict, timezones)
        when "DTEND"
          data[:end_time] = parse_time(value, parameters, strict, timezones)
        when "RDATE"
          data[:rtimes] ||= []
          data[:rtimes].concat parse_time_list(value, parameters, strict, timezones)
        when "EXDATE"
          data[:extimes] ||= []
          data[:extimes].concat parse_time_list(value, parameters, strict, timezones)
        when "RRULE"
          data[:rrules] ||= []
          data[:rrules] << rule_from_ical(value, strict)
        end
      end

      raise ArgumentError, "iCalendar VTIMEZONE is not properly closed" if timezone || observation

      Schedule.from_hash data
    end

    def self.rule_from_ical(ical, strict = false)
      raise ArgumentError, "empty ical rule" if ical.nil?

      validations = {}
      params = {validations: validations, interval: 1}

      ical.split(";").each do |rule|
        (name, value) = rule.split("=")
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
          params[:until] = parse_utc_time(value, strict)
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

    def self.unfolded_lines(ical_string)
      lines = []
      ical_string.each_line do |line|
        line = line.chomp
        line = line[0..-2] if line.end_with?("\r")
        if lines.any? && line.start_with?(" ", "\t")
          lines[-1] += line.sub(/\A[ \t]+/, "")
        else
          lines << line
        end
      end
      lines
    end

    def self.parse_property(property_string)
      name, *parameter_strings = property_string.split(";")
      parameters = {}
      parameter_strings.each do |parameter_string|
        key, parameter_value = parameter_string.split("=", 2)
        parameters[key.upcase] = unquote(parameter_value)
      end
      [name.upcase, parameters]
    end

    def self.unquote(value)
      value = value[1..-2] if value&.start_with?('"') && value.end_with?('"')
      value
    end

    def self.new_observation(kind)
      {kind: kind.downcase.to_sym, dtstart: nil, rrule: nil, offset_from: nil, offset_to: nil}
    end

    def self.read_observation_line(observation, property, parameters, value)
      unless parameters.empty?
        raise ArgumentError, "unsupported parameters on VTIMEZONE #{property}"
      end

      case property
      when "DTSTART"
        observation[:dtstart] = parse_floating_template(value)
      when "RRULE"
        observation[:rrule] = value
      when "TZOFFSETFROM"
        observation[:offset_from] = parse_offset(value)
      when "TZOFFSETTO"
        observation[:offset_to] = parse_offset(value)
      when "TZNAME"
        nil
      else
        raise ArgumentError, "unsupported VTIMEZONE property #{property}"
      end
    end

    def self.read_timezone_line(timezone, property, parameters, value)
      unless parameters.empty?
        raise ArgumentError, "unsupported parameters on VTIMEZONE #{property}"
      end

      case property
      when "TZID"
        raise ArgumentError, "VTIMEZONE has multiple TZID values" unless timezone[:name].nil?
        timezone[:name] = value
      else
        raise ArgumentError, "unsupported VTIMEZONE property #{property}"
      end
    end

    def self.build_timezone(timezone, years)
      name = timezone[:name]
      raise ArgumentError, "VTIMEZONE is missing TZID" if name.nil?
      unless timezone[:observations].size == 2
        raise ArgumentError, "VTIMEZONE #{name.inspect} requires one STANDARD and one DAYLIGHT rule"
      end

      observations = timezone[:observations].map { |fields| build_observation(name, fields) }
      IcalTimezone.new(name, observations, years || [])
    end

    def self.build_observation(name, fields)
      missing = [:dtstart, :rrule, :offset_from, :offset_to].select { |key| fields[key].nil? }
      unless missing.empty?
        raise ArgumentError, "VTIMEZONE #{name.inspect} #{fields[:kind]} is missing #{missing.join(", ")}"
      end

      rule = parse_observation_rrule(name, fields[:kind], fields[:rrule])
      IcalTimezone::Observation.new(
        fields[:kind], fields[:dtstart], fields[:offset_from], fields[:offset_to],
        rule[:month], rule[:monthday], rule[:weekday], rule[:week]
      )
    end

    def self.parse_observation_rrule(name, kind, ical)
      parts = parse_rule_parts(name, kind, ical)
      unless parts["FREQ"] == "YEARLY" && (!parts.key?("INTERVAL") || parts["INTERVAL"] == "1")
        raise ArgumentError, "VTIMEZONE #{name.inspect} only supports yearly observations"
      end
      month = parse_month(name, kind, parts.delete("BYMONTH"))
      monthday, weekday, week = parse_observation_day(name, kind, parts)
      parts.delete("FREQ")
      parts.delete("INTERVAL")
      unless parts.empty?
        raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} contains an unsupported RRULE part"
      end

      {month: month, monthday: monthday, weekday: weekday, week: week}
    end

    def self.parse_rule_parts(name, kind, ical)
      ical.split(";").each_with_object({}) do |part, result|
        key, value = part.split("=", 2)
        if key.nil? || value.nil? || value.empty? || result.key?(key)
          raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} has an invalid RRULE"
        end
        result[key] = value
      end
    end

    def self.parse_month(name, kind, value)
      raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} requires BYMONTH" unless value
      month = Integer(value, exception: false)
      unless month && (1..12).cover?(month) && value.match?(/\A\d{1,2}\z/)
        raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} has an invalid BYMONTH value"
      end
      month
    end

    def self.parse_observation_day(name, kind, parts)
      if parts.key?("BYMONTHDAY")
        if parts.key?("BYDAY")
          raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} cannot combine BYMONTHDAY and BYDAY"
        end
        value = parts.delete("BYMONTHDAY")
        day = Integer(value, exception: false)
        unless day && (1..31).cover?(day) && value.match?(/\A\d{1,2}\z/)
          raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} has an invalid BYMONTHDAY value"
        end
        [day, nil, nil]
      else
        value = parts.delete("BYDAY")
        raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} requires BYMONTHDAY or BYDAY" unless value
        match = /\A([+-]?[1-5])([A-Z]{2})\z/.match(value)
        unless match
          raise ArgumentError, "VTIMEZONE #{name.inspect} #{kind} has an invalid BYDAY value"
        end
        [nil, TimeUtil::DAYS.fetch(TimeUtil.ical_day_to_symbol(match[2])), Integer(match[1])]
      end
    end

    def self.parse_floating_template(value)
      details = parse_datetime_parts(value)
      unless details[:utc].nil?
        raise ArgumentError, "VTIMEZONE DTSTART must be floating local time"
      end
      Time.utc(*details[:parts])
    end

    def self.parse_offset(value)
      match = OFFSET_PATTERN.match(value)
      raise ArgumentError, "invalid VTIMEZONE offset #{value.inspect}" unless match

      sign = match[1] == "-" ? -1 : 1
      sign * (match[2].to_i * 3600 + match[3].to_i * 60 + match[4].to_i)
    end

    def self.parse_time_list(value, parameters, strict, timezones)
      value.split(",").map { |item| parse_time(item, parameters, strict, timezones) }
    end

    def self.parse_time(value, parameters, strict, timezones)
      return TimeUtil.deserialize_time(value) unless strict

      tzid = parameters["TZID"]
      if tzid
        unless parameters.keys == ["TZID"]
          raise ArgumentError, "unsupported parameters on TZID date-time #{value.inspect}"
        end
        zone = timezones[tzid] or raise ArgumentError, "unknown TZID #{tzid.inspect}"
        return zone.local_from_parts(datetime_parts(value))
      end

      if parameters.key?("VALUE") && parameters["VALUE"] == "DATE"
        unless parameters.keys == ["VALUE"]
          raise ArgumentError, "unsupported parameters on date #{value.inspect}"
        end
        return IcalTimezone.floating_time(date_parts(value))
      end

      unless parameters.empty?
        raise ArgumentError, "unsupported parameters on date-time #{value.inspect}"
      end

      details = parse_datetime_parts(value)
      if details[:utc]
        Time.utc(*details[:parts])
      else
        IcalTimezone.floating_time(details[:parts])
      end
    end

    def self.parse_utc_time(value, strict)
      return TimeUtil.deserialize_time(value).utc unless strict

      details = parse_datetime_parts(value)
      raise ArgumentError, "RRULE UNTIL must use UTC time" if details[:utc].nil?
      Time.utc(*details[:parts])
    end

    def self.parse_datetime_parts(value)
      match = DATETIME_PATTERN.match(value)
      raise ArgumentError, "invalid iCalendar date-time #{value.inspect}" unless match

      parts = [1, 2, 3, 4, 5, 6].map { |index| match[index].to_i }
      Date.new(parts[0], parts[1], parts[2])
      {parts: parts, utc: match[7]}
    end

    def self.datetime_parts(value)
      parse_datetime_parts(value)[:parts]
    end

    def self.date_parts(value)
      match = DATE_PATTERN.match(value)
      raise ArgumentError, "invalid iCalendar date #{value.inspect}" unless match

      parts = [1, 2, 3].map { |index| match[index].to_i }
      Date.new(*parts)
      parts
    end

    private_class_method :unfolded_lines, :parse_property, :unquote, :new_observation,
      :read_observation_line, :read_timezone_line, :build_timezone, :build_observation,
      :parse_observation_rrule, :parse_rule_parts, :parse_month, :parse_observation_day,
      :parse_floating_template, :parse_offset, :parse_time_list, :parse_time,
      :parse_utc_time, :parse_datetime_parts, :datetime_parts, :date_parts
  end
end
