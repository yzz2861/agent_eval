module IceCube
  class IcalParser
    def self.schedule_from_ical(ical_string, options = {})
      data = {}

      # First join lines that are wrapped
      lines = []
      ical_string.each_line do |line|
        if lines[-1] && line =~ /\A[ \t].+/
          lines[-1] = lines[-1].strip + line.sub(/\A[ \t]+/, "")
        else
          lines << line
        end
      end

      lines.each do |line|
        line = line.chomp
        (property_with_params, value) = line.split(":", 2)
        property, *params = property_with_params.split(";")
        params = parse_params(params)
        case property
        when "DTSTART"
          data[:start_time] = TimeUtil.parse_ical_time(value, params["TZID"])
        when "DTEND"
          data[:end_time] = TimeUtil.parse_ical_time(value, params["TZID"])
        when "RDATE"
          data[:rtimes] ||= []
          data[:rtimes] += value.split(",").map { |v| parse_recurrence_value(v, params) }
        when "EXDATE"
          data[:extimes] ||= []
          data[:extimes] += value.split(",").map { |v| TimeUtil.parse_ical_time(v, params["TZID"]) }
        when "DURATION"
          data[:duration] = parse_duration(value)
        when "RRULE"
          data[:rrules] ||= []
          data[:rrules] += [rule_from_ical(value)]
        end
      end
      Schedule.from_hash data
    end

    def self.parse_params(params)
      params.each_with_object({}) do |param, hash|
        name, value = param.split("=", 2)
        hash[name.upcase] = value
      end
    end

    def self.parse_recurrence_value(value, params)
      return TimeUtil.parse_ical_time(value, params["TZID"]) unless value.include?("/")

      start_value, end_value = value.split("/", 2)
      start_time = TimeUtil.parse_ical_time(start_value, params["TZID"])
      duration = parse_duration(end_value) if end_value.start_with?("P")
      end_time = if duration
        start_time + duration
      else
        TimeUtil.parse_ical_time(end_value, params["TZID"])
      end
      {time: start_time, end_time: end_time, period_duration: duration}
    end

    def self.parse_duration(value)
      match = /\AP(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?\z/.match(value)
      raise ArgumentError, "Invalid iCalendar duration: #{value}" unless match

      weeks, days, hours, minutes, seconds = match.captures
      seconds.to_f + minutes.to_i * 60 + hours.to_i * 3600 + days.to_i * 86400 + weeks.to_i * 604800
    end

    private_class_method :parse_params, :parse_recurrence_value, :parse_duration

    def self.rule_from_ical(ical)
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
          params[:until] = TimeUtil.deserialize_time(value).utc
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
            if expr.strip.length > 2 # day with occurence
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
          validations[name] = nil # invalid type
        end
      end

      Rule.from_hash(params)
    end
  end
end
