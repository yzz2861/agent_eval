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
        property_part, value = line.chomp.split(":", 2)
        property, *params = property_part.split(";")
        params = parse_params(params)
        case property
        when "DTSTART"
          data[:start_time] = parse_time_value(value, params)
        when "DTEND"
          data[:end_time] = parse_time_value(value, params)
        when "RDATE"
          data[:rtimes] ||= []
          data[:rtimes] += parse_rdate_value(value, params)
        when "EXDATE"
          data[:extimes] ||= []
          data[:extimes] += value.split(",").map { |v| parse_time_value(v, params) }
        when "DURATION"
          data[:duration] # FIXME
        when "RRULE"
          data[:rrules] ||= []
          data[:rrules] += [rule_from_ical(value)]
        end
      end
      Schedule.from_hash data
    end

    def self.parse_params(params)
      params.each_with_object({}) do |param, hash|
        name, param_value = param.split("=", 2)
        hash[name.upcase.to_sym] = param_value
      end
    end

    def self.parse_time_value(value, params)
      time = TimeUtil.deserialize_time(value)
      apply_tzid(time, params[:TZID])
    end

    def self.apply_tzid(time, tzid)
      return time unless tzid
      if Object.const_defined?(:ActiveSupport) && ActiveSupport::TimeZone[tzid]
        ActiveSupport::TimeZone[tzid].local(time.year, time.month, time.day, time.hour, time.min, time.sec)
      else
        time
      end
    end

    def self.parse_rdate_value(value, params)
      if params[:VALUE]&.upcase == "PERIOD"
        value.split(",").map { |v| parse_period_value(v, params) }
      else
        value.split(",").map { |v| parse_time_value(v, params) }
      end
    end

    # A period is either start/end (DATE-TIME/DATE-TIME) or start/duration
    # (DATE-TIME/DURATION). It is represented in the hash as start/end_time.
    def self.parse_period_value(value, params)
      start_value, end_value = value.split("/")
      raise ArgumentError, "Invalid iCal period: #{value}" unless start_value && end_value
      start_time = parse_time_value(start_value, params)
      end_time =
        if end_value.start_with?("P", "+", "-")
          start_time + IcalBuilder.ical_duration_to_seconds(end_value)
        else
          parse_time_value(end_value, params)
        end
      {time: start_time, end_time: end_time}
    end

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
