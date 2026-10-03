module IceCube
  class IcalBuilder
    ICAL_DAYS = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"]

    def initialize
      @hash = {}
    end

    def self.fixnum_to_ical_day(num)
      ICAL_DAYS[num]
    end

    def [](key)
      @hash[key] ||= []
    end

    # Build for a single rule entry
    def to_s
      arr = []
      if (freq = @hash.delete("FREQ"))
        arr << "FREQ=#{freq.join(",")}"
      end
      arr.concat(@hash.map do |key, value|
        if value.is_a?(Array)
          "#{key}=#{value.join(",")}"
        end
      end.compact)
      arr.join(";")
    end

    def self.ical_utc_format(time)
      time = time.dup.utc
      IceCube::I18n.l(time, format: "%Y%m%dT%H%M%SZ") # utc time
    end

    def self.ical_format(time, force_utc)
      time = time.dup.utc if force_utc
      if time.utc?
        ":#{IceCube::I18n.l(time, format: "%Y%m%dT%H%M%SZ")}" # utc time
      else
        ";TZID=#{IceCube::I18n.l(time, format: "%Z:%Y%m%dT%H%M%S")}" # local time specified
      end
    end

    def self.ical_time_line(name, time, force_utc, original_params = [])
      time = time.dup.utc if force_utc
      if time.utc?
        params = original_params.reject { |param| param.name.upcase == "TZID" }
        value = IceCube::I18n.l(time, format: "%Y%m%dT%H%M%SZ")
      else
        tzid = IcalContentLine::Parameter.new(
          name: "TZID",
          value: IceCube::I18n.l(time, format: "%Z"),
          quoted: false,
          raw_value: nil
        )
        params = merge_managed_parameter(parameter_objects(original_params), tzid)
        value = IceCube::I18n.l(time, format: "%Y%m%dT%H%M%S")
      end
      content_line(name, params, value)
    end

    def self.ical_rule_line(original_line, rule)
      rendered_params = original_line.params.map { |param| ";#{param}" }.join
      "#{original_line.name.upcase}#{rendered_params}:#{rule.to_ical(true)}"
    end

    def self.content_line(name, params, value)
      rendered_params = params.map { |param| ";#{param}" }.join
      "#{name.upcase}#{rendered_params}:#{value}"
    end

    def self.parameter_objects(params)
      params.map do |param|
        next param if param.is_a?(IcalContentLine::Parameter)
        IcalContentLine::Parameter.new(
          name: param[:name],
          value: param[:value],
          quoted: param[:quoted] || false,
          raw_value: param[:raw_value]
        )
      end
    end

    def self.merge_managed_parameter(params, managed_param)
      result = params.dup
      index = result.index { |param| param.name.upcase == managed_param.name.upcase }
      if index
        result[index] = merge_parameter(result[index], managed_param)
      else
        [managed_param].concat(result)
      end
      result
    end

    def self.merge_parameter(original, managed)
      return managed unless original.is_a?(IcalContentLine::Parameter)
      IcalContentLine::Parameter.new(
        name: managed.name,
        value: managed.value,
        quoted: managed.quoted,
        raw_value: managed.raw_value
      )
    end

    def self.fold_lines(lines)
      lines.map { |line| fold_line(line) }.join("\n")
    end

    def self.fold_line(line)
      result = +""
      remaining = line
      first = true

      until remaining.empty?
        limit = first ? 75 : 74
        chunk_size = [remaining.bytesize, limit].min
        if remaining.bytesize > limit
          chunk_size -= 1 until chunk_size == 0 ||
            remaining.byteslice(0, chunk_size).valid_encoding?
          chunk_size = limit if chunk_size.zero?
        end
        result << "\n " unless first
        result << remaining.byteslice(0, chunk_size)
        remaining = remaining.byteslice(chunk_size, remaining.bytesize)
        first = false
      end

      result
    end

    def self.ical_duration(duration)
      hours = duration / 3600
      duration %= 3600
      minutes = duration / 60
      duration %= 60
      repr = ""
      repr << "#{hours}H" if hours > 0
      repr << "#{minutes}M" if minutes > 0
      repr << "#{duration}S" if duration > 0
      "PT#{repr}"
    end
  end
end
