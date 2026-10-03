require "strscan"

module IceCube
  class IcalParser
    class ParseError < ArgumentError
      attr_reader :line_number, :column, :byte_offset

      def initialize(message, line_number = nil, column = nil, byte_offset = nil)
        location = line_number ? " at line #{line_number}, column #{column}" : ""
        super("#{message}#{location}")
        @line_number = line_number
        @column = column
        @byte_offset = byte_offset
      end
    end

    def self.schedule_from_ical(ical_string, options = {})
      new(ical_string, options).to_schedule
    end

    def self.rule_from_ical(ical, content_line = nil, preserve = false)
      new("", {}).rule_from_ical(ical, content_line, preserve)
    end

    def initialize(ical_string, options = {})
      @ical_string = ical_string.to_s
      @preserve = options[:preserve] == true || options[:preserve_ical] == true
    end

    def to_schedule
      data = {}
      layout = []
      stack = []
      seen_singletons = []
      saw_vevent = false

      each_content_line do |line|
        name = line.name.upcase

        case name
        when "BEGIN"
          component_name = line.value.upcase
          if component_name == "VEVENT"
            raise parse_error("Invalid iCalendar structure: multiple VEVENT components", line) if saw_vevent
            saw_vevent = true
          end
          stack.push([component_name, line])
          layout << line if preserve?
          next
        when "END"
          component, _opening_line = stack.pop
          if component.nil? || component != line.value.upcase
            raise parse_error("Invalid iCalendar structure: END:#{line.value} without matching BEGIN", line)
          end
          layout << line if preserve?
          next
        end

        model_scope = stack.empty? || stack.last.first == "VEVENT"
        recognized = %w[DTSTART DTEND RDATE EXDATE RRULE EXRULE DURATION].include?(name)
        next if !model_scope && (!preserve? || recognized)

        case name
        when "DTSTART", "DTEND"
          if preserve? && seen_singletons.include?(name)
            raise parse_error("Invalid iCalendar structure: duplicate #{name}", line)
          end
          seen_singletons << name
          key = name == "DTSTART" ? :start_time : :end_time
          data[key] = TimeUtil.deserialize_time(line.value)
          layout << [name.downcase.to_sym, line]
        when "RDATE", "EXDATE"
          times = split_values(line).map { |value| TimeUtil.deserialize_time(value) }
          key = name == "RDATE" ? :rtimes : :extimes
          data[key] ||= []
          data[key].concat(times)
          layout << [name.downcase.to_sym, line, times]
        when "RRULE", "EXRULE"
          rule = rule_from_ical(line.value, line, preserve?)
          key = name == "RRULE" ? :rrules : :exrules
          data[key] ||= []
          data[key] << rule
          layout << [name.downcase.to_sym, line, rule]
        else
          layout << line if preserve?
        end
      end

      if stack.any?
        component, opening_line = stack.last
        raise parse_error("Invalid iCalendar structure: unclosed #{component}", opening_line)
      end

      schedule = Schedule.from_hash(data)
      if preserve?
        schedule.ical_preserve = true
        schedule.ical_layout = layout
      end
      schedule
    end

    def rule_from_ical(ical, content_line = nil, preserve = false)
      raise ArgumentError, "empty ical rule" if ical.nil?

      validations = {}
      params = {validations: validations, interval: 1}
      extension_components = []
      component_offset = 0

      ical.split(";").each do |component|
        raw_name, value = split_component(component, content_line, component_offset)
        name = raw_name.upcase
        value = value.strip

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
          parse_byday(value, validations)
        when "BYMONTHDAY"
          validations[:day_of_month] = value.split(",").map(&:to_i)
        when "BYMONTH"
          validations[:month_of_year] = value.split(",").map(&:to_i)
        when "BYYEARDAY"
          validations[:day_of_year] = value.split(",").map(&:to_i)
        when "BYSETPOS"
          validations[:by_set_pos] = value.split(",").map(&:to_i)
        else
          if preserve && name.start_with?("X-")
            extension_components << IcalContentLine::Component.new(name: raw_name, value: value)
          else
            validations[raw_name] = nil
          end
        end
        component_offset += component.bytesize + 1
      end

      rule = begin
        Rule.from_hash(params)
      rescue ArgumentError => error
        raise(error) unless content_line
        raise parse_error(error.message, content_line)
      end

      rule.ical_params.concat(unmanaged_params(content_line)) if content_line && preserve
      rule.ical_components.concat(extension_components)
      rule
    end

    private

    def preserve?
      @preserve
    end

    def parse_error(message, line, offset = 0)
      ParseError.new(
        message,
        line.line_number,
        line.column + offset,
        line.byte_offset + offset
      )
    end

    def parse_byday(value, validations)
      dows = {}
      days = []
      value.split(",").each do |expr|
        stripped = expr.strip
        day = TimeUtil.ical_day_to_symbol(stripped[-2..])
        if stripped.length > 2
          occurrence = stripped[0...-2].to_i
          if dows[day].nil?
            dows[day] = [occurrence]
          else
            dows[day].push(occurrence)
          end
          days.delete(TimeUtil.sym_to_wday(day))
        elsif dows[day].nil?
          days.push(TimeUtil.sym_to_wday(day))
        end
      end
      validations[:day_of_week] = dows unless dows.empty?
      validations[:day] = days unless days.empty?
    end

    def split_component(component, content_line, component_offset)
      equal_position = component.index("=")
      unless equal_position
        if content_line
          value_offset = content_line.name.bytesize + content_line.params.sum { |param| param.to_s.bytesize } + 1
          raise parse_error(
            "Invalid iCal rule component",
            content_line,
            value_offset + component_offset + component.bytesize
          )
        end
        raise ArgumentError, "Invalid iCal rule component"
      end
      [component[0...equal_position], component[(equal_position + 1)..]]
    end

    def unmanaged_params(line)
      line.params.reject { |param| param.name.upcase == "TZID" && %w[RDATE EXDATE DTSTART DTEND].include?(line.name.upcase) }
    end

    def split_values(line)
      values = []
      value = +""
      escaped = false

      line.value.each_char do |char|
        if escaped
          value << "\\" << char
          escaped = false
        elsif char == "\\"
          escaped = true
        elsif char == ","
          values << value
          value = +""
        else
          value << char
        end
      end

      raise parse_error("Invalid iCalendar value: trailing escape", line) if escaped
      values << value
    end

    def each_content_line
      each_logical_line do |logical_line|
        yield parse_content_line(logical_line)
      end
    end

    def each_logical_line
      scanner = StringScanner.new(@ical_string.dup.force_encoding("BINARY"))
      current = nil
      line_number = 0

      until scanner.eos?
        line_start = scanner.pos
        line_number += 1
        physical_line = scanner.scan(/[^\r\n]*/n)
        scanner.scan(/(?:\r\n|\r|\n)/n)

        if physical_line.start_with?(" ", "\t")
          unless current
            raise ParseError.new("Invalid iCalendar line continuation", line_number, 1, line_start)
          end
          continuation = physical_line.dup.sub(/\A[ \t]+/, "")
          current[:content] << continuation
        else
          yield parse_logical_line(current) if current
          current = {
            content: physical_line.dup,
            line_number: line_number,
            byte_offset: line_start
          }
        end
      end

      yield parse_logical_line(current) if current
    end

    def parse_logical_line(current)
      content = current[:content].force_encoding("UTF-8")
      unless content.valid_encoding?
        raise ParseError.new(
          "Invalid UTF-8 sequence",
          current[:line_number],
          1,
          current[:byte_offset]
        )
      end
      [content, current[:line_number], 1, current[:byte_offset]]
    end

    def parse_content_line(logical_line)
      content, line_number, column, byte_offset = logical_line
      scanner = StringScanner.new(content)
      name = scanner.scan(/[A-Za-z0-9][A-Za-z0-9.-]*/)
      unless name
        raise ParseError.new("Invalid iCalendar content line", line_number, column, byte_offset)
      end

      params = []
      while scanner.scan(/;/)
        param_name = scanner.scan(/[A-Za-z0-9][A-Za-z0-9.-]*/)
        unless param_name && scanner.scan(/=/)
          raise ParseError.new(
            "Invalid iCalendar parameter",
            line_number,
            column + scanner.pos,
            byte_offset + scanner.pos
          )
        end
        params << parse_parameter_value(scanner, param_name, line_number, column, byte_offset)
      end

      unless scanner.scan(/:/)
        raise ParseError.new(
          "Invalid iCalendar content line: missing ':'",
          line_number,
          column + scanner.pos,
          byte_offset + scanner.pos
        )
      end

      IcalContentLine.new(
        name: name,
        params: params,
        value: scanner.rest,
        line_number: line_number,
        column: column,
        byte_offset: byte_offset
      )
    end

    def parse_parameter_value(scanner, name, line_number, column, byte_offset)
      value_start = scanner.pos
      if scanner.scan(/"/)
        value = +""
        raw_value = +""
        until scanner.eos?
          char = scanner.getch
          if char == '"'
            return IcalContentLine::Parameter.new(
              name: name,
              value: value,
              quoted: true,
              raw_value: raw_value
            )
          elsif char == "\\"
            escaped = scanner.getch
            unless escaped
              raise ParseError.new("Invalid iCalendar parameter: trailing escape", line_number, column + scanner.pos, byte_offset + scanner.pos)
            end
            raw_value << char << escaped
            value << char << escaped
          else
            raw_value << char
            value << char
          end
        end
        raise ParseError.new("Invalid iCalendar parameter: unterminated quoted value", line_number, column, byte_offset)
      end

      value = scanner.scan(/[^;:"]*/)
      if value.empty?
        raise ParseError.new(
          "Invalid iCalendar parameter: empty value",
          line_number,
          column + value_start - 1,
          byte_offset + value_start - 1
        )
      end
      if scanner.peek(1) == '"' || value.include?("\\")
        raise ParseError.new("Invalid iCalendar parameter", line_number, column + scanner.pos, byte_offset + scanner.pos)
      end
      IcalContentLine::Parameter.new(name: name, value: value, quoted: false)
    end
  end
end
