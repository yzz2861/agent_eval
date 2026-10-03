module IceCube
  # A single iCalendar content line (RFC 5545 section 3.1), parsed into
  # its name, parameters and value so that properties IceCube does not
  # model directly (e.g. vendor X- properties) can be preserved across
  # a parse/serialize round trip.
  #
  # Parameter values are kept as their raw tokens (including any quoting
  # or backslash escapes) so that output is byte-for-byte faithful.
  class IcalProperty
    NAME_PATTERN = /\A[A-Za-z0-9-]+\z/

    attr_reader :name, :params, :value

    def initialize(name, params = {}, value = "")
      @name = name
      @params = params
      @value = value
    end

    def ==(other)
      other.is_a?(IcalProperty) &&
        name == other.name &&
        params == other.params &&
        value == other.value
    end

    # Parse one unfolded content line. Raises InvalidIcalError with the
    # offending line number and character position on malformed input.
    def self.parse(line, line_number: nil)
      unless line.valid_encoding?
        raise InvalidIcalError.new("invalid byte sequence in content line",
          line_number: line_number, position: 0)
      end

      colon = index_of_unquoted(line, ":")
      if colon.nil?
        split_unquoted(line, ";", line_number: line_number)
        raise InvalidIcalError.new("content line is missing a ':' separator",
          line_number: line_number, position: line.length)
      end

      head = line[0...colon]
      value = line[(colon + 1)..] || ""

      segments = split_unquoted(head, ";", line_number: line_number)
      name = segments.shift
      unless name && NAME_PATTERN.match?(name)
        raise InvalidIcalError.new("invalid property name #{name.inspect}",
          line_number: line_number, position: 0)
      end

      params = {}
      offset = name.length + 1
      segments.each do |segment|
        equals = index_of_unquoted(segment, "=")
        if equals.nil?
          raise InvalidIcalError.new("parameter is missing a '=' separator",
            line_number: line_number, position: offset)
        end
        param_name = segment[0...equals]
        unless NAME_PATTERN.match?(param_name)
          raise InvalidIcalError.new("invalid parameter name #{param_name.inspect}",
            line_number: line_number, position: offset)
        end
        raw_values = segment[(equals + 1)..] || ""
        params[param_name] = split_param_values(raw_values)
        offset += segment.length + 1
      end

      new(name, params, value)
    end

    # Rebuild the content line. The result is identical to the parsed
    # input for well-formed lines.
    def to_s
      line = +name.dup
      params.each do |param_name, values|
        line << ";" << param_name << "=" << values.join(",")
      end
      line << ":" << value
      line
    end

    # Index of the first occurrence of +char+ that is not inside a
    # double-quoted section, or nil. Backslash-escaped characters inside
    # quotes are skipped so an escaped quote does not toggle quoting.
    def self.index_of_unquoted(line, char)
      quoted = false
      index = 0
      while index < line.length
        current = line[index]
        if current == "\\" && quoted
          index += 2
          next
        elsif current == '"'
          quoted = !quoted
        elsif current == char && !quoted
          return index
        end
        index += 1
      end
      nil
    end

    # Split on +delimiter+ characters that are not inside double quotes.
    # An unterminated quote is reported with its position.
    def self.split_unquoted(line, delimiter, line_number: nil)
      segments = []
      start = 0
      quoted = false
      quote_index = nil
      index = 0
      while index < line.length
        current = line[index]
        if current == "\\" && quoted
          index += 2
          next
        elsif current == '"'
          quoted = !quoted
          quote_index = quoted ? index : nil
        elsif current == delimiter && !quoted
          segments << line[start...index]
          start = index + 1
        end
        index += 1
      end
      if quoted
        raise InvalidIcalError.new("unterminated quoted parameter value",
          line_number: line_number, position: quote_index)
      end
      segments << line[start..]
      segments
    end

    # Split a parameter value list on commas, honoring double-quoted
    # sections and backslash-escaped commas (used by some vendors).
    # Tokens are returned raw, preserving quotes and escapes.
    def self.split_param_values(raw)
      values = []
      start = 0
      quoted = false
      index = 0
      while index < raw.length
        current = raw[index]
        if current == "\\"
          index += 2
          next
        elsif current == '"'
          quoted = !quoted
        elsif current == "," && !quoted
          values << raw[start...index]
          start = index + 1
        end
        index += 1
      end
      values << raw[start..]
      values
    end
  end
end
