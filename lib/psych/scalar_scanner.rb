# frozen_string_literal: true

module Psych
  ###
  # Scan scalars for built in types
  class ScalarScanner
    def self.validate_scalar_schema scalar_schema, strict_integer = false
      unless SCALAR_SCHEMAS.include?(scalar_schema)
        raise ArgumentError, "invalid scalar schema #{scalar_schema.inspect}; expected one of #{SCALAR_SCHEMAS.map(&:inspect).join(", ")}"
      end
      if strict_integer && scalar_schema != COMPAT_SCALAR_SCHEMA
        raise ArgumentError, "strict_integer can only be combined with scalar schema #{COMPAT_SCALAR_SCHEMA.inspect}"
      end
    end

    # Taken from http://yaml.org/type/timestamp.html
    TIME = /^-?\d{4}-\d{1,2}-\d{1,2}(?:[Tt]|\s+)\d{1,2}:\d\d:\d\d(?:\.\d*)?(?:\s*(?:Z|[-+]\d{1,2}:?(?:\d\d)?))?$/

    # Taken from http://yaml.org/type/float.html
    # Base 60, [-+]inf and NaN are handled separately
    FLOAT = /^(?:[-+]?([0-9][0-9_,]*)?\.[0-9]*([eE][-+][0-9]+)?(?# base 10))$/x

    # Taken from http://yaml.org/type/int.html and modified to ensure at least one numerical symbol exists
    INTEGER_STRICT = /^(?:[-+]?0b[_]*[0-1][0-1_]*             (?# base 2)
                         |[-+]?0[_]*[0-7][0-7_]*              (?# base 8)
                         |[-+]?(0|[1-9][0-9_]*)               (?# base 10)
                         |[-+]?0x[_]*[0-9a-fA-F][0-9a-fA-F_]* (?# base 16))$/x

    # Same as above, but allows commas.
    # Not to YML spec, but kept for backwards compatibility
    INTEGER_LEGACY = /^(?:[-+]?0b[_,]*[0-1][0-1_,]*                (?# base 2)
                         |[-+]?0[_,]*[0-7][0-7_,]*                 (?# base 8)
                         |[-+]?(?:0|[1-9](?:[0-9]|,[0-9]|_[0-9])*) (?# base 10)
                         |[-+]?0x[_,]*[0-9a-fA-F][0-9a-fA-F_,]*    (?# base 16))$/x

    # YAML 1.1 treats yes/no/on/off as booleans in addition to true/false,
    # while YAML 1.2's core schema only recognizes true/false.  The default
    # libyaml backend keeps the 1.1 set for backward compatibility; the
    # experimental libfyaml backend follows 1.2.
    if defined?(Psych::BACKEND) && Psych::BACKEND == 'libfyaml'
      BOOLEAN_TRUE  = /^true$/i
      BOOLEAN_FALSE = /^false$/i
    else
      BOOLEAN_TRUE  = /^(yes|true|on)$/i
      BOOLEAN_FALSE = /^(no|false|off)$/i
    end

    attr_reader :class_loader

    COMPAT_SCALAR_SCHEMA = :compat
    JSON_SCALAR_SCHEMA = :json
    CORE_SCALAR_SCHEMA = :core
    SCALAR_SCHEMAS = [
      COMPAT_SCALAR_SCHEMA,
      JSON_SCALAR_SCHEMA,
      CORE_SCALAR_SCHEMA,
    ].freeze

    YAML_12_NULL = /^(?:~|null|Null|NULL)$/
    YAML_12_BOOLEAN_TRUE = /^(?:true|True|TRUE)$/
    YAML_12_BOOLEAN_FALSE = /^(?:false|False|FALSE)$/
    YAML_12_JSON_INTEGER = /^[-+]?(?:0|[1-9][0-9]*)$/
    YAML_12_CORE_INTEGER = /^(?:[-+]?0o[0-7][0-7]*(?:_[0-7]+)*
                               |[-+]?0x[0-9a-fA-F][0-9a-fA-F]*(?:_[0-9a-fA-F]+)*
                               |[-+]?(?:0|[1-9][0-9]*(?:_[0-9]+)*))$/x
    YAML_12_JSON_FLOAT = /^[-+]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?$/
    YAML_12_CORE_FLOAT = /^(?:[-+]?(?:(?:0|[1-9][0-9]*(?:_[0-9]+)*)(?:\.(?:[0-9][0-9]*(?:_[0-9]+)*)?)?
                            |\.[0-9](?:_[0-9]+)*)(?:[eE][-+]?[0-9]+)?
                           |[-+]?\.(?:inf|Inf|INF)
                           |\.(?:nan|NaN|NAN))$/x

    # Create a new scanner
    def initialize class_loader, scalar_schema: COMPAT_SCALAR_SCHEMA, strict_integer: false, parse_symbols: true
      self.class.validate_scalar_schema scalar_schema, strict_integer

      @symbol_cache = {}
      @class_loader = class_loader
      @strict_integer = strict_integer
      @parse_symbols = parse_symbols
      @scalar_schema = scalar_schema
    end

    # Tokenize +string+ returning the Ruby object
    def tokenize string
      return nil if string.empty?
      if @scalar_schema == COMPAT_SCALAR_SCHEMA
        return tokenize_compat(string)
      else
        return tokenize_yaml12(string)
      end
    end

    def tokenize_compat string
      return @symbol_cache[string] if @symbol_cache.key?(string)
      integer_regex = @strict_integer ? INTEGER_STRICT : INTEGER_LEGACY
      # Check for a String type, being careful not to get caught by hash keys, hex values, and
      # special floats (e.g., -.inf).
      if string.match?(%r{^[^\d.:-]?[[:alpha:]_\s!@#$%\^&*(){}<>|/\\~;=]+}) || string.match?(/\n/)
        return string if string.length > 5

        if string.match?(/^[^ytonf~]/i)
          string
        elsif string == '~' || string.match?(/^null$/i)
          nil
        elsif string.match?(BOOLEAN_TRUE)
          true
        elsif string.match?(BOOLEAN_FALSE)
          false
        else
          string
        end
      elsif string.match?(TIME)
        begin
          parse_time string
        rescue ArgumentError
          string
        end
      elsif string.match?(/^\d{4}-(?:1[012]|0\d|\d)-(?:[12]\d|3[01]|0\d|\d)$/)
        begin
          class_loader.date.strptime(string, '%F', Date::GREGORIAN)
        rescue ArgumentError
          string
        end
      elsif string.match?(/^\+?\.inf$/i)
        Float::INFINITY
      elsif string.match?(/^-\.inf$/i)
        -Float::INFINITY
      elsif string.match?(/^\.nan$/i)
        Float::NAN
      elsif @parse_symbols && string.match?(/^:./)
        if string =~ /^:(["'])(.*)\1/
          @symbol_cache[string] = class_loader.symbolize($2.sub(/^:/, ''))
        else
          @symbol_cache[string] = class_loader.symbolize(string.sub(/^:/, ''))
        end
      elsif string.match?(/^[-+]?[0-9][0-9_]*(:[0-5]?[0-9]){1,2}$/)
        i = 0
        string.split(':').each_with_index do |n,e|
          i += (n.to_i * 60 ** (e - 2).abs)
        end
        i
      elsif string.match?(/^[-+]?[0-9][0-9_]*(:[0-5]?[0-9]){1,2}\.[0-9_]*$/)
        i = 0
        string.split(':').each_with_index do |n,e|
          i += (n.to_f * 60 ** (e - 2).abs)
        end
        i
      elsif string.match?(FLOAT)
        if string.match?(/\A[-+]?\.\Z/)
          string
        else
          Float(string.delete(',_').gsub(/\.([Ee]|$)/, '\1'))
        end
      elsif string.match?(integer_regex)
        parse_int string
      else
        string
      end
    end

    def tokenize_tagged string, tag
      type = standard_scalar_tag(tag)
      return tokenize(string) unless type

      case @scalar_schema
      when JSON_SCALAR_SCHEMA
        tokenize_json_tag(string, type)
      when CORE_SCALAR_SCHEMA
        tokenize_core_tag(string, type)
      else
        tokenize_compat_tag(string, type)
      end
    end

    def standard_scalar_tag? tag
      !standard_scalar_tag(tag).nil?
    end

    def yaml12_scalar_schema?
      @scalar_schema != COMPAT_SCALAR_SCHEMA
    end

    ###
    # Parse and return an int from +string+
    def parse_int string
      Integer(string.delete(',_'))
    end

    ###
    # Parse and return a Time from +string+
    def parse_time string
      klass = class_loader.load 'Time'

      date, time = *(string.split(/[Tt]|\s+/, 2))
      (yy, m, dd) = date.match(/^(-?\d{4})-(\d{1,2})-(\d{1,2})/).captures.map { |x| x.to_i }
      md = time.match(/(\d+:\d+:\d+)(?:\.(\d*))?\s*(Z|[-+]\d+(:\d\d)?)?/)

      (hh, mm, ss) = md[1].split(':').map { |x| x.to_i }
      us = (md[2] ? Rational("0.#{md[2]}") : 0) * 1000000

      time = klass.utc(yy, m, dd, hh, mm, ss, us)

      return time if 'Z' == md[3]
      return klass.at(time.to_i, us) unless md[3]

      tz = md[3].match(/^([+\-]?\d{1,2})\:?(\d{1,2})?$/)[1..-1].compact.map { |digit| Integer(digit, 10) }
      offset = tz.first * 3600

      if offset < 0
        offset -= ((tz[1] || 0) * 60)
      else
        offset += ((tz[1] || 0) * 60)
      end

      klass.new(yy, m, dd, hh, mm, ss+us/(1_000_000r), offset)
    end

    private

    def tokenize_yaml12 string
      case @scalar_schema
      when JSON_SCALAR_SCHEMA
        tokenize_json_scalar string
      when CORE_SCALAR_SCHEMA
        tokenize_core_scalar string
      end
    end

    def tokenize_json_scalar string
      return nil if string.match?(YAML_12_NULL)
      return true if string.match?(YAML_12_BOOLEAN_TRUE)
      return false if string.match?(YAML_12_BOOLEAN_FALSE)
      return parse_json_integer(string) if string.match?(YAML_12_JSON_INTEGER)
      return parse_json_float(string) if string.match?(YAML_12_JSON_FLOAT)
      string
    end

    def tokenize_core_scalar string
      return nil if string.match?(YAML_12_NULL)
      return true if string.match?(YAML_12_BOOLEAN_TRUE)
      return false if string.match?(YAML_12_BOOLEAN_FALSE)
      return parse_core_integer(string) if string.match?(YAML_12_CORE_INTEGER)
      return parse_core_float(string) if string.match?(YAML_12_CORE_FLOAT)
      string
    end

    def tokenize_json_tag string, type
      case type
      when 'str' then string
      when 'null'
        return nil if string.empty? || string.match?(YAML_12_NULL)
        invalid_tag!(string, type)
      when 'bool'
        return true if string.match?(YAML_12_BOOLEAN_TRUE)
        return false if string.match?(YAML_12_BOOLEAN_FALSE)
        invalid_tag!(string, type)
      when 'int'
        return parse_json_integer(string) if string.match?(YAML_12_JSON_INTEGER)
        invalid_tag!(string, type)
      when 'float'
        return parse_json_float(string) if string.match?(YAML_12_JSON_FLOAT)
        invalid_tag!(string, type)
      else
        unsupported_tag!(type)
      end
    end

    def tokenize_core_tag string, type
      case type
      when 'str' then string
      when 'null'
        return nil if string.empty? || string.match?(YAML_12_NULL)
        invalid_tag!(string, type)
      when 'bool'
        return true if string.match?(YAML_12_BOOLEAN_TRUE)
        return false if string.match?(YAML_12_BOOLEAN_FALSE)
        invalid_tag!(string, type)
      when 'int'
        return parse_core_integer(string) if string.match?(YAML_12_CORE_INTEGER)
        invalid_tag!(string, type)
      when 'float'
        return parse_core_float(string) if string.match?(YAML_12_CORE_FLOAT)
        invalid_tag!(string, type)
      else
        unsupported_tag!(type)
      end
    end

    def tokenize_compat_tag string, type
      case type
      when 'str' then string
      when 'null'
        return nil if string.empty? || tokenize_compat(string).nil?
        invalid_tag!(string, type)
      when 'bool'
        tokenized = tokenize_compat(string)
        tokenized.equal?(true) || tokenized.equal?(false) ? tokenized : invalid_tag!(string, type)
      when 'int'
        integer_regex = @strict_integer ? INTEGER_STRICT : INTEGER_LEGACY
        string.match?(integer_regex) ? parse_int(string) : invalid_tag!(string, type)
      when 'float'
        tokenized = tokenize_compat(string)
        tokenized.is_a?(Numeric) ? Float(tokenized) : invalid_tag!(string, type)
      when 'timestamp'
        tokenized = tokenize_compat(string)
        tokenized.is_a?(Date) || tokenized.is_a?(Time) ? tokenized : invalid_tag!(string, type)
      else
        tokenize_compat(string)
      end
    end

    def standard_scalar_tag tag
      case tag
      when 'tag:yaml.org,2002:str', '!str', '!!str' then 'str'
      when 'tag:yaml.org,2002:null', '!null', '!!null' then 'null'
      when 'tag:yaml.org,2002:bool', '!bool', '!!bool' then 'bool'
      when 'tag:yaml.org,2002:int', '!int', '!!int' then 'int'
      when 'tag:yaml.org,2002:float', '!float', '!!float' then 'float'
      when 'tag:yaml.org,2002:timestamp', '!timestamp', '!!timestamp' then 'timestamp'
      when 'tag:yaml.org,2002:binary', '!binary', '!!binary' then 'binary'
      end
    end

    def parse_json_integer string
      Integer(string)
    end

    def parse_core_integer string
      Integer(string.delete('_'))
    end

    def parse_json_float string
      Float(string)
    end

    def parse_core_float string
      normalized = string.delete('_')
      case normalized
      when /^\+?\.(?:inf|Inf|INF)$/ then Float::INFINITY
      when /^-\.(?:inf|Inf|INF)$/ then -Float::INFINITY
      when /^\.(?:nan|NaN|NAN)$/ then Float::NAN
      else
        Float(normalized)
      end
    end

    def invalid_tag! string, type
      raise ArgumentError, "invalid #{type} scalar: #{string.inspect}"
    end

    def unsupported_tag! type
      raise ArgumentError, "unsupported #{type} scalar in #{@scalar_schema.inspect} schema"
    end
  end
end
