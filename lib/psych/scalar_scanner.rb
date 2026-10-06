# frozen_string_literal: true
require_relative 'exception'

module Psych
  ###
  # Scan scalars for built in types
  class ScalarScanner
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

    # YAML 1.2 core schema resolution regexes.
    # See https://yaml.org/spec/1.2.2/#103-core-schema
    CORE_NULL   = /^(?:~|null|Null|NULL)$/
    CORE_TRUE   = /^(?:true|True|TRUE)$/
    CORE_FALSE  = /^(?:false|False|FALSE)$/
    CORE_INT    = /^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$/
    CORE_FLOAT  = /^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/

    # YAML 1.2 JSON schema resolution regexes.
    # See https://yaml.org/spec/1.2.2/#102-json-schema
    JSON_NULL   = /^null$/
    JSON_TRUE   = /^true$/
    JSON_FALSE  = /^false$/
    JSON_INT    = /^-?(?:0|[1-9][0-9]*)$/
    JSON_FLOAT  = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*)?(?:[eE][-+]?[0-9]+)?$/

    # Schemas that can be selected with the +schema+ keyword argument:
    #
    # [+:compat+] YAML 1.1 style resolution, preserving Psych's historical
    #             behavior (yes/no/on/off booleans, legacy octals,
    #             sexagesimal integers, timestamps, symbols).  This is the
    #             default.
    # [+:core+]   YAML 1.2 core schema.
    # [+:json+]   YAML 1.2 JSON schema.
    SCHEMAS = %i[compat core json].freeze

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

    # Create a new scanner
    def initialize class_loader, strict_integer: false, parse_symbols: true, schema: :compat
      unless SCHEMAS.include?(schema)
        raise ArgumentError, "unknown scalar schema: #{schema.inspect} (expected one of #{SCHEMAS.map(&:inspect).join(', ')})"
      end

      @symbol_cache = {}
      @class_loader = class_loader
      @strict_integer = strict_integer
      @parse_symbols = parse_symbols
      @schema = schema
    end

    # Tokenize +string+ returning the Ruby object
    def tokenize string
      case @schema
      when :core
        tokenize_core string
      when :json
        tokenize_json string
      else
        tokenize_compat string
      end
    end

    # Tokenize +string+ that carries an explicit !!int tag
    def tokenize_int string
      case @schema
      when :core
        raise ScalarSchemaError.new('tag:yaml.org,2002:int', string, @schema) unless string.match?(CORE_INT)
        tokenize_core string
      when :json
        raise ScalarSchemaError.new('tag:yaml.org,2002:int', string, @schema) unless string.match?(JSON_INT)
        tokenize_json string
      else
        tokenize_compat string
      end
    end

    # Tokenize +string+ that carries an explicit !!float tag
    def tokenize_float string
      case @schema
      when :core
        raise ScalarSchemaError.new('tag:yaml.org,2002:float', string, @schema) unless string.match?(CORE_FLOAT)
        tokenize_core string
      when :json
        raise ScalarSchemaError.new('tag:yaml.org,2002:float', string, @schema) unless string.match?(JSON_FLOAT)
        tokenize_json string
      else
        Float(tokenize_compat(string))
      end
    end

    # Tokenize +string+ that carries an explicit !!bool tag
    def tokenize_bool string
      case @schema
      when :core
        unless string.match?(CORE_TRUE) || string.match?(CORE_FALSE)
          raise ScalarSchemaError.new('tag:yaml.org,2002:bool', string, @schema)
        end
        tokenize_core string
      when :json
        unless string.match?(JSON_TRUE) || string.match?(JSON_FALSE)
          raise ScalarSchemaError.new('tag:yaml.org,2002:bool', string, @schema)
        end
        tokenize_json string
      else
        tokenize_compat string
      end
    end

    # Tokenize +string+ that carries an explicit !!null tag
    def tokenize_null string
      case @schema
      when :core
        unless string.empty? || string.match?(CORE_NULL)
          raise ScalarSchemaError.new('tag:yaml.org,2002:null', string, @schema)
        end
        tokenize_core string
      when :json
        unless string.empty? || string.match?(JSON_NULL)
          raise ScalarSchemaError.new('tag:yaml.org,2002:null', string, @schema)
        end
        tokenize_json string
      else
        tokenize_compat string
      end
    end

    # Tokenize +string+ that carries an explicit !!timestamp tag
    def tokenize_timestamp string
      value = scan_timestamp string
      return value unless value.nil?

      if @schema == :compat
        tokenize_compat string
      else
        raise ScalarSchemaError.new('tag:yaml.org,2002:timestamp', string, @schema)
      end
    end

    # Tokenize +string+ using Psych's historical YAML 1.1 style resolution
    def tokenize_compat string
      return nil if string.empty?
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

    # Tokenize +string+ using the YAML 1.2 core schema
    def tokenize_core string
      case string
      when '', '~', CORE_NULL
        nil
      when CORE_TRUE
        true
      when CORE_FALSE
        false
      when /^0o[0-7]+$/
        Integer(string[2..-1], 8)
      when /^0x[0-9a-fA-F]+$/
        Integer(string[2..-1], 16)
      when CORE_INT
        Integer(string, 10)
      when /^[-+]?\.(?:inf|Inf|INF)$/
        string.start_with?('-') ? -Float::INFINITY : Float::INFINITY
      when /^\.(?:nan|NaN|NAN)$/
        Float::NAN
      when CORE_FLOAT
        Float(string)
      else
        string
      end
    end

    # Tokenize +string+ using the YAML 1.2 JSON schema
    def tokenize_json string
      case string
      when '', JSON_NULL
        nil
      when JSON_TRUE
        true
      when JSON_FALSE
        false
      when JSON_INT
        Integer(string, 10)
      when JSON_FLOAT
        Float(string)
      else
        string
      end
    end

    ###
    # Parse and return an int from +string+
    def parse_int string
      Integer(string.delete(',_'))
    end

    ###
    # Scan +string+ as a timestamp, returning a Time or Date, or nil when
    # +string+ is not a valid timestamp
    def scan_timestamp string
      if string.match?(TIME)
        begin
          parse_time string
        rescue ArgumentError
          nil
        end
      elsif string.match?(/^\d{4}-(?:1[012]|0\d|\d)-(?:[12]\d|3[01]|0\d|\d)$/)
        begin
          class_loader.date.strptime(string, '%F', Date::GREGORIAN)
        rescue ArgumentError
          nil
        end
      end
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
  end
end
