# frozen_string_literal: true

require_relative 'formatter'
require_relative 'severity'

class Logger
  # Formatter for RFC 5424 syslog messages.
  class RFC5424Formatter < Formatter
    VERSION = 1
    NIL_VALUE = '-'
    UTF8_BOM = "\uFEFF".b.freeze
    TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S.%6N%:z'

    SEVERITY_CODES = {
      Severity::DEBUG => 7,
      Severity::INFO => 6,
      Severity::WARN => 4,
      Severity::ERROR => 3,
      Severity::FATAL => 2,
      Severity::UNKNOWN => 1,
    }.freeze

    PRINTUSASCII = /\A[\x21-\x7E]+\z/.freeze
    SD_NAME_FORBIDDEN = /["=\]]/.freeze
    PARAM_VALUE = /[\\"\]]/.freeze

    # Per-message RFC 5424 message id and structured data.
    class Message
      attr_reader :message, :msgid, :structured_data

      def initialize(message, msgid: nil, structured_data: nil)
        @message = message
        @msgid = msgid
        @structured_data = structured_data
      end
    end

    def initialize(app_name:, procid: nil, msgid: nil, structured_data: nil,
                   hostname: nil, facility: 1)
      @hostname = nillable_field(:hostname, hostname, 255)
      @app_name = required_field(:app_name, app_name, 48)
      @procid = nillable_field(:procid, procid, 128)
      @msgid = nillable_field(:msgid, msgid, 32)
      @facility = validate_facility(facility)
      @structured_data = validate_structured_data(structured_data)
      super()
    end

    def call(severity, time, _progname, msg)
      entry = msg
      if msg.is_a?(Message)
        entry = msg.message
        msgid = nillable_field(:msgid, msg.msgid, 32)
        structured_data = validate_structured_data(msg.structured_data)
      else
        msgid = @msgid
        structured_data = @structured_data
      end

      priority = (@facility * 8) + severity_code(severity)
      timestamp = time.strftime(TIMESTAMP_FORMAT)
      message = format_message_body(entry)

      "<#{priority}>#{VERSION} #{timestamp} #{@hostname} #{@app_name} #{@procid} #{msgid} #{structured_data}#{message}".b
    end

    private

    def severity_code(severity)
      code = if severity.is_a?(Integer)
        SEVERITY_CODES[severity]
      else
        SEVERITY_CODES[Severity.coerce(severity)]
      end
      code or raise ArgumentError, "invalid syslog severity: #{severity.inspect}"
    end

    def validate_facility(facility)
      unless facility.is_a?(Integer) && facility.between?(0, 23)
        raise ArgumentError, "syslog facility must be an integer between 0 and 23: #{facility.inspect}"
      end
      facility
    end

    def required_field(name, value, max_length)
      field = nillable_field(name, value, max_length)
      if field == NIL_VALUE
        raise ArgumentError, "#{name} is required"
      end
      field
    end

    def nillable_field(name, value, max_length)
      return NIL_VALUE.b if value.nil?

      field = protocol_string(name, value)
      unless field.ascii_only? && field.match?(PRINTUSASCII) && field.bytesize <= max_length
        raise ArgumentError, "invalid RFC 5424 #{name}: #{value.inspect}"
      end
      field.dup.freeze
    end

    def validate_structured_data(structured_data)
      return NIL_VALUE.b if structured_data.nil?

      elements = case structured_data
      when Hash
        structured_data.map { |id, params| [id, params] }
      when Array
        structured_data
      else
        raise ArgumentError, "invalid RFC 5424 structured data: #{structured_data.inspect}"
      end
      return NIL_VALUE.b if elements.empty?

      elements.map do |element|
        format_structured_element(element)
      end.join
    end

    def format_structured_element(element)
      unless element.is_a?(Array) && element.length == 2
        raise ArgumentError, "invalid RFC 5424 structured data element: #{element.inspect}"
      end

      id, params = element
      id_value = structured_name(:structured_data_id, id)
      formatted_params = format_structured_params(params)
      "[#{id_value}#{formatted_params}]".b
    end

    def structured_name(name, value)
      if value.nil?
        raise ArgumentError, "invalid RFC 5424 #{name}: nil"
      end
      field = protocol_string(name, value)
      unless field.ascii_only? && field.match?(PRINTUSASCII) &&
             field.bytesize <= 32 && !field.match?(SD_NAME_FORBIDDEN)
        raise ArgumentError, "invalid RFC 5424 #{name}: #{value.inspect}"
      end
      field.dup.freeze
    end

    def protocol_string(name, value)
      unless value.respond_to?(:to_str) || value.respond_to?(:to_s)
        raise ArgumentError, "invalid RFC 5424 #{name}: #{value.inspect}"
      end
      field = value.to_s
      unless field.is_a?(String)
        raise ArgumentError, "invalid RFC 5424 #{name}: #{value.inspect}"
      end
      field
    rescue NoMethodError
      raise ArgumentError, "invalid RFC 5424 #{name}: #{value.inspect}"
    end

    def format_structured_params(params)
      return +'' if params.nil?
      unless params.is_a?(Hash)
        raise ArgumentError, "RFC 5424 structured data parameters must be a Hash: #{params.inspect}"
      end

      params.map do |name, value|
        name_text = structured_name(:structured_data_param_name, name)
        " #{name_text}=\"#{escape_param_value(value)}\""
      end.join
    end

    def escape_param_value(value)
      text = value.to_s
      encoded = text.encode(Encoding::UTF_8)
      encoded.gsub(PARAM_VALUE) do |character|
        "\\#{character}"
      end.b
    rescue EncodingError
      raise ArgumentError, "invalid RFC 5424 structured data parameter value: #{value.inspect}"
    end

    def format_message_body(message)
      text = msg2str(message)
      return +'' if text.empty?

      encoded = if text.encoding.equal?(Encoding::UTF_8) && text.valid_encoding?
        text
      elsif text.ascii_only?
        text.dup.force_encoding(Encoding::UTF_8)
      else
        begin
          text.encode(Encoding::UTF_8)
        rescue Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError
          return text.b
        end
      end
      "#{UTF8_BOM}#{encoded.b}"
    end
  end
end
