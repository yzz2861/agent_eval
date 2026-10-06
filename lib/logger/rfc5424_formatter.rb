# frozen_string_literal: true

class Logger
  # Formatter for RFC 5424 syslog messages.
  #
  #   socket = TCPSocket.new("syslog.example.com", 514)
  #   formatter = Logger::RFC5424Formatter.new(
  #     app_name: "billing",
  #     procid: Process.pid.to_s,
  #     msgid: "order_created",
  #     structured_data: {"meta" => {"order_id" => "42"}}
  #   )
  #   logger = Logger.new(socket, formatter: formatter, framing: :octet_counting)
  class RFC5424Formatter < Formatter
    VERSION = "1"
    NILVALUE = "-"
    DEFAULT_FACILITY = 1
    BOM = "\uFEFF"

    SEVERITY = {
      DEBUG: 7,
      INFO: 6,
      WARN: 4,
      ERROR: 3,
      FATAL: 2,
      ANY: 0,
    }.freeze

    # Creates a formatter for RFC 5424 messages.
    #
    # +structured_data+ may be +nil+ for the NILVALUE, a Hash whose keys are
    # structured-data IDs, or an Array of [ID, params] pairs.
    def initialize(app_name:, procid:, msgid:, structured_data: nil,
                   hostname: nil, facility: DEFAULT_FACILITY)
      super()
      @facility = validate_facility(facility)
      @hostname = validate_header_value(hostname, :hostname, 255)
      @app_name = validate_header_value(app_name, :app_name, 48)
      @procid = validate_header_value(procid, :procid, 128)
      @msgid = validate_header_value(msgid, :msgid, 32)
      @structured_data = normalize_structured_data(structured_data)
    end

    def call(severity, time, _progname, msg)
      severity = logger_severity(severity)
      message = msg2str(msg).encode(Encoding::UTF_8)
      unless message.valid_encoding?
        raise ArgumentError, "invalid UTF-8 message"
      end

      sprintf(
        "<%d>%s %s %s %s %s %s %s %s",
        pri(severity),
        VERSION,
        format_datetime(time),
        @hostname,
        @app_name,
        @procid,
        @msgid,
        format_structured_data(@structured_data),
        BOM + message
      )
    end

    private

    def format_datetime(time)
      time.getutc.strftime("%Y-%m-%dT%H:%M:%S.%6NZ")
    end

    def logger_severity(severity)
      return severity if severity.is_a?(Integer) && severity >= 0 && severity <= 5
      return severity if severity.is_a?(Integer)

      value = {DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3, FATAL: 4, ANY: 5}[severity.to_s.to_sym]
      return value unless value.nil?

      raise ArgumentError, "invalid log severity: #{severity.inspect}"
    end

    def pri(severity)
      syslog_severity = SEVERITY.values[severity]
      if syslog_severity.nil?
        raise ArgumentError, "invalid log severity: #{severity.inspect}"
      end
      @facility * 8 + syslog_severity
    end

    def validate_facility(facility)
      facility = Integer(facility)
      unless facility >= 0 && facility <= 23
        raise ArgumentError, "invalid syslog facility: #{facility.inspect}"
      end
      facility
    rescue ArgumentError, TypeError
      raise ArgumentError, "invalid syslog facility: #{facility.inspect}"
    end

    def validate_header_value(value, name, max_bytesize)
      return NILVALUE if value.nil?

      value = value.to_s
      if value.bytesize < 1 || value.bytesize > max_bytesize ||
          !value.ascii_only? || value =~ /[\x00-\x20\x7f]/
        raise ArgumentError, "invalid RFC 5424 #{name}: #{value.inspect}"
      end
      value.dup.freeze
    end

    def normalize_structured_data(data)
      return nil if data.nil?

      elements =
        case data
        when Array
          if data.length == 2 && data.first.respond_to?(:to_s) &&
              !data.first.is_a?(Array) &&
              (data.last.is_a?(Hash) || data.last.nil?)
            [data]
          else
            data
          end
        when Hash
          data.map { |id, params| [id, params || {}] }
        else
          raise ArgumentError, "invalid RFC 5424 structured data: #{data.inspect}"
        end

      elements = elements.map do |element|
        unless element.is_a?(Array) && element.length == 2 &&
            (element.last.is_a?(Hash) || element.last.nil?)
          raise ArgumentError, "invalid RFC 5424 structured-data element: #{element.inspect}"
        end

        id = validate_sd_name(element.first, "structured-data ID")
        parameter_names = {}
        params = (element.last || {}).map do |name, value|
          parameter_name = validate_sd_name(name, "parameter name")
          if parameter_names.key?(parameter_name)
            raise ArgumentError, "duplicate RFC 5424 parameter name: #{parameter_name.inspect}"
          end
          parameter_names[parameter_name] = true
          [parameter_name, validate_param_value(value)]
        end
        [id, params || []]
      end
      if elements.empty?
        raise ArgumentError, "invalid RFC 5424 structured data: #{data.inspect}"
      end
      elements
    end

    def validate_sd_name(value, description)
      value = value.to_s
      unless value.bytesize >= 1 && value.bytesize <= 32 &&
          value.ascii_only? && value =~ /\A[\x21-\x7e]+\z/ &&
          value !~ /[="\]]/
        raise ArgumentError, "invalid RFC 5424 #{description}: #{value.inspect}"
      end
      value.dup.freeze
    end

    def validate_param_value(value)
      value = value.to_s.encode(Encoding::UTF_8).dup
      unless value.valid_encoding?
        raise ArgumentError, "invalid RFC 5424 parameter value: #{value.inspect}"
      end
      value.freeze
    end

    def format_structured_data(elements)
      return NILVALUE unless elements

      elements.map do |id, params|
        formatted_params = params.map do |name, value|
          " #{name}=\"#{escape_param_value(value)}\""
        end.join
        "[#{id}#{formatted_params}]"
      end.join
    end

    def escape_param_value(value)
      value.gsub(/[\\\]"]/) { |character| "\\#{character}" }
    end
  end
end
