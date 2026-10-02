# frozen_string_literal: true

module Rack
  class Cors
    # Validates and normalizes serialized Origin header values as defined by
    # RFC 6454 / the WHATWG URL "origin" concept:
    #
    #   scheme "://" host [ ":" port ]
    #
    # Anything else (comma-joined lists, userinfo, path/query/fragment
    # segments, control characters, ...) is rejected so that abnormal input
    # never reaches rule matching, response headers or log files.
    module Origin
      NULL_ORIGIN = 'null'

      DEFAULT_PORTS = {
        'http' => 80,
        'https' => 443,
        'ws' => 80,
        'wss' => 443
      }.freeze

      SCHEME_PATTERN = /[a-zA-Z][a-zA-Z0-9+.-]*/.freeze
      HOST_PATTERN = /(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)/.freeze
      PORT_PATTERN = /\d{1,5}/.freeze
      SERIALIZED_ORIGIN_PATTERN = /\A(#{SCHEME_PATTERN}):\/\/(#{HOST_PATTERN})(?::(#{PORT_PATTERN}))?\z/.freeze

      CONTROL_CHARS = /[\x00-\x1f\x7f]/.freeze

      # Maximum length of a sanitized origin value written to logs.
      LOG_MAX_LENGTH = 200

      class << self
        def null?(value)
          value == NULL_ORIGIN
        end

        # Returns nil when +value+ is a well-formed serialized origin,
        # otherwise a Symbol describing why it was rejected.
        def invalid_reason(value)
          return :empty if value.nil? || value.empty?
          return :control_characters if value.match?(CONTROL_CHARS)
          return :multiple_origins if value.include?(',')

          match = SERIALIZED_ORIGIN_PATTERN.match(value)
          return :malformed unless match
          return :port_out_of_range if match[3] && match[3].to_i > 65_535

          nil
        end

        def valid?(value)
          invalid_reason(value).nil?
        end

        # Canonicalizes a valid serialized origin: lowercases the scheme and
        # host (IPv6 literals keep their brackets) and drops the port when it
        # is the scheme's default. The result is the only value that should
        # be matched against rules or echoed back in response headers.
        def normalize(value)
          match = SERIALIZED_ORIGIN_PATTERN.match(value)
          return nil unless match

          scheme = match[1].downcase
          host = match[2].downcase
          port = match[3]&.to_i

          normalized = +"#{scheme}://#{host}"
          normalized << ":#{port}" if port && port != DEFAULT_PORTS[scheme]
          normalized
        end

        # Escapes control characters and truncates the value so that abnormal
        # input can be logged without log-injection or unbounded output.
        def sanitize_for_log(value)
          sanitized = value.to_s.gsub(CONTROL_CHARS) { |char| format('\\x%02X', char.ord) }
          sanitized = "#{sanitized[0, LOG_MAX_LENGTH]}..." if sanitized.length > LOG_MAX_LENGTH
          sanitized
        end
      end
    end
  end
end
