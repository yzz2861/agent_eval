# frozen_string_literal: true

require 'uri'

require_relative 'bad_request'
require_relative 'constants'

module Rack
  # Validate and preserve an HTTP request target without decoding or
  # normalizing it. Path checks examine one percent-encoded triplet at a time,
  # and the query component is never checked with path-specific rules.
  #
  # == Basic usage
  #
  #   use Rack::RequestTarget,
  #     encoded_slash: :reject,
  #     backslash: :reject,
  #     dot_segments: :reject,
  #     double_percent_encoding: :reject
  #
  # Valid origin-form targets are stored in +rack.request_target+ unchanged.
  # +PATH_INFO+ and +QUERY_STRING+ are not rewritten.
  #
  # The four path ambiguity policies are independent and accept +:reject+ or
  # +:allow+: +encoded_slash+, +backslash+, +dot_segments+, and
  # +double_percent_encoding+. Malformed percent sequences and invalid UTF-8 in
  # a path segment are always rejected.
  #
  # == Examples
  #
  # Valid UTF-8 may be direct bytes or percent encoded:
  #   GET /caf%C3%A9      # accepted, PATH_INFO stays "/caf%C3%A9"
  #   GET /caf\u00e9       # accepted when the server uses ASCII-8BIT bytes
  #   GET /caf%E3        # rejected: Component path, invalid UTF-8
  #
  # Each policy reports the exact path segment instead of only returning 400:
  #   GET /users/a%2Fb
  #   # Reason: encoded slash is not allowed in a path segment
  #   # Component: path; Segment index: 1; Segment: "a%2Fb"
  #
  #   GET /files/%252E%252E%252Fetc
  #   # Reason: repeated percent encoding is not allowed
  #   # Component: path; Segment index: 1
  #
  # Layered encoding such as +%25%32%46+ is also detected. It decodes one
  # layer to +%2F+, without recursively decoding the request target.
  #
  # Path policies do not apply to the query component:
  #   GET /search?q=%2F..%5C%252F
  #   # accepted; the query remains q=%2F..%5C%252F
  #
  # For an application mounted at +/admin+, the mount prefix and remaining path
  # are checked separately:
  #   use Rack::RequestTarget, mount_prefix: "/admin"
  #
  #   GET /admin/users/a%2Fb
  #   # Component: path; Segment index: 1; Segment: "a%2Fb"
  #   GET /adminx/users
  #   # Component: mount-prefix; request target is outside the mount
  #
  # Absolute-form targets are rejected by default because reverse proxies
  # normally convert them to origin form:
  #   GET http://example.com/users/a%2Fb
  #   # Component: absolute-form; absolute-form request targets are not allowed
  # Set +absolute_form: :allow+ only when that form is intentional; the URI
  # path still receives the same path checks.
  #
  # == Missing request target
  #
  # Raw targets are read from +rack.request_target+, +REQUEST_URI+, or
  # +REQUEST_PATH+ (combined with +QUERY_STRING+ when needed). The default is
  # to reject a request with none of these keys. For explicit degradation,
  # configure +missing_request_target: :pass+; checks are skipped, a warning is
  # written to +rack.errors+, and +rack.request_target.source+ is set to
  # +missing+.
  class RequestTarget
    REQUEST_TARGET_KEYS = [RACK_REQUEST_TARGET, "REQUEST_URI", REQUEST_PATH].freeze

    ERROR_MESSAGES = {
      :absolute_form_not_allowed => "absolute-form request targets are not allowed",
      :backslash_not_allowed => "backslash is not allowed in a path segment",
      :dot_segment_not_allowed => "dot segments are not allowed in a path segment",
      :double_percent_encoding_not_allowed => "repeated percent encoding is not allowed",
      :encoded_slash_not_allowed => "encoded slash is not allowed in a path segment",
      :invalid_connect_request_target => "CONNECT request targets must be in authority form",
      :invalid_percent_sequence => "invalid percent-encoded sequence",
      :invalid_request_target_form => "request target must be origin form or an allowed absolute-form URI",
      :invalid_utf8 => "path segment is not valid UTF-8",
      :invalid_whitespace => "request target contains whitespace or a control character",
      :missing_absolute_path => "absolute-form request target does not include a path",
      :mount_prefix_mismatch => "request target does not start with the configured mount prefix",
      :options_request_target => "OPTIONS request targets must be origin form, absolute form, or '*'",
      :request_target_contains_fragment => "request target must not contain a fragment",
    }.freeze

    HEX_CHARACTERS = /\A[0-9A-Fa-f]{2}\z/
    ABSOLUTE_HTTP_TARGET = /\Ahttps?:\/\//i

    class InvalidRequestTarget < ArgumentError
      include Rack::BadRequest

      attr_reader :code, :component, :segment, :segment_index, :target

      def initialize(code, target:, component:, segment: nil, segment_index: nil)
        @code = code
        @component = component
        @segment = segment
        @segment_index = segment_index
        @target = target
        super(Rack::RequestTarget::ERROR_MESSAGES.fetch(code))
      end
    end

    class MissingRequestTarget < ArgumentError
      include Rack::BadRequest

      attr_reader :code

      def initialize
        @code = :missing_request_target
        super("request target is not available in the Rack environment")
      end
    end

    def self.check(target, request_method: GET, mount_prefix: nil, encoded_slash: :reject,
      backslash: :reject, dot_segments: :reject, double_percent_encoding: :reject,
      absolute_form: :reject)
      new(
        nil,
        encoded_slash: encoded_slash,
        backslash: backslash,
        dot_segments: dot_segments,
        double_percent_encoding: double_percent_encoding,
        absolute_form: absolute_form,
        mount_prefix: mount_prefix
      ).check_target(target.to_s, request_method)
    end

    def initialize(app, request_target_keys: REQUEST_TARGET_KEYS, missing_request_target: :reject,
      mount_prefix: nil, on_invalid: nil, encoded_slash: :reject, backslash: :reject,
      dot_segments: :reject, double_percent_encoding: :reject, absolute_form: :reject)
      @app = app
      @request_target_keys = request_target_keys
      @missing_request_target = policy(missing_request_target, [:reject, :pass], :missing_request_target)
      @mount_prefix = mount_prefix
      @on_invalid = on_invalid
      @encoded_slash = policy(encoded_slash, [:reject, :allow], :encoded_slash)
      @backslash = policy(backslash, [:reject, :allow], :backslash)
      @dot_segments = policy(dot_segments, [:reject, :allow], :dot_segments)
      @double_percent_encoding = policy(double_percent_encoding, [:reject, :allow], :double_percent_encoding)
      @absolute_form = policy(absolute_form, [:reject, :allow], :absolute_form)
    end

    def call(env)
      target, source = extract_target(env)

      if target.nil?
        if @missing_request_target == :reject
          return invalid_response(MissingRequestTarget.new)
        end

        env[RACK_REQUEST_TARGET_SOURCE] = "missing"
        env[RACK_ERRORS]&.puts("Rack::RequestTarget: request target is missing; request target checks were skipped")
        return @app.call(env)
      end

      check_target(target, env[REQUEST_METHOD], env)
      env[RACK_REQUEST_TARGET] = target
      env[RACK_REQUEST_TARGET_SOURCE] = source
      @app.call(env)
    rescue InvalidRequestTarget, MissingRequestTarget => error
      invalid_response(error)
    end

    def check_target(target, request_method = GET, env = nil)
      prefix = configured_mount_prefix(env)
      validate_characters(target)

      if target == "*"
        unless request_method == OPTIONS
          raise_invalid(:options_request_target, target, "request-target")
        end
      elsif target.start_with?("/")
        check_origin_target(target, prefix)
      elsif absolute_target?(target)
        check_absolute_target(target, request_method, prefix)
      elsif target.start_with?("http://", "https://", "HTTP://", "HTTPS://")
        raise_invalid(:invalid_request_target_form, target, "absolute-form")
      elsif request_method == CONNECT
        check_authority_target(target)
      else
        raise_invalid(:invalid_request_target_form, target, "request-target")
      end

      target
    end

    private

    def configured_mount_prefix(env)
      return nil if @mount_prefix.nil?
      return env[SCRIPT_NAME].to_s if @mount_prefix == true

      @mount_prefix
    end

    def extract_target(env)
      @request_target_keys.each do |key|
        value = env[key]
        next if value.nil? || value.empty?

        target = value.dup
        if key == REQUEST_PATH && !target.include?("?") && !env[QUERY_STRING].to_s.empty?
          target << "?" << env[QUERY_STRING]
          return target.freeze, "#{REQUEST_PATH}+#{QUERY_STRING}"
        end

        return target.freeze, key
      end

      nil
    end

    def validate_characters(target)
      target.each_byte do |byte|
        if byte <= 0x20 || byte == 0x7F
          raise_invalid(:invalid_whitespace, target, "request-target")
        end
      end
    end

    def check_origin_target(target, mount_prefix)
      question_index = target.index("?")
      path = question_index.nil? ? target : target.byteslice(0, question_index)
      fragment_index = target.index("#")

      if fragment_index
        raise_invalid(:request_target_contains_fragment, target, "fragment")
      end

      if mount_prefix && !mount_prefix.empty?
        unless mount_prefix.start_with?("/")
          raise ArgumentError, "mount_prefix must start with '/'"
        end

        check_path(mount_prefix, target, "mount-prefix")
        unless path == mount_prefix || path.start_with?(mount_prefix + "/")
          raise_invalid(:mount_prefix_mismatch, target, "mount-prefix")
        end

        application_path = path.byteslice(
          mount_prefix.bytesize + 1,
          path.bytesize - mount_prefix.bytesize - 1
        )
        check_path(application_path, target, "path") unless application_path.empty?
      else
        check_path(path, target, "path")
      end
    end

    def check_absolute_target(target, request_method, mount_prefix)
      if @absolute_form == :reject
        raise_invalid(:absolute_form_not_allowed, target, "absolute-form")
      end

      if request_method == OPTIONS || request_method == CONNECT
        raise_invalid(:invalid_request_target_form, target, "absolute-form")
      end

      begin
        uri = URI.parse(target)
        unless uri.is_a?(URI::HTTP) && uri.absolute?
          raise_invalid(:invalid_request_target_form, target, "absolute-form")
        end
      rescue URI::InvalidURIError
        raise_invalid(:invalid_request_target_form, target, "absolute-form")
      end
      if uri.fragment
        raise_invalid(:request_target_contains_fragment, target, "fragment")
      end
      if uri.path.nil? || uri.path.empty?
        raise_invalid(:missing_absolute_path, target, "path")
      end

      if mount_prefix && !mount_prefix.empty?
        unless uri.path == mount_prefix || uri.path.start_with?(mount_prefix + "/")
          raise_invalid(:mount_prefix_mismatch, target, "mount-prefix")
        end
      end

      check_path(uri.path, target, "path")
    end

    def check_authority_target(target)
      if target.include?("/") || target.include?("?") || target.include?("#")
        raise_invalid(:invalid_connect_request_target, target, "authority")
      end
    end

    def absolute_target?(target)
      return true if target.match?(ABSOLUTE_HTTP_TARGET)

      uri = URI.parse(target)
      uri.is_a?(URI::HTTP) && uri.absolute?
    rescue URI::InvalidURIError
      false
    end

    def check_path(path, target, component)
      path.split("/", -1).each_with_index do |segment, segment_index|
        decoded = String.new(encoding: Encoding::BINARY)
        position = 0

        while position < segment.bytesize
          byte = segment.getbyte(position)

          if byte == 0x25
            check_percent_sequence(segment, position, decoded, segment_index, target, component)
            position += 3
          else
            if byte == 0x5C && @backslash == :reject
              raise_invalid(:backslash_not_allowed, target, component, segment, segment_index)
            end

            decoded << byte
            position += 1
          end
        end

        if @double_percent_encoding == :reject && decoded.match?(/%[0-9A-Fa-f]{2}/)
          raise_invalid(:double_percent_encoding_not_allowed, target, component, segment, segment_index)
        end

        decoded.force_encoding(Encoding::UTF_8)
        unless decoded.valid_encoding?
          raise_invalid(:invalid_utf8, target, component, segment, segment_index)
        end
        if @dot_segments == :reject && (decoded == "." || decoded == "..")
          raise_invalid(:dot_segment_not_allowed, target, component, segment, segment_index)
        end
      end
    end

    def check_percent_sequence(segment, position, decoded, segment_index, target, component)
      encoded_byte = segment.byteslice(position + 1, 2)
      unless encoded_byte&.match?(HEX_CHARACTERS)
        raise_invalid(:invalid_percent_sequence, target, component, segment, segment_index)
      end

      value = encoded_byte.to_i(16)
      if value == 0x2F && @encoded_slash == :reject
        raise_invalid(:encoded_slash_not_allowed, target, component, segment, segment_index)
      end
      if value == 0x5C && @backslash == :reject
        raise_invalid(:backslash_not_allowed, target, component, segment, segment_index)
      end

      decoded << value
    end

    def raise_invalid(code, target, component, segment = nil, segment_index = nil)
      raise InvalidRequestTarget.new(
        code,
        target: target,
        component: component,
        segment: segment,
        segment_index: segment_index
      )
    end

    def invalid_response(error)
      return @on_invalid.call(error) if @on_invalid

      headers = {
        CONTENT_TYPE => "text/plain; charset=utf-8",
        "x-request-target-error" => error_code(error).to_s.tr("_", "-")
      }
      [400, headers, [error_body(error)]]
    end

    def error_code(error)
      error.respond_to?(:code) ? error.code : :missing_request_target
    end

    def error_body(error)
      lines = ["Bad Request", "Reason: #{error.message}"]

      if error.respond_to?(:component)
        lines << "Component: #{error.component}"
        lines << "Segment index: #{error.segment_index}" unless error.segment_index.nil?
        lines << "Segment: #{error.segment.b.dump}" unless error.segment.nil?
        lines << "Request target: #{error.target.b.dump}"
      end

      lines.join("\n") << "\n"
    end

    def policy(value, allowed_values, option_name)
      unless allowed_values.include?(value)
        raise ArgumentError, "#{option_name} must be one of #{allowed_values.join(', ')}"
      end

      value
    end
  end
end
