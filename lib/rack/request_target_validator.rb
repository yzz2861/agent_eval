# frozen_string_literal: true

require_relative 'constants'
require_relative 'utils'

module Rack
  # Rack::RequestTargetValidator inspects the *raw* request target of
  # incoming requests and rejects targets whose path is ambiguous when
  # interpreted by both a reverse proxy and the application behind it.
  #
  # When an application sits behind a reverse proxy, the proxy and the
  # application may disagree on how to decode the request path.  A proxy
  # that routes on the undecoded path can be tricked into forwarding a
  # request the application later decodes differently, smuggling paths
  # past proxy-level access rules.  This middleware lets the application
  # explicitly reject such ambiguous targets instead of silently
  # accepting whatever the proxy forwarded.
  #
  # Four independent rules are available, each configured separately so
  # they are never conflated by a single unconditional URL decode:
  #
  # [+encoded_slash+]
  #   Percent-encoded slashes in the path, e.g. <tt>/files/a%2Fb</tt>.
  #   A proxy may route this as one segment while the application sees
  #   two segments after decoding.
  # [+backslash+]
  #   Literal or percent-encoded backslashes in the path, e.g.
  #   <tt>/files\..\secret</tt> or <tt>/files%5Csecret</tt>.  Some
  #   servers treat <tt>\</tt> as a path separator, others do not.
  # [+dot_segments+]
  #   <tt>.</tt> and <tt>..</tt> path segments, including singly encoded
  #   forms such as <tt>%2e</tt>, <tt>%2e%2e</tt> or <tt>.%2e</tt>.
  #   Only exact dot segments match: <tt>/.well-known/</tt> and
  #   <tt>/foo..bar</tt> are not affected.  The segment is decoded one
  #   level solely for this comparison; the decoded value is never
  #   written back to the environment.
  # [+double_encoding+]
  #   Repeated percent-encoding, e.g. <tt>/files/%252Fetc</tt> (decodes
  #   to <tt>%2F</tt>) or <tt>/a/%25252e</tt>.  Any <tt>%25</tt> followed
  #   by two hex digits means one decode still leaves a percent-encoded
  #   sequence behind, so proxy and application may decode a different
  #   number of times.
  #
  # Each rule accepts <tt>:reject</tt> (the default) or <tt>:allow</tt>:
  #
  #   use Rack::RequestTargetValidator,
  #     encoded_slash: :reject,
  #     backslash: :reject,
  #     dot_segments: :reject,
  #     double_encoding: :allow
  #
  # The rules apply to the path portion of the request target only.
  # The query string is never inspected: <tt>/search?q=%2F%5C..%252F</tt>
  # passes all rules.
  #
  # The raw request target is read from the +REQUEST_URI+ or
  # +REQUEST_PATH+ environment keys (in that order), as provided by the
  # server, and stored back into <tt>env['rack.request_target']</tt> so
  # downstream applications can see exactly what was validated.  The
  # environment is otherwise passed through untouched: +PATH_INFO+,
  # +SCRIPT_NAME+ and +QUERY_STRING+ are never rewritten, so the router
  # receives the same path it would have received without this
  # middleware.
  #
  # If the server provides no raw request target, the validator cannot
  # inspect anything and applies the +fallback+ policy:
  # <tt>fallback: :allow</tt> (the default) passes the request through,
  # while <tt>fallback: :reject</tt> responds 400.  Choose
  # <tt>:reject</tt> when your proxy is expected to always forward the
  # raw target and its absence indicates misconfiguration.
  #
  # Both origin-form and absolute-form targets are understood, so a
  # proxy forwarding <tt>http://example.org/a/%2F/b?x=%2F</tt> has the
  # path checked while the authority and query string are ignored.
  # Asterisk-form (<tt>OPTIONS *</tt>) and authority-form (CONNECT)
  # targets carry no path and always pass.
  #
  # ==== Examples
  #
  # Percent-encoded UTF-8 is not ambiguous and passes:
  #
  #   /caf%C3%A9                  # allowed
  #   /%E6%97%A5%E6%9C%AC         # allowed
  #
  # Rejections identify the exact segment at fault.  With an application
  # mounted under a prefix (SCRIPT_NAME=/app), the raw target still
  # contains the prefix and the reported segment index refers to the
  # full raw path:
  #
  #   /app/../secret              # rejected: dot_segments, segment 1 ("..")
  #   /app/files/%252Fetc         # rejected: double_encoding, segment 2 ("%252Fetc")
  #   http://example.org/a/%2F/b  # rejected: encoded_slash, segment 1 ("%2F")
  #
  # On rejection the middleware responds 400 with a plain-text body
  # naming the rule, the offending segment and the full target, and
  # stores a Rack::RequestTargetValidator::Rejection in
  # <tt>env['rack.request_target_validator.rejection']</tt>.  Pass
  # +on_reject+ to customize the response or add logging:
  #
  #   use Rack::RequestTargetValidator, on_reject: ->(env, rejection) do
  #     env['rack.errors'].puts(rejection.message)
  #     [400, { 'content-type' => 'text/plain' }, ['bad request']]
  #   end
  class RequestTargetValidator
    # Environment key under which the raw request target is stored once
    # found, so downstream applications can inspect what was validated.
    REQUEST_TARGET = 'rack.request_target'

    # Environment key under which the Rejection describing a failed
    # validation is stored before the 400 response is generated.
    REJECTION = 'rack.request_target_validator.rejection'

    # Environment keys consulted for the raw request target, in order.
    TARGET_KEYS = ['REQUEST_URI', REQUEST_PATH].freeze

    # Valid actions for each rule and for the fallback policy.
    ACTIONS = [:allow, :reject].freeze

    # All supported rules, in the order they are checked.
    RULES = [:encoded_slash, :backslash, :dot_segments, :double_encoding].freeze

    ENCODED_SLASH = /%2f/i
    ENCODED_BACKSLASH = /%5c/i
    DOUBLE_ENCODING = /%25[0-9a-f]{2}/i
    ABSOLUTE_FORM = %r{\A[A-Za-z][A-Za-z0-9+.\-]*://[^/?]*}

    # Describes why a request target was rejected: the +rule+ that
    # matched, the offending path +segment+, its +segment_index+ in the
    # raw path, and the full raw +target+.  For a +missing_target+
    # rejection (no raw target available and <tt>fallback: :reject</tt>),
    # +segment+, +segment_index+ and +target+ are nil.
    Rejection = Struct.new(:rule, :segment, :segment_index, :target) do
      def message
        if rule == :missing_target
          "invalid request target: no raw request target available " +            "(#{TARGET_KEYS.join(' or ')} not set)"
        else
          "invalid request target: #{rule} rule matched segment " +            "#{segment_index} (#{segment.inspect}) in #{target.inspect}"
        end
      end
      alias to_s message
    end

    def initialize(app, encoded_slash: :reject, backslash: :reject,
                   dot_segments: :reject, double_encoding: :reject,
                   fallback: :allow, on_reject: nil)
      @app = app
      @rules = {
        encoded_slash: encoded_slash,
        backslash: backslash,
        dot_segments: dot_segments,
        double_encoding: double_encoding,
      }.freeze
      @rules.each do |rule, action|
        unless ACTIONS.include?(action)
          raise ArgumentError,
            "invalid action #{action.inspect} for #{rule}, " +            "expected one of #{ACTIONS.map(&:inspect).join(', ')}"
        end
      end
      unless ACTIONS.include?(fallback)
        raise ArgumentError,
          "invalid fallback #{fallback.inspect}, " +          "expected one of #{ACTIONS.map(&:inspect).join(', ')}"
      end
      @fallback = fallback
      @on_reject = on_reject
    end

    def call(env)
      target = raw_target(env)

      if target.nil?
        return reject(env, Rejection.new(:missing_target)) if @fallback == :reject
        return @app.call(env)
      end

      env[REQUEST_TARGET] = target

      if (rejection = validate(target))
        reject(env, rejection)
      else
        @app.call(env)
      end
    end

    private

    def raw_target(env)
      TARGET_KEYS.each do |key|
        value = env[key]
        return value if value.is_a?(String) && !value.empty?
      end
      nil
    end

    def validate(target)
      path = extract_path(target)
      return nil unless path

      segments = path.split('/', -1)
      # Drop the empty segment before the leading slash so that
      # segment indexes count real path segments: in "/a/b", "a" is
      # segment 0 and "b" is segment 1.
      segments.shift if segments.first == ''

      segments.each_with_index do |segment, index|
        RULES.each do |rule|
          next unless @rules[rule] == :reject
          if violated?(rule, segment)
            return Rejection.new(rule, segment, index, target)
          end
        end
      end
      nil
    end

    def violated?(rule, segment)
      case rule
      when :encoded_slash
        segment.match?(ENCODED_SLASH)
      when :backslash
        segment.include?('\\') || segment.match?(ENCODED_BACKSLASH)
      when :double_encoding
        segment.match?(DOUBLE_ENCODING)
      when :dot_segments
        # Decode one level, solely to compare against "." and "..".
        # The decoded value never leaves this check.
        decoded = Utils.unescape_path(segment)
        decoded == '.' || decoded == '..'
      end
    end

    # Returns the raw path portion of the request target, or nil when
    # the target carries no path (asterisk-form, authority-form, or an
    # absolute-form target with an empty path).
    def extract_path(target)
      path =
        if target.start_with?('/')
          target
        elsif (match = ABSOLUTE_FORM.match(target))
          match.post_match
        else
          return nil
        end
      path = path.split('?', 2).first.to_s
      path.empty? ? nil : path
    end

    def reject(env, rejection)
      env[REJECTION] = rejection
      return @on_reject.call(env, rejection) if @on_reject

      body = "#{rejection.message}\n".b
      [400, {
        'content-type' => 'text/plain',
        'content-length' => body.bytesize.to_s,
      }, [body]]
    end
  end
end
