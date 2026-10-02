# frozen_string_literal: true

module Rack
  class Cors
    class Resource
      # All CORS routes need to accept CORS simple headers at all times
      # {https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers}
      CORS_SIMPLE_HEADERS = %w[accept accept-language content-language content-type].freeze

      # Response headers that must never be exposed to the client, even
      # when an expose pattern or wildcard would match them.
      SENSITIVE_EXPOSE_HEADERS = %w[set-cookie www-authenticate proxy-authenticate].freeze

      attr_accessor :path, :methods, :headers, :expose, :max_age, :credentials, :pattern, :if_proc, :vary_headers

      def initialize(public_resource, path, opts = {})
        raise CorsMisconfigurationError if public_resource && opts[:credentials] == true

        self.path         = path
        self.credentials  = public_resource ? false : (opts[:credentials] == true)
        self.max_age      = opts[:max_age] || 7200
        self.pattern      = compile(path)
        self.if_proc      = opts[:if]
        self.vary_headers = opts[:vary] && [opts[:vary]].flatten
        @public_resource  = public_resource

        self.headers = case opts[:headers]
                       when :any then :any
                       when nil then nil
                       else
                         [opts[:headers]].flatten.collect(&:downcase)
                       end

        self.methods = case opts[:methods]
                       when :any then %i[get head post put patch delete options]
                       else
                         ensure_enum(opts[:methods]) || [:get]
                       end.map(&:to_s)

        self.expose = opts[:expose] ? [opts[:expose]].flatten : nil
      end

      def matches_path?(path)
        pattern =~ path
      end

      def match?(path, env)
        matches_path?(path) && (if_proc.nil? || if_proc.call(env))
      end

      def process_preflight(env, result)
        headers = {}

        request_method = env[Rack::Cors::HTTP_ACCESS_CONTROL_REQUEST_METHOD]
        result.miss(Result::MISS_NO_METHOD) && (return headers) if request_method.nil?
        result.miss(Result::MISS_DENY_METHOD) && (return headers) unless methods.include?(request_method.downcase)

        request_headers = env[Rack::Cors::HTTP_ACCESS_CONTROL_REQUEST_HEADERS]
        result.miss(Result::MISS_DENY_HEADER) && (return headers) if request_headers && !allow_headers?(request_headers)

        result.hit = true
        headers.merge(to_preflight_headers(env))
      end

      def to_headers(env)
        h = {
          'access-control-allow-origin' => origin_for_response_header(env[Rack::Cors::HTTP_ORIGIN]),
          'access-control-allow-methods' => methods.collect { |m| m.to_s.upcase }.join(', '),
          'access-control-expose-headers' => static_expose_headers.join(', '),
          'access-control-max-age' => max_age.to_s
        }
        h['access-control-allow-credentials'] = 'true' if credentials
        header_proc.call(h)
      end

      # Statically configured expose header names. Patterns and the
      # wildcard are resolved against the actual response instead, and
      # sensitive headers are always excluded.
      def static_expose_headers
        return [] if expose.nil?

        expose.reject { |entry| entry.is_a?(Regexp) || entry.to_s == '*' }
              .map(&:to_s)
              .reject { |name| sensitive_expose_header?(name) }
      end

      def expose_patterns
        return [] if expose.nil?

        expose.select { |entry| entry.is_a?(Regexp) }
      end

      def expose_wildcard?
        !expose.nil? && expose.any? { |entry| entry.to_s == '*' }
      end

      # True when the expose configuration can only be resolved by
      # inspecting the headers of the actual response.
      def dynamic_expose?
        expose_patterns.any? || expose_wildcard?
      end

      # Returns a new headers hash in which Access-Control-Expose-Headers
      # has been merged with the response headers matching the configured
      # expose patterns and/or wildcard. The given hash is never mutated
      # (it may be frozen).
      #
      # Merge rules:
      # - names already present (set by the app, or from the static
      #   configuration) are kept first, in their original order;
      # - statically configured names come next;
      # - pattern matches are appended in response header order;
      # - a wildcard expands to the concrete response header names when
      #   credentials are enabled (a literal wildcard is invalid there),
      #   and is emitted as a single wildcard otherwise;
      # - sensitive headers are never added;
      # - header names are compared case-insensitively and appear once.
      def apply_dynamic_expose(headers)
        return headers unless dynamic_expose?

        expose_keys = headers.keys.select do |key|
          key.to_s.casecmp('access-control-expose-headers').zero?
        end

        names = []
        add_name = lambda do |name|
          name = name.to_s.strip
          next if name.empty?
          next if names.any? { |existing| existing.casecmp(name).zero? }

          names << name
        end

        expose_keys.each do |key|
          headers[key].to_s.split(',').each { |name| add_name.call(name) }
        end
        static_expose_headers.each { |name| add_name.call(name) }

        response_names = headers.keys.map(&:to_s).reject do |name|
          name.casecmp('access-control-expose-headers').zero? ||
            sensitive_expose_header?(name)
        end

        expose_patterns.each do |pattern|
          response_names.each do |name|
            add_name.call(name) if pattern.match?(name) || pattern.match?(name.downcase)
          end
        end

        if expose_wildcard?
          if credentials
            response_names.each do |name|
              add_name.call(name) unless name.downcase.start_with?('access-control-')
            end
          else
            add_name.call('*')
          end
        end

        merged = headers.dup
        expose_keys.each { |key| merged.delete(key) }
        merged['access-control-expose-headers'] = names.join(', ')
        merged
      end

      protected

      def sensitive_expose_header?(name)
        SENSITIVE_EXPOSE_HEADERS.include?(name.to_s.downcase)
      end

      def public_resource?
        @public_resource
      end

      def origin_for_response_header(origin)
        return '*' if public_resource?

        origin
      end

      def to_preflight_headers(env)
        h = to_headers(env)
        h.merge!('access-control-allow-headers' => env[Rack::Cors::HTTP_ACCESS_CONTROL_REQUEST_HEADERS]) if env[Rack::Cors::HTTP_ACCESS_CONTROL_REQUEST_HEADERS]
        h
      end

      def allow_headers?(request_headers)
        headers = self.headers || []
        return true if headers == :any

        request_headers = request_headers.split(/,\s*/) if request_headers.is_a?(String)
        request_headers.all? do |header|
          header = header.downcase
          CORS_SIMPLE_HEADERS.include?(header) || headers.include?(header)
        end
      end

      def ensure_enum(var)
        return nil if var.nil?

        [var].flatten
      end

      def compile(path)
        if path.respond_to? :to_str
          special_chars = %w[. + ( ) $]
          pattern =
            path.to_str.gsub(%r{((:\w+)|/\*|[\*#{special_chars.join}])}) do |match|
              case match
              when '/*'
                '\\/?(.*?)'
              when '*'
                '(.*?)'
              when *special_chars
                Regexp.escape(match)
              else
                '([^/?&#]+)'
              end
            end
          /^#{pattern}$/
        elsif path.respond_to? :match
          path
        else
          raise TypeError, path
        end
      end

      def header_proc
        @header_proc ||= begin
          if defined?(Rack::Headers)
            ->(h) { h }
          else
            ->(h) { Rack::Utils::HeaderHash.new(h) }
          end
        end
      end
    end
  end
end
