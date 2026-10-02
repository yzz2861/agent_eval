# frozen_string_literal: true

module Rack
  class Cors
    class Resource
      # All CORS routes need to accept CORS simple headers at all times
      # {https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers}
      CORS_SIMPLE_HEADERS = %w[accept accept-language content-language content-type].freeze

      attr_accessor :path, :methods, :headers, :expose, :max_age, :credentials, :pattern, :if_proc, :vary_headers

      def initialize(public_resource, wildcard_origin, path, opts = {})
        # '*' must never be combined with credentials=true, even when more
        # specific origins are declared alongside the wildcard.
        raise CorsMisconfigurationError if wildcard_origin && opts[:credentials] == true

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

      def process_preflight(env, result, origin_result = nil)
        headers = {}

        request_method = env[Rack::Cors::HTTP_ACCESS_CONTROL_REQUEST_METHOD]
        result.miss(Result::MISS_NO_METHOD) && (return headers) if request_method.nil?
        result.miss(Result::MISS_DENY_METHOD) && (return headers) unless methods.include?(request_method.downcase)

        request_headers = env[Rack::Cors::HTTP_ACCESS_CONTROL_REQUEST_HEADERS]
        result.miss(Result::MISS_DENY_HEADER) && (return headers) if request_headers && !allow_headers?(request_headers)

        result.hit = true
        headers.merge(to_preflight_headers(env, origin_result))
      end

      def to_headers(env, origin_result = nil)
        h = {
          'access-control-allow-origin' => origin_for_response_header(env[Rack::Cors::HTTP_ORIGIN], origin_result),
          'access-control-allow-methods' => methods.collect { |m| m.to_s.upcase }.join(', '),
          'access-control-expose-headers' => expose.nil? ? '' : expose.join(', '),
          'access-control-max-age' => effective_max_age(origin_result).to_s
        }
        h['access-control-allow-credentials'] = 'true' if effective_credentials?(origin_result)
        header_proc.call(h)
      end

      protected

      def public_resource?
        @public_resource
      end

      def origin_for_response_header(origin, origin_result = nil)
        return '*' if origin_result&.public_resource? || (origin_result.nil? && public_resource?)
        origin
      end

      def effective_credentials?(origin_result)
        return false if origin_result&.public_resource?

        if origin_result && !origin_result.credentials.nil?
          origin_result.credentials == true
        else
          credentials
        end
      end

      def effective_max_age(origin_result)
        if origin_result && !origin_result.max_age.nil?
          origin_result.max_age
        else
          max_age
        end
      end

      def to_preflight_headers(env, origin_result)
        h = to_headers(env, origin_result)
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
