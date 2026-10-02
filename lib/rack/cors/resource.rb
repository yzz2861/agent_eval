# frozen_string_literal: true

module Rack
  class Cors
    class Resource
      # All CORS routes need to accept CORS simple headers at all times
      # {https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers}
      CORS_SIMPLE_HEADERS = %w[accept accept-language content-language content-type].freeze

      attr_accessor :path, :methods, :headers, :expose, :max_age, :credentials, :pattern, :if_proc, :vary_headers
      attr_reader :any_methods, :max_age_configured

      def initialize(public_resource, path, opts = {})
        raise CorsMisconfigurationError if public_resource && opts[:credentials] == true

        self.path         = path
        self.credentials  = public_resource ? false : (opts[:credentials] == true)
        @max_age_configured = opts.key?(:max_age)
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

        @any_methods = opts[:methods] == :any
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

      def public_resource?
        @public_resource
      end

      # Combine all the resources that match a request by intersecting their
      # permissions.  Order of the matched resources must not affect the
      # result, so collections are normalized (sorted/uniq) here.
      def self.combine(matched_resources)
        resources = matched_resources
        public_all = resources.all?(&:public_resource?)

        combined = new(public_all, resources.first.path)
        combined.send(:combine_attributes, resources)
        combined
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
          'access-control-expose-headers' => expose.nil? ? '' : expose.join(', '),
          'access-control-max-age' => max_age.to_s
        }
        h['access-control-allow-credentials'] = 'true' if credentials
        header_proc.call(h)
      end

      protected

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

      def combine_attributes(resources)
        combine_methods(resources)
        combine_headers(resources)

        # expose only grants the client visibility into response headers, so
        # matched rules accumulate: the union is allowed.
        self.expose = resources.flat_map { |r| r.expose || [] }.uniq.sort
        self.expose = nil if expose.empty?

        configured_ages = resources.select(&:max_age_configured).map(&:max_age)
        self.max_age = configured_ages.empty? ? 7200 : configured_ages.min
        @max_age_configured = !configured_ages.empty?

        # Credentials are only sent when every matched rule grants them.
        self.credentials = resources.all?(&:credentials)

        self.vary_headers = resources.flat_map { |r| r.vary_headers || [] }.uniq.sort
        self.vary_headers = nil if vary_headers.empty?
      end

      def combine_methods(resources)
        if resources.any?(&:any_methods)
          explicit = resources.reject(&:any_methods)
          if explicit.empty?
            @any_methods = true
            self.methods = %w[get head post put patch delete options]
          else
            self.methods = explicit.map(&:methods).reduce(:&)
            @any_methods = false
          end
        else
          self.methods = resources.map(&:methods).reduce(:&)
          @any_methods = false
        end
        self.methods = methods.sort.uniq
      end

      def combine_headers(resources)
        if resources.any? { |r| r.headers == :any }
          explicit = resources.reject { |r| r.headers == :any }
          if explicit.empty?
            self.headers = :any
          else
            self.headers = explicit.map { |r| r.headers || [] }.reduce(:&).sort
          end
        else
          self.headers = resources.map { |r| r.headers || [] }.reduce(:&).sort
        end
      end
    end
  end
end
