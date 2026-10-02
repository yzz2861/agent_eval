# frozen_string_literal: true

require_relative 'constants'

module Rack
  # Rack::URLMap takes a hash mapping urls or paths to apps, and
  # dispatches accordingly.  Support for HTTP/1.1 host names exists if
  # the URLs start with <tt>http://</tt> or <tt>https://</tt>.
  #
  # For explicit control over which requests a mapped application
  # serves, a map key may also be a hash with an +authority+ and an
  # optional +path+ (defaulting to <tt>/</tt>):
  #
  #   Rack::URLMap.new(
  #     { authority: "example.com",      path: "/app" } => app,
  #     { authority: "*.example.com"                } => sub_app,
  #   )
  #
  # An authority is an exact host (<tt>example.com</tt>), a
  # single-label subdomain wildcard (<tt>*.example.com</tt>, which
  # matches <tt>a.example.com</tt> but neither <tt>example.com</tt>
  # nor <tt>a.b.example.com</tt>), and may carry an explicit port
  # (<tt>example.com:8080</tt>).  IPv6 literals must be enclosed in
  # square brackets (<tt>[::1]:8080</tt>).  Host matching is
  # case-insensitive.  When the authority omits the port, any request
  # port matches; when the request omits the port, SERVER_PORT is
  # consulted.  An invalid authority raises ArgumentError at
  # configuration time instead of silently matching unrelated
  # requests.
  #
  # Authorities are matched only against the current request's own
  # server information (HTTP_HOST, SERVER_NAME and SERVER_PORT);
  # forwarded headers are never consulted.
  #
  # Entries are tried from most to least specific authority: exact
  # host with port, exact host, wildcard with port, wildcard, and
  # finally entries without an authority.  Within each group, longer
  # hosts and longer paths are tried first, since they are most
  # specific.
  #
  # URLMap modifies the SCRIPT_NAME and PATH_INFO such that the part
  # relevant for dispatch is in the SCRIPT_NAME, and the rest in the
  # PATH_INFO.  Both are restored once the mapped application returns
  # or raises, so nested URLMaps leave the environment as they found
  # it.  This should be taken care of when you need to reconstruct the
  # URL in order to create links.
  #
  # URLMap dispatches in such a way that the longest paths are tried
  # first, since they are most specific.

  class URLMap
    # A parsed authority mapping option: an exact host or a
    # single-label wildcard, plus an optional port.
    class Authority
      LABEL = /[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/i
      HOST_NAME = /\A#{LABEL}(?:\.#{LABEL})*\z/.freeze
      BRACKETED = /\A\[([0-9a-fA-F:.]*:[0-9a-fA-F:.]*)\](?::(\d+))?\z/.freeze
      PLAIN = /\A([^:\/\[\]\s]+)(?::(\d+))?\z/.freeze

      private_constant :LABEL, :HOST_NAME, :BRACKETED, :PLAIN

      attr_reader :host, :port

      def self.parse(authority)
        unless authority.is_a?(String) && !authority.empty?
          raise ArgumentError, "authority must be a non-empty string"
        end

        if authority.start_with?('[')
          unless match = BRACKETED.match(authority)
            raise ArgumentError, "invalid authority: #{authority.inspect}"
          end

          new(match[1], match[2], wildcard: false, original: authority)
        else
          unless match = PLAIN.match(authority)
            raise ArgumentError, "invalid authority: #{authority.inspect}"
          end

          host = match[1]
          if host.start_with?('*.')
            suffix = host[2..]
            unless HOST_NAME.match?(suffix)
              raise ArgumentError, "invalid wildcard authority: #{authority.inspect}"
            end

            new(suffix, match[2], wildcard: true, original: authority)
          else
            if host.include?('*')
              raise ArgumentError, "wildcard is only allowed as the left-most label: #{authority.inspect}"
            end
            unless HOST_NAME.match?(host)
              raise ArgumentError, "invalid host in authority: #{authority.inspect}"
            end

            new(host, match[2], wildcard: false, original: authority)
          end
        end
      end

      def initialize(host, port, wildcard:, original:)
        @wildcard = wildcard
        # Wildcards are stored with a leading dot as a suffix to match.
        @host = (wildcard ? ".#{host}" : host).downcase

        if port
          port = Integer(port, 10)
          unless port.between?(0, 65535)
            raise ArgumentError, "invalid port in authority: #{original.inspect}"
          end
        end
        @port = port
      end

      def match?(host, port)
        return false if host.nil? || host.empty?

        host = host.downcase
        if @wildcard
          return false unless host.end_with?(@host)

          prefix = host[0...-@host.size]
          # The wildcard covers exactly one label.
          return false if prefix.empty? || prefix.include?('.')
        else
          return false unless host == @host
        end

        @port.nil? || @port == port
      end

      # Exact host beats wildcard; a specified port is more specific
      # than an omitted one.
      def specificity
        (@wildcard ? 2 : 4) + (@port ? 1 : 0)
      end
    end

    def initialize(map = {})
      remap(map)
    end

    def remap(map)
      @authorities = []
      @mapping = map.map { |location, app|
        authority = nil

        if location.is_a?(Hash)
          authority = Authority.parse(location[:authority] || location['authority'])
          location = location[:path] || location['path'] || '/'
        elsif location =~ %r{\Ahttps?://(.*?)(/.*)}
          authority = Authority.parse($1)
          location = $2
        end

        unless location.is_a?(String) && location[0] == ?/
          raise ArgumentError, "paths need to start with /"
        end

        location = location.chomp('/')
        match = Regexp.new("\\A#{Regexp.quote(location).gsub('/', '/+')}(.*)", Regexp::NOENCODING).freeze

        @authorities << authority if authority

        [authority, location, match, app]
      }.sort_by do |(authority, location, _, _)|
        if authority
          [-authority.specificity, -authority.host.size, -location.size]
        else
          [0, 0, -location.size]
        end
      end
    end

    def call(env)
      path        = env[PATH_INFO]
      script_name = env[SCRIPT_NAME]
      http_host   = env[HTTP_HOST]
      server_name = env[SERVER_NAME]
      server_port = env[SERVER_PORT]

      is_same_server = casecmp?(http_host, server_name) ||
                       casecmp?(http_host, "#{server_name}:#{server_port}")

      candidates = request_authorities(http_host, server_name, server_port, env[RACK_URL_SCHEME])

      is_host_known = @authorities.any? do |authority|
        candidates.any? { |host, port| authority.match?(host, port) }
      end

      @mapping.each do |authority, location, match, app|
        if authority
          next unless candidates.any? { |host, port| authority.match?(host, port) }
        else
          # If we don't have a matching host, default to the first without a specified host
          next unless is_same_server || !is_host_known
        end

        next unless m = match.match(path.to_s)

        rest = m[1]
        next unless !rest || rest.empty? || rest[0] == ?/

        env[SCRIPT_NAME] = (script_name + location)
        env[PATH_INFO] = rest

        return app.call(env)
      end

      [404, { CONTENT_TYPE => "text/plain", "x-cascade" => "pass" }, ["Not Found: #{path}"]]

    ensure
      env[PATH_INFO]   = path
      env[SCRIPT_NAME] = script_name
    end

    private

    # The authorities the current request itself claims, built from
    # HTTP_HOST and SERVER_NAME/SERVER_PORT only.  Forwarded headers
    # are deliberately ignored.  A malformed HTTP_HOST is discarded
    # rather than matched against anything.
    def request_authorities(http_host, server_name, server_port, scheme)
      server_port = server_port.to_i if server_port
      server_port ||= scheme == 'https' ? 443 : 80

      candidates = []
      if (parsed = parse_host_header(http_host))
        candidates << [parsed[0], parsed[1] || server_port]
      end
      if server_name.is_a?(String) && !server_name.empty?
        if server_name.start_with?('[') && server_name.end_with?(']')
          server_name = server_name[1...-1]
        end
        candidates << [server_name, server_port]
      end
      candidates
    end

    def parse_host_header(http_host)
      return nil unless http_host.is_a?(String) && !http_host.empty?

      if http_host.start_with?('[')
        return nil unless http_host =~ /\A\[([0-9a-fA-F:.]+)\](?::(\d+))?\z/
      else
        return nil unless http_host =~ /\A([^:\/\[\]\s]+)(?::(\d+))?\z/
      end

      [$1, $2 && Integer($2, 10)]
    end

    def casecmp?(v1, v2)
      # if both nil, or they're the same string
      return true if v1 == v2

      # if either are nil... (but they're not the same)
      return false if v1.nil?
      return false if v2.nil?

      # otherwise check they're not case-insensitive the same
      v1.casecmp(v2).zero?
    end
  end
end
