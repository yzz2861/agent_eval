# frozen_string_literal: true

require_relative 'constants'

module Rack
  # Rack::URLMap takes a hash mapping urls or paths to apps, and
  # dispatches accordingly.  Support for HTTP/1.1 host names exists if
  # the URLs start with <tt>http://</tt> or <tt>https://</tt>.
  #
  # An explicit authority can also be given by using a hash as the map
  # key, with an +:authority+ entry and an optional +:path+ entry
  # (defaulting to <tt>/</tt>):
  #
  #   Rack::URLMap.new(
  #     { authority: 'example.com', path: '/api' } => api_app,
  #     { authority: '*.example.com' } => wildcard_app,
  #     { authority: 'example.com:9292' } => port_app,
  #     { authority: '[::1]:9292' } => ipv6_app,
  #     '/' => default_app)
  #
  # An authority is a host with an optional port.  The host may be an
  # exact host (<tt>example.com</tt>), a single-level subdomain wildcard
  # (<tt>*.example.com</tt>, which matches <tt>a.example.com</tt> but
  # neither <tt>example.com</tt> nor <tt>a.b.example.com</tt>), or an
  # IPv6 address enclosed in brackets (<tt>[::1]</tt>).  Host matching
  # is case-insensitive.  If the port is given, only requests whose
  # effective port matches are dispatched; if it is omitted, any port
  # matches.  Authorities that cannot be parsed raise ArgumentError.
  #
  # Only the current request's own server information (HTTP_HOST,
  # SERVER_NAME and SERVER_PORT) is used for authority matching;
  # forwarded headers are never consulted.
  #
  # Entries are tried from most to least specific: entries with an
  # authority come before entries without one, exact hosts come before
  # wildcards, authorities with a port come before authorities without
  # one, longer hosts come before shorter ones, and finally longer
  # paths come before shorter ones.
  #
  # URLMap modifies the SCRIPT_NAME and PATH_INFO such that the part
  # relevant for dispatch is in the SCRIPT_NAME, and the rest in the
  # PATH_INFO.  This should be taken care of when you need to
  # reconstruct the URL in order to create links.
  #
  # URLMap dispatches in such a way that the most specific entries are
  # tried first.

  class URLMap
    # Valid characters for a single host label.
    HOST_LABEL = /[A-Za-z0-9_-]+/
    private_constant :HOST_LABEL

    def initialize(map = {})
      remap(map)
    end

    def remap(map)
      @mapping = map.map { |location, app|
        authority = nil

        if location.is_a?(Hash)
          unknown = location.keys.map(&:to_s) - %w[authority path]
          unless unknown.empty?
            raise ArgumentError, "unknown URLMap keys: #{unknown.join(', ')}"
          end

          authority = location[:authority] || location['authority']
          unless authority
            raise ArgumentError, "URLMap hash keys must include an :authority entry"
          end
          location = location[:path] || location['path'] || '/'
        elsif location =~ %r{\Ahttps?://(.*?)(/.*)}
          authority, location = $1, $2
        end

        if authority
          # [host, port, wildcard]
          authority = parse_authority(authority)
        end

        unless location[0] == ?/
          raise ArgumentError, "paths need to start with /"
        end

        location = location.chomp('/')
        match = Regexp.new("\\A#{Regexp.quote(location).gsub('/', '/+')}(.*)", Regexp::NOENCODING).freeze

        [authority, location, match, app]
      }.sort_by do |(authority, location, _, _)|
        if authority
          host, port, wildcard = authority
          [0, wildcard ? 1 : 0, port ? 0 : 1, -host.size, -location.size]
        else
          [1, 0, 0, 0, -location.size]
        end
      end
    end

    def call(env)
      path        = env[PATH_INFO]
      script_name = env[SCRIPT_NAME]
      http_host   = env[HTTP_HOST]
      server_name = env[SERVER_NAME]
      server_port = env[SERVER_PORT]

      # Only the request's own server information is considered;
      # forwarded headers are deliberately ignored.
      candidates = request_authorities(env)

      is_same_server = casecmp?(http_host, server_name) ||
                       casecmp?(http_host, "#{server_name}:#{server_port}")

      is_host_known = @mapping.any? do |authority, _, _, _|
        authority && candidates.any? { |host, port| authority_match?(authority, host, port) }
      end

      @mapping.each do |authority, location, match, app|
        if authority
          next unless candidates.any? { |host, port| authority_match?(authority, host, port) }
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

    # Parse a configured authority string into [host, port, wildcard],
    # raising ArgumentError when invalid.  IPv6 addresses must be
    # enclosed in brackets.  A wildcard is a single leading "*." label;
    # the stored host is the suffix it matches against.
    def parse_authority(authority)
      invalid = -> { raise ArgumentError, "invalid authority: #{authority.inspect}" }

      invalid.call unless authority.is_a?(String)
      authority = authority.strip
      invalid.call if authority.empty?

      port = nil
      wildcard = false

      if authority.start_with?('[')
        match = /\A\[([0-9A-Fa-f:.]+)\](?::(\d+))?\z/.match(authority)
        invalid.call unless match
        host = match[1].downcase
        port = match[2]
      else
        invalid.call if authority.count(':') > 1
        host, port = authority.split(':', 2)
        host = host.downcase
        wildcard = host.start_with?('*.')
        suffix = wildcard ? host[2..] : host
        invalid.call unless suffix.match?(/\A#{HOST_LABEL}(?:\.#{HOST_LABEL})*\z/)
        host = suffix if wildcard
      end

      if port
        invalid.call unless port.match?(/\A\d+\z/)
        port = port.to_i
        invalid.call unless port >= 1 && port <= 65535
      end

      [host, port, wildcard]
    end

    # Build the list of [host, port] candidates for the current request
    # from HTTP_HOST and SERVER_NAME/SERVER_PORT only.
    def request_authorities(env)
      http_host   = env[HTTP_HOST]
      server_name = env[SERVER_NAME]
      server_port = env[SERVER_PORT]

      port = server_port.to_s[/\A\d+\z/]
      port = (port ? port.to_i : nil) || (env[RACK_URL_SCHEME] == 'https' ? 443 : 80)

      candidates = []

      if http_host && !http_host.empty?
        candidate = parse_request_authority(http_host, port)
        candidates << candidate if candidate
      end

      if server_name && !server_name.empty?
        host = server_name.downcase
        host = host[1..-2] if host.start_with?('[') && host.end_with?(']')
        candidates << [host, port]
      end

      candidates
    end

    # Parse the Host header into [host, port], returning nil when it is
    # malformed so a malformed authority can never match a rule.
    def parse_request_authority(str, default_port)
      if str.start_with?('[')
        close = str.index(']')
        return nil unless close
        host = str[1...close]
        rest = str[(close + 1)..]
        return nil if host.empty?
        return nil unless rest.empty? || rest.start_with?(':')
        port = rest[1..]
        return nil if port && (port.empty? || !port.match?(/\A\d+\z/))
        [host.downcase, port ? port.to_i : default_port]
      else
        return nil if str.count(':') > 1
        host, port = str.split(':', 2)
        return nil if host.nil? || host.empty?
        return nil if port && (port.empty? || !port.match?(/\A\d+\z/))
        [host.downcase, port ? port.to_i : default_port]
      end
    end

    def authority_match?(authority, host, port)
      rule_host, rule_port, wildcard = authority
      return false unless host
      return false if rule_port && rule_port != port

      if wildcard
        wildcard_match?(rule_host, host)
      else
        host == rule_host
      end
    end

    # Single-level wildcard: "*.example.com" matches "a.example.com"
    # but not "example.com" or "a.b.example.com".  The label must be a
    # valid host label so malformed authorities cannot match.
    def wildcard_match?(suffix, host)
      return false unless host.length > suffix.length + 1
      return false unless host.end_with?(".#{suffix}")
      label = host[0...(-suffix.length - 1)]
      label.match?(/\A#{HOST_LABEL}\z/)
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
