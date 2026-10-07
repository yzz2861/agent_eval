# -*- ruby encoding: utf-8 -*-

class Net::LDAP
  # Raised when an LDAP URL cannot be parsed.
  class LdapUrlError < Error; end

  ##
  # Parses an LDAP URL as described by RFC 4516:
  #
  #   ldap://host:port/dn?attributes?scope?filter?extensions
  #
  # Every field after the authority is optional; a field that is absent (or
  # empty) is exposed as +nil+ so that callers can apply their own
  # inheritance rules (e.g. falling back to the parameters of the search
  # that produced a referral).
  #
  #   url = Net::LDAP::LdapUrl.parse("ldap://example.com/dc=example,dc=com?cn,mail?sub?(objectClass=*)")
  #   url.host       # => "example.com"
  #   url.port       # => 389
  #   url.dn         # => "dc=example,dc=com"
  #   url.attributes # => ["cn", "mail"]
  #   url.scope      # => Net::LDAP::SearchScope_WholeSubtree
  #   url.filter     # => "(objectClass=*)"
  #
  # Percent-escapes (e.g. %2C, %3D) are decoded in every field.
  class LdapUrl
    DEFAULT_PORTS = { "ldap" => 389, "ldaps" => 636 }.freeze

    attr_reader :scheme, :host, :port, :dn, :attributes, :scope, :filter, :extensions

    class << self
      # Parses +string+ into a Net::LDAP::LdapUrl. Raises
      # Net::LDAP::LdapUrlError when the string is not a valid LDAP URL.
      def parse(string)
        match = %r{\A(ldap|ldaps)://([^/?]*)(/.*)?\z}i.match(string.to_s)
        unless match
          raise Net::LDAP::LdapUrlError, "invalid LDAP URL: #{string.inspect}"
        end

        scheme = match[1].downcase
        host, port = parse_authority(match[2], scheme, string)
        dn, attributes, scope, filter, extensions =
          parse_path(match[3] ? match[3][1..-1] : "", string)

        new(scheme: scheme, host: host, port: port, dn: dn,
            attributes: attributes, scope: scope, filter: filter,
            extensions: extensions)
      end

      # Decodes RFC 4516 percent-escapes. Raises Net::LDAP::LdapUrlError on
      # malformed escape sequences.
      def unescape(string)
        if string =~ /%(?![0-9A-Fa-f]{2})/
          raise Net::LDAP::LdapUrlError, "invalid percent-encoding in LDAP URL: #{string.inspect}"
        end
        string.gsub(/%([0-9A-Fa-f]{2})/) { [$1].pack("H2") }.force_encoding(Encoding::UTF_8)
      end

      private

      def parse_authority(authority, scheme, original)
        match =
          if authority.start_with?("[")
            /\A\[(?<host>[^\]]*)\](?::(?<port>\d+))?\z/.match(authority)
          else
            /\A(?<host>[^:]*)(?::(?<port>\d+))?\z/.match(authority)
          end
        unless match
          raise Net::LDAP::LdapUrlError, "invalid authority in LDAP URL: #{original.inspect}"
        end

        host = unescape(match[:host])
        if host.empty?
          raise Net::LDAP::LdapUrlError, "LDAP URL has no host: #{original.inspect}"
        end

        port = match[:port] ? match[:port].to_i : DEFAULT_PORTS.fetch(scheme)
        [host, port]
      end

      def parse_path(path, original)
        segments = path.split("?", -1)
        if segments.length > 5
          raise Net::LDAP::LdapUrlError, "too many fields in LDAP URL: #{original.inspect}"
        end

        dn, attributes, scope, filter, extensions = segments.map do |segment|
          present(segment) ? unescape(segment) : nil
        end

        if attributes
          attributes = attributes.split(",").map(&:strip).reject(&:empty?)
          attributes = nil if attributes.empty?
        end

        scope = parse_scope(scope, original)

        [dn, attributes, scope, filter, extensions]
      end

      def parse_scope(scope, original)
        return nil unless scope

        value = {
          "base" => Net::LDAP::SearchScope_BaseObject,
          "one"  => Net::LDAP::SearchScope_SingleLevel,
          "sub"  => Net::LDAP::SearchScope_WholeSubtree,
        }[scope.downcase]
        unless value
          raise Net::LDAP::LdapUrlError, "invalid scope #{scope.inspect} in LDAP URL: #{original.inspect}"
        end
        value
      end

      def present(segment)
        !segment.nil? && !segment.empty?
      end
    end

    def initialize(scheme:, host:, port:, dn:, attributes:, scope:, filter:, extensions:)
      @scheme = scheme
      @host = host
      @port = port
      @dn = dn
      @attributes = attributes
      @scope = scope
      @filter = filter
      @extensions = extensions
    end

    # True when the URL uses the +ldaps+ (LDAP over TLS) scheme.
    def tls?
      scheme == "ldaps"
    end
  end
end
