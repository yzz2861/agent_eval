# frozen_string_literal: false
# = uri/origin.rb
#
# Author:: Akira Yamada <akira@ruby-lang.org>
# License:: You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require 'ipaddr'

module URI

  #
  # An origin as defined by RFC 6454[https://www.rfc-editor.org/rfc/rfc6454].
  #
  # An origin identifies the principal responsible for a URI.  For
  # +http:+ and +https:+ URIs it is the tuple of the (case-insensitive)
  # scheme, the canonicalized host and the effective port (the default
  # port is used when the URI omits it).  The userinfo, path, query and
  # fragment components never participate in the origin.
  #
  #   URI("http://example.com/a?b#c").origin ==
  #     URI("http://EXAMPLE.COM:80/").origin   #=> true
  #
  # URI::Origin is a value object: two origins with the same tuple are
  # interchangeable as Hash keys and serialize to the same String.
  #
  class Origin
    # Default ports of the schemes that have tuple origins, keyed by the
    # lowercase scheme name.
    DEFAULT_PORTS = {
      'http' => 80,
      'https' => 443,
    }.freeze

    # The lowercase scheme component of the origin.
    attr_reader :scheme

    # The canonicalized host component of the origin.
    # Reg-name hosts are lowercased and IP-literal hosts are kept wrapped
    # in brackets, with IPv6 addresses in compressed lowercase form.
    attr_reader :host

    # The effective port component of the origin as an Integer.
    attr_reader :port

    #
    # Creates an origin tuple from +scheme+, +host+ and +port+.
    #
    # +host+ must not be nil or empty (such URIs have an opaque origin,
    # see URI::OpaqueOrigin).  When +port+ is nil the scheme's default
    # port is used, if known.  +default_port+ overrides the default port
    # associated with +scheme+ and is also used to decide whether the
    # port is omitted from #to_s.
    #
    def initialize(scheme, host, port, default_port: nil)
      raise ArgumentError, "scheme component is required" unless scheme
      raise ArgumentError, "host component is required" if host.nil? || host.empty?

      @scheme = scheme.downcase.freeze
      @host = self.class.send(:canonical_host, host).freeze
      @default_port = default_port || DEFAULT_PORTS[@scheme]
      @port = port ? Integer(port) : @default_port
      @serialized = build_string.freeze
      freeze
    end

    # Returns false; this is a tuple origin rather than an opaque one.
    def opaque?
      false
    end

    # Returns true when +other+ is an origin with the same scheme,
    # canonical host and effective port.
    def ==(other)
      other.is_a?(Origin) &&
        scheme == other.scheme &&
        host == other.host &&
        port == other.port
    end
    alias eql? ==

    # Returns the hash value along with #==.
    def hash
      [self.class, scheme, host, port].hash
    end

    # Serializes the origin as +scheme://host+ or
    # +scheme://host:port+, omitting the default port.
    def to_s
      @serialized
    end
    alias to_str to_s

    def inspect # :nodoc:
      "#<#{self.class} #{self}>"
    end

    private

    def build_string
      if @port && @port != @default_port
        "#{@scheme}://#{@host}:#{@port}"
      else
        "#{@scheme}://#{@host}"
      end
    end

    def self.canonical_host(host)
      host = host.downcase
      if host.start_with?('[') && host.end_with?(']')
        inner = host[1..-2]
        address, zone = inner.split('%', 2)
        begin
          address = IPAddr.new(address).to_s
        rescue IPAddr::Error, ArgumentError
          # Not an IPv6 address (e.g. an IPvFuture literal); keep it verbatim.
        else
          inner = zone ? "#{address}%#{zone}" : address
        end
        host = "[#{inner}]"
      end
      host
    end
  end

  #
  # An opaque origin as defined by RFC 6454 section 4.
  #
  # URIs without an origin (such as +mailto:+, +file:+ or the
  # authority-less +http:foo+) carry a unique, unguessable opaque origin.
  # Every URI::OpaqueOrigin instance is distinct: even though they all
  # serialize as the string +"null"+ (as required by the RFC), they are
  # never equal and never collide as Hash keys.
  #
  #   a = URI("mailto:foo@example.com").origin
  #   b = URI("mailto:bar@example.com").origin
  #   a.to_s       #=> "null"
  #   a == b       #=> false
  #
  class OpaqueOrigin
    def initialize
      freeze
    end

    # Returns true; this is an opaque origin.
    def opaque?
      true
    end

    # Returns true only for this very opaque origin instance.
    def ==(other)
      equal?(other)
    end
    alias eql? ==

    # Distinct opaque origins have distinct hash values.
    def hash
      object_id
    end

    # Serializes the opaque origin as the string "null", as required by
    # RFC 6454 section 6.2.
    def to_s
      'null'
    end
    alias to_str to_s

    def inspect # :nodoc:
      "#<#{self.class} null>"
    end
  end

end
