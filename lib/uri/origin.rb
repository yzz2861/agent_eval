# frozen_string_literal: true

# = uri/origin.rb
#
# License:: You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require_relative 'common'

module URI

  #
  # A value object representing the origin of a URI, as defined in
  # RFC 6454[https://www.rfc-editor.org/rfc/rfc6454].
  #
  # == Tuple origins
  #
  # A hierarchical URI with a scheme and a non-empty host (such as an
  # HTTP or HTTPS URI) has a <em>tuple origin</em> made of its scheme,
  # its normalized host, and its effective port (the explicit port, or
  # the scheme's default port when the URI has none).  The path,
  # userinfo, query, and fragment components do not take part in the
  # identity of an origin:
  #
  #   URI::Origin.from_uri(URI('http://user@Example.COM:80/a?x=1#f')) ==
  #     URI::Origin.from_uri(URI('http://example.com/other'))
  #   #=> true
  #
  # Being value objects, origins are suitable as Hash keys, e.g. to
  # group the connections of an HTTP proxy by origin:
  #
  #   pools[URI::Origin.from_uri(uri)] ||= ConnectionPool.new
  #
  # == Opaque origins
  #
  # A URI that does not carry an origin (an opaque URI such as
  # <tt>mailto:foo@example.com</tt>, or a hierarchical URI without a
  # host) yields an <em>opaque origin</em> instead.  Opaque origins are
  # globally unique: an opaque origin is only ever equal to itself,
  # even though every opaque origin serializes to the same text
  # (<tt>null</tt>).
  #
  #   URI::Origin.from_uri(URI('mailto:foo@example.com')) ==
  #     URI::Origin.from_uri(URI('mailto:foo@example.com'))
  #   #=> false
  #
  class Origin
    #
    # The scheme of this origin, downcased (<tt>http</tt>,
    # <tt>https</tt>, ...), or nil for an opaque origin.
    #
    attr_reader :scheme

    #
    # The normalized host of this origin: downcased, with IPv6 (and
    # future IP) addresses keeping their brackets.  nil for an opaque
    # origin.
    #
    attr_reader :host

    #
    # The effective port of this origin: the explicit port, or the
    # scheme's default port when the URI has no explicit one.  nil for
    # an opaque origin, and for tuple origins whose scheme has no
    # well-known default port when the URI has no explicit port.
    #
    attr_reader :port

    #
    # Returns the origin of +uri+ (a URI::Generic).
    #
    # Returns a tuple origin when +uri+ is a hierarchical URI with a
    # scheme and a non-empty host, and a fresh opaque origin otherwise.
    #
    #   URI::Origin.from_uri(URI('https://example.com:443/a'))
    #   #=> #<URI::Origin https://example.com>
    #   URI::Origin.from_uri(URI('mailto:foo@example.com'))
    #   #=> #<URI::Origin null>
    #
    def self.from_uri(uri)
      scheme = uri.scheme
      host = uri.host

      if scheme && host && !host.empty?
        new(scheme.downcase, host.downcase, uri.port || uri.default_port)
      else
        opaque
      end
    end

    #
    # Returns a fresh opaque origin.  Each call returns an origin that
    # is not equal to any other origin.
    #
    def self.opaque
      new(nil, nil, nil)
    end

    def initialize(scheme, host, port) # :nodoc:
      @scheme = scheme
      @host = host
      @port = port
      # A unique token giving each opaque origin its identity; nil for
      # tuple origins, which are compared by value.
      @token = Object.new if opaque?
      freeze
    end
    private_class_method :new

    #
    # Whether this is an opaque origin.  Opaque origins carry no
    # components and are only equal to themselves.
    #
    def opaque?
      @scheme.nil?
    end

    #
    # Two origins are equal when they are the same object, or when
    # both are tuple origins with equal scheme, host, and port.  An
    # opaque origin is never equal to another origin, not even to
    # another opaque origin.
    #
    def ==(other)
      return true if equal?(other)
      return false unless other.is_a?(Origin)
      return false if opaque? || other.opaque?

      scheme == other.scheme && host == other.host && port == other.port
    end
    alias eql? ==

    #
    # Returns the hash value.  Equal origins have equal hash values,
    # so origins can be used as Hash keys.
    #
    def hash
      @token ? @token.hash : [Origin, @scheme, @host, @port].hash
    end

    #
    # Returns the canonical serialization of this origin:
    # <tt>scheme://host</tt>, with <tt>:port</tt> appended when the
    # effective port differs from the scheme's well-known default
    # port.  Opaque origins serialize to <tt>null</tt>.
    #
    # Equal origins always serialize to the same String.  The converse
    # does not hold for opaque origins: distinct opaque origins all
    # serialize to <tt>null</tt> without being equal.
    #
    def to_s
      if opaque?
        +'null'
      elsif @port.nil? || @port == self.class.default_port_for(@scheme)
        scheme_host
      else
        scheme_host + ':' + @port.to_s
      end
    end

    def inspect # :nodoc:
      '#<URI::Origin ' + to_s + '>'
    end

    #
    # Returns the well-known default port for +scheme+ (a downcased
    # scheme name), or nil when the scheme has none.
    #
    def self.default_port_for(scheme)
      klass = URI.scheme_list[scheme.upcase]
      klass.default_port if klass
    end

    private

    def scheme_host # :nodoc:
      @scheme + '://' + @host
    end
  end
end
