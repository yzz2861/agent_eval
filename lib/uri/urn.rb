# frozen_string_literal: false
# = uri/urn.rb
#
# Author:: Akira Yamada <akira@ruby-lang.org>
# License:: You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require_relative 'generic'

module URI

  #
  # RFC8141, Uniform Resource Names (URNs).
  #
  class URN < Generic
    # A Default port of nil for URI::URN.
    DEFAULT_PORT = nil

    # An Array of the available components for URI::URN.
    COMPONENT = [
      :scheme,
      :nid,
      :nss,
      :r_component,
      :q_component,
      :fragment,
    ].freeze

    # :stopdoc:
    #  "namestring" and its parts are defined in RFC 8141 as follows:
    #
    #    namestring    = assigned-name [ rq-components ] [ "#" f-component ]
    #    assigned-name = "urn" ":" NID ":" NSS
    #    NID           = (alphanum) 0*30(ldh) (alphanum)
    #    ldh           = alphanum / "-"
    #    NSS           = pchar *(pchar / "/")
    #    rq-components = [ "?+" r-component ] [ "?=" q-component ]
    #    r-component   = pchar *( pchar / "/" / "?" )
    #    q-component   = pchar *( pchar / "/" / "?" )
    #
    #  Note that the NSS, the r-component, and the q-component can contain
    #  pct-encoded characters; a pct-encoded delimiter (e.g. "%3F") is data
    #  and never acts as a structural delimiter.

    # ; RFC 8141
    # NID = (alphanum) 0*30(ldh) (alphanum)
    NID_REGEXP = /\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])\z/
    # ; RFC 3986
    # pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
    PCHAR = "(?:%\\h\\h|[!$&-.0-9:;=@A-Z_a-z~])"
    # NSS = pchar *(pchar / "/")
    NSS_REGEXP = /\A#{PCHAR}(?:#{PCHAR}|\/)*\z/
    # r-component / q-component = pchar *( pchar / "/" / "?" )
    RQ_COMPONENT_REGEXP = /\A(?:#{PCHAR}|\/|\?)+\z/
    # "?+" starts the r-component, "?=" starts the q-component
    RQ_DELIMITER_REGEXP = /\?\+|\?=/
    # :startdoc:

    #
    # == Description
    #
    # Creates a new URI::URN object from components, with syntax checking.
    #
    # Components can be provided as an Array or a Hash. If an Array is used,
    # the components must be supplied as
    # <code>[nid, nss, r_component, q_component, fragment]</code>.
    #
    # If a Hash is used, the keys are the component names preceded by colons.
    #
    # Examples:
    #
    #    require 'uri'
    #
    #    u1 = URI::URN.build(['example', 'foo', nil, nil, nil])
    #    u1.to_s  # => "urn:example:foo"
    #
    #    u2 = URI::URN.build({:nid => 'example', :nss => 'foo',
    #                         :r_component => 'rr', :q_component => 'qq',
    #                         :fragment => 'frag'})
    #    u2.to_s  # => "urn:example:foo?+rr?=qq#frag"
    #
    def self.build(args)
      tmp = Util.make_components_hash(self, args)

      nid = tmp[:nid]
      nss = tmp[:nss]
      r_component = tmp[:r_component]
      q_component = tmp[:q_component]

      opaque = +"#{nid}:#{nss}"
      opaque << "?+#{r_component}" if r_component
      opaque << "?=#{q_component}" if q_component
      tmp[:opaque] = opaque

      uri = super(tmp)

      # The composed opaque part is parsed back into components by
      # URI::URN.new; make sure every component round-tripped exactly,
      # so that a delimiter hidden in a component cannot be silently
      # reinterpreted as structure.
      unless uri.nid == nid && uri.nss == nss &&
             uri.r_component == r_component && uri.q_component == q_component
        raise InvalidComponentError,
          "bad components for URN: #{tmp.inspect}"
      end

      uri
    end

    #
    # == Description
    #
    # Creates a new URI::URN object from generic URL components with
    # no syntax checking.
    #
    # This method is usually called from URI::parse, which checks
    # the validity of each component.
    #
    def initialize(*arg)
      super(*arg)

      @nid = nil
      @nss = nil
      @r_component = nil
      @q_component = nil

      # The RFC3986 parser does not normally populate opaque
      @opaque = "?#{@query}" if @query && !@opaque

      unless @opaque
        raise InvalidComponentError,
          "missing opaque part for URN"
      end

      nid, nss, r_component, q_component = self.class.split_opaque(@opaque)

      check_nid(nid)
      check_nss(nss)
      check_r_component(r_component)
      check_q_component(q_component)

      set_nid(nid)
      set_nss(nss)
      set_r_component(r_component)
      set_q_component(q_component)
    end

    # The namespace identifier (NID) of the URN, as a String.
    attr_reader :nid

    # The namespace-specific string (NSS) of the URN, as a String.
    attr_reader :nss

    # The r-component of the URN (the part introduced by "?+"),
    # as a String, or nil if not present.
    attr_reader :r_component

    # The q-component of the URN (the part introduced by "?="),
    # as a String, or nil if not present.
    attr_reader :q_component

    # Splits the opaque part of a URN (the part after "urn:") into
    # <code>[nid, nss, r_component, q_component]</code>.
    #
    # Only literal "?+", "?=", and ":" act as delimiters here;
    # pct-encoded characters such as "%3F" are left untouched.
    def self.split_opaque(opaque) # :nodoc:
      nid, colon, rest = opaque.partition(':')
      if colon.empty? || rest.empty?
        raise InvalidComponentError,
          "bad component(expected opaque component): #{opaque}"
      end

      nss = rest
      r_component = q_component = nil
      if m = RQ_DELIMITER_REGEXP.match(rest)
        nss = rest[0...m.begin(0)]
        tail = rest[m.begin(0)..-1]
        if tail.start_with?('?+')
          tail = tail[2..-1]
          if idx = tail.index('?=')
            r_component = tail[0...idx]
            q_component = tail[(idx + 2)..-1]
          else
            r_component = tail
          end
        else
          q_component = tail[2..-1]
        end
      end

      [nid, nss, r_component, q_component]
    end

    # Checks the nid +v+ component against NID_REGEXP.
    def check_nid(v)
      unless v.is_a?(String) && NID_REGEXP.match?(v)
        raise InvalidComponentError,
          "bad component(expected nid component): #{v.inspect}"
      end
      if v.casecmp?('urn')
        raise InvalidComponentError,
          "nid 'urn' is reserved: #{v}"
      end

      true
    end
    private :check_nid

    # Private setter for nid +v+.
    def set_nid(v)
      @nid = v
      sync_opaque
    end
    protected :set_nid

    # Setter for nid +v+.
    def nid=(v)
      check_nid(v)
      set_nid(v)
      v
    end

    # Checks the nss +v+ component against NSS_REGEXP.
    def check_nss(v)
      unless v.is_a?(String) && NSS_REGEXP.match?(v)
        raise InvalidComponentError,
          "bad component(expected nss component): #{v.inspect}"
      end

      true
    end
    private :check_nss

    # Private setter for nss +v+.
    def set_nss(v)
      @nss = v
      sync_opaque
    end
    protected :set_nss

    # Setter for nss +v+.
    def nss=(v)
      check_nss(v)
      set_nss(v)
      v
    end

    # Checks the r-component +v+ against RQ_COMPONENT_REGEXP.
    def check_r_component(v)
      return true unless v
      unless v.is_a?(String) && RQ_COMPONENT_REGEXP.match?(v)
        raise InvalidComponentError,
          "bad component(expected r-component): #{v.inspect}"
      end

      true
    end
    private :check_r_component

    # Private setter for r-component +v+.
    def set_r_component(v)
      @r_component = v
      sync_opaque
    end
    protected :set_r_component

    # Setter for r-component +v+.
    def r_component=(v)
      check_r_component(v)
      set_r_component(v)
      v
    end

    # Checks the q-component +v+ against RQ_COMPONENT_REGEXP.
    def check_q_component(v)
      return true unless v
      unless v.is_a?(String) && RQ_COMPONENT_REGEXP.match?(v)
        raise InvalidComponentError,
          "bad component(expected q-component): #{v.inspect}"
      end

      true
    end
    private :check_q_component

    # Private setter for q-component +v+.
    def set_q_component(v)
      @q_component = v
      sync_opaque
    end
    protected :set_q_component

    # Setter for q-component +v+.
    def q_component=(v)
      check_q_component(v)
      set_q_component(v)
      v
    end

    # Setter for the opaque component +v+ (with validation).
    #
    # The nid, nss, r-component, and q-component are re-parsed from +v+.
    def opaque=(v)
      check_opaque(v)
      set_opaque(v)
      if v
        nid, nss, r_component, q_component = self.class.split_opaque(v)
        self.nid = nid
        self.nss = nss
        self.r_component = r_component
        self.q_component = q_component
      end
      v
    end

    # Updates the opaque part from the individual components.
    def sync_opaque # :nodoc:
      return unless @nid && @nss
      opaque = +"#{@nid}:#{@nss}"
      opaque << "?+#{@r_component}" if @r_component
      opaque << "?=#{@q_component}" if @q_component
      @opaque = opaque
    end
    private :sync_opaque

    #
    # Constructs String from URI.
    #
    def to_s
      str = +"#{@scheme}:#{@nid}:#{@nss}"
      str << "?+#{@r_component}" if @r_component
      str << "?=#{@q_component}" if @q_component
      str << "##{@fragment}" if @fragment
      str
    end

    #
    # Compares two URNs for name equivalence, as defined by RFC 8141.
    #
    # Two URNs are name-equivalent when their NIDs are equal
    # case-insensitively and their NSSs are equal octet-by-octet after
    # normalizing the hexadecimal digits of pct-encoded triplets to
    # uppercase. The NSS itself is case-sensitive, and the r-component,
    # q-component, and fragment are not taken into account.
    #
    # Use #eql? (or compare #to_s) for full string equality of all
    # components.
    #
    def ==(oth)
      if self.class == oth.class
        s = normalize
        o = oth.normalize
        s.scheme == o.scheme && s.nid == o.nid && s.nss == o.nss
      else
        false
      end
    end

    # Returns true if +oth+ is a URN name-equivalent to this one.
    # See #==.
    alias name_equivalent? ==

    #
    # Destructive version of #normalize.
    #
    # Normalizes the scheme and the nid to lowercase and the hexadecimal
    # digits of pct-encoded triplets in the nss to uppercase. The nss
    # itself is case-sensitive and is never lowercased.
    #
    def normalize!
      if scheme && scheme != scheme.downcase
        set_scheme(scheme.downcase)
      end
      if nid && nid != nid.downcase
        set_nid(nid.downcase)
      end
      if nss
        normalized = nss.gsub(/%\h\h/) {|triplet| triplet.upcase }
        set_nss(normalized) if normalized != nss
      end
    end
  end

  register_scheme 'URN', URN
end
