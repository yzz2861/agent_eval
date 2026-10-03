# :markup: markdown
# frozen_string_literal: true

# Describes the context of an HTTP request for the purpose of
# SameSite cookie evaluation.
#
# A request context captures the information a user agent needs in
# order to decide whether a cookie with a SameSite attribute may be
# sent with a request: the request method, the schemeful site of the
# top-level document, whether the request is a top-level navigation,
# and the schemeful sites of every URL in the redirect chain that
# led to the request.
class HTTP::Cookie::RequestContext
  # Request methods considered safe for the SameSite=Lax top-level
  # navigation exemption (cf. RFC 7231 4.2.1).
  SAFE_METHODS = %w[GET HEAD].freeze

  # The request method, normalized to upper case.
  attr_reader :method

  # The schemeful site of the top-level document, as computed by
  # HTTP::Cookie.schemeful_site, or nil if it is unknown.  When nil,
  # no request is considered same-site.
  attr_reader :top_level_site

  # An array of the schemeful sites of every URL in the redirect
  # chain that led to the request, in order.
  attr_reader :redirect_chain

  # :call-seq:
  #   new(method: 'GET', top_level_site:, top_level_navigation: false, redirect_chain: [])
  #
  # Creates a request context.  The `top_level_site` keyword is
  # mandatory so that a caller cannot accidentally get a permissive
  # default; pass nil explicitly to describe an unknown top-level
  # site, which makes every request cross-site.
  #
  # `top_level_site` and each entry of `redirect_chain` may be a
  # URI/URL or a schemeful site string as returned by
  # HTTP::Cookie.schemeful_site.
  def initialize(method: 'GET', top_level_site:, top_level_navigation: false, redirect_chain: [])
    @method = String(method).upcase
    @top_level_site = top_level_site && HTTP::Cookie.schemeful_site(top_level_site)
    @top_level_navigation = !!top_level_navigation
    @redirect_chain = redirect_chain.map { |uri|
      HTTP::Cookie.schemeful_site(uri)
    }.freeze
  end

  # Tests if the request is a top-level navigation.
  def top_level_navigation?
    @top_level_navigation
  end

  # Tests if the request method is safe (GET or HEAD).
  def safe_method?
    SAFE_METHODS.include?(@method)
  end

  # Tests if a request to `uri` is same-site in this context, that
  # is the schemeful site of `uri` equals the top-level site and
  # every site in the redirect chain.
  def same_site?(uri)
    site = HTTP::Cookie.schemeful_site(uri)
    site == @top_level_site &&
      @redirect_chain.all? { |redirect_site| redirect_site == site }
  end
end
