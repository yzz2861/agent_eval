# :markup: markdown

class HTTP::CookieJar
  # This module namespaces cookie acceptance policies, which decide
  # whether a cookie offered to a jar may be stored.  A policy is a
  # stateless object whose #rejection_reason method is called with
  # the candidate cookie and the jar it is about to be added to.
  #
  # It returns nil when the cookie is acceptable, or a symbol that
  # describes the reason of rejection otherwise.
  #
  # Two policies are shipped:
  #
  # :rfc6265:: HTTP::CookieJar::AcceptPolicy::RFC6265Policy, the
  #            historical lenient behaviour and the default.
  # :browser_secure:: HTTP::CookieJar::AcceptPolicy::BrowserSecurePolicy,
  #            a stricter, browser-like policy that enforces the
  #            `__Secure-`/`__Host-` name prefix constraints and keeps
  #            insecure origins from overwriting stored Secure cookies.
  module AcceptPolicy
    class << self
      # Gets an implementation class by the name.
      def implementation(symbol)
        case symbol
        when :rfc6265, :default
          RFC6265Policy
        when :browser_secure, :secure
          BrowserSecurePolicy
        else
          raise IndexError, 'cookie acceptance policy unavailable: %s' % symbol.inspect
        end
      end
    end

    # Returns nil when +cookie+ may be added to +jar+, or a symbol
    # describing why it must be rejected.  Override this in policy
    # implementations.
    def rejection_reason(cookie, jar = nil) # :nodoc:
      nil
    end

    # The lenient policy that follows RFC 6265 without any extra
    # restrictions beyond HTTP::Cookie#acceptable?.  This is the
    # historical behaviour of HTTP::CookieJar and remains the default
    # policy.
    class RFC6265Policy
      include AcceptPolicy
    end

    # A stricter, browser-like cookie acceptance policy.
    #
    # In addition to the checks performed by the default policy, this
    # policy implements:
    #
    # 1. The `__Secure-` prefix requirements (RFC 6265bis): the cookie
    #    must be set from a secure (HTTPS) origin and carry the Secure
    #    attribute.
    # 2. The `__Host-` prefix requirements (RFC 6265bis): in addition
    #    to the `__Secure-` requirements, the cookie must not carry a
    #    Domain attribute (it is host-only) and its Path must be `/`.
    # 3. A non-prefixed cookie carrying the Secure attribute is only
    #    accepted from a secure origin.
    # 4. A cookie offered by an insecure (HTTP) origin is rejected
    #    when it would overwrite (including expire) a stored Secure
    #    cookie with the same name whose domain scope and path
    #    overlap, comparing the domain values, the host-only flags and
    #    the path prefix relationship of both records.
    #
    # Cookies with no origin set (e.g. those deserialized from a
    # saved jar) skip the origin-dependent checks; legitimate updates
    #    and deletions over HTTPS are always allowed.
    #
    # Possible rejection reasons (symbols) are:
    #
    # :secure_cookie_from_insecure_origin::
    #   A Secure cookie (without a security prefix) was set from an
    #   insecure origin.
    # :secure_prefix_insecure_origin::
    #   A `__Secure-` cookie was set from an insecure origin.
    # :secure_prefix_without_secure::
    #   A `__Secure-` cookie lacked the Secure attribute.
    # :host_prefix_insecure_origin::
    #   A `__Host-` cookie was set from an insecure origin.
    # :host_prefix_without_secure::
    #   A `__Host-` cookie lacked the Secure attribute.
    # :host_prefix_with_domain::
    #   A `__Host-` cookie carried a Domain attribute.
    # :host_prefix_path_not_root::
    #   A `__Host-` cookie had a Path other than `/`.
    # :insecure_overwrite_of_secure::
    #   An insecure origin tried to overwrite or expire a stored
    #   Secure cookie with an overlapping domain scope and path.
    class BrowserSecurePolicy
      include AcceptPolicy

      # The `__Host-` name prefix.
      HOST_PREFIX = '__Host-'

      # The `__Secure-` name prefix.
      SECURE_PREFIX = '__Secure-'

      def rejection_reason(cookie, jar = nil) # :nodoc:
        name = cookie.name
        secure_origin = secure_origin?(cookie.origin)

        if name.start_with?(HOST_PREFIX)
          unless cookie.origin.nil? || secure_origin
            return :host_prefix_insecure_origin
          end
          return :host_prefix_without_secure unless cookie.secure?
          return :host_prefix_with_domain if cookie.for_domain?
          return :host_prefix_path_not_root unless cookie.path == '/'
        elsif name.start_with?(SECURE_PREFIX)
          unless cookie.origin.nil? || secure_origin
            return :secure_prefix_insecure_origin
          end
          return :secure_prefix_without_secure unless cookie.secure?
        elsif !cookie.origin.nil? && cookie.secure? && !secure_origin
          return :secure_cookie_from_insecure_origin
        end

        # Everything below requires comparison with the records that
        # are already stored, and only insecure origins need to be
        # constrained.
        return if cookie.origin.nil? || secure_origin

        jar.store.each { |existing|
          next unless existing.name == name && existing.secure?
          if domain_scopes_overlap?(cookie, existing) &&
             paths_overlap?(cookie.path, existing.path)
            return :insecure_overwrite_of_secure
          end
        }

        nil
      end

      private

      def secure_origin?(origin)
        origin && URI::HTTPS === origin
      end

      # Tests if the domain scopes of two cookies intersect, taking
      # their host-only flags (the opposite of #for_domain) into
      # account.  A domain cookie covers its domain and all subdomains
      # while a host-only cookie covers its exact host only.
      def domain_scopes_overlap?(new_cookie, existing_cookie)
        new_domain = new_cookie.domain_name
        existing_domain = existing_cookie.domain_name
        return false unless new_domain && existing_domain

        if new_cookie.for_domain?
          if existing_cookie.for_domain?
            new_domain == existing_domain ||
              new_domain.cookie_domain?(existing_domain) ||
              existing_domain.cookie_domain?(new_domain)
          else
            existing_domain.cookie_domain?(new_domain)
          end
        else
          if existing_cookie.for_domain?
            new_domain.cookie_domain?(existing_domain)
          else
            new_domain == existing_domain
          end
        end
      end

      # Tests if two cookie paths share any request path, i.e. one is
      # a prefix directory of the other or they are identical.
      def paths_overlap?(new_path, existing_path)
        HTTP::Cookie.path_match?(existing_path, new_path) ||
          HTTP::Cookie.path_match?(new_path, existing_path)
      end
    end
  end
end
