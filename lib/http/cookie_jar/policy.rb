# :markup: markdown
# frozen_string_literal: true

# Reception policies consulted by HTTP::CookieJar when a cookie is
# about to be stored or deleted.
#
# A policy is any object that responds to the following two methods
# and returns nil when the operation is allowed, or a reason symbol
# when it is rejected:
#
# - #reject_add_reason(jar, cookie)
# - #reject_delete_reason(jar, cookie)
#
# Two built-in policies are provided:
#
# Policy::Lenient::
#     The historical, permissive policy (the default).  Any cookie
#     that passes HTTP::Cookie#acceptable? is stored, and any cookie
#     can be deleted.
#
# Policy::BrowserSecure::
#     A stricter, browser-style policy that enforces the
#     `__Secure-`/`__Host-` name prefix constraints of RFC 6265bis
#     and prevents cookies received from a non-secure origin from
#     shadowing (i.e. overwriting or expiring) an already stored
#     Secure cookie with the same name and an overlapping domain
#     and path.
class HTTP::CookieJar
  module Policy
    class << self
      # Returns a built-in policy object for a symbol:
#
      # - `:lenient` (default) -> Policy::Lenient
      # - `:browser` or `:browser_secure` -> Policy::BrowserSecure
      #
      # Any other object is returned as-is if it quacks like a
      # policy (responds to #reject_add_reason).  IndexError is
      # raised for an unknown symbol, and TypeError for anything
      # else.
      def implementation(value)
        case value
        when :lenient
          Lenient
        when :browser, :browser_secure
          BrowserSecure
        when Symbol
          raise IndexError, 'cookie reception policy unavailable: %s' % value.inspect
        else
          if value.respond_to?(:reject_add_reason)
            value
          else
            raise TypeError, 'invalid cookie reception policy: %s' % value.inspect
          end
        end
      end

      # Returns a human-readable description of a reason symbol.
      def reason_message(reason)
        REASON_MESSAGES.fetch(reason, reason.to_s)
      end
    end

    # Helpers shared by the built-in policies.
    module Common
      module_function

      # Tests if the origin of the cookie is a secure (HTTPS) one.
      # A cookie without an origin is treated as insecure.
      def secure_origin?(cookie)
        URI::HTTPS === cookie.origin
      end

      # Tests if the scopes (domain plus the host-only flag) of two
      # cookies overlap, i.e. if a host could accept both cookies.
      # Host-only cookies only match their exact host, while domain
      # cookies also cover subdomains.
      def domains_overlap?(cookie1, cookie2)
        return false if cookie1.domain.nil? || cookie2.domain.nil?
        host1 = DomainName.new(cookie1.domain)
        host2 = DomainName.new(cookie2.domain)
        return true if host1 == host2
        if cookie1.for_domain? && cookie2.for_domain?
          host1.cookie_domain?(cookie2.domain_name) ||
            host2.cookie_domain?(cookie1.domain_name)
        elsif cookie1.for_domain?
          host2.cookie_domain?(cookie1.domain_name)
        elsif cookie2.for_domain?
          host1.cookie_domain?(cookie2.domain_name)
        else
          false
        end
      end

      # Tests if either of the two paths matches the other, i.e. the
      # two cookies can be sent together to some URL.
      def paths_overlap?(cookie1, cookie2)
        HTTP::Cookie.path_match?(cookie1.path, cookie2.path) ||
          HTTP::Cookie.path_match?(cookie2.path, cookie1.path)
      end
    end

    # The historical, permissive reception policy.
    module Lenient
      extend Common

      # Always returns nil; every acceptable cookie is stored.
      def self.reject_add_reason(_jar, _cookie)
        nil
      end

      # Always returns nil; every cookie can be deleted.
      def self.reject_delete_reason(_jar, _cookie)
        nil
      end
    end

    # A browser-style secure reception policy.
    #
    # It performs two kinds of checks:
    #
    # 1. The `__Secure-` and `__Host-` name prefix constraints of
    #    RFC 6265bis section 4.1.3 are enforced, including that such
    #    a cookie is received from a secure origin.
    #
    # 2. A cookie received from a non-secure (non-HTTPS) origin is
    #    rejected when an existing Secure cookie has the same name
    #    and an overlapping domain (taking the host-only flag into
    #    account) and path.  This closes the insecure-fallback
    #    (cookie shadowing) attack and applies to expiring cookies
    #    as well, so that an HTTP response cannot delete a Secure
    #    cookie.  A legitimate update sent over HTTPS is still
    #    accepted and replaces the old value.
    module BrowserSecure
      extend Common

      # The `__Host-` name prefix.
      HOST_PREFIX = '__Host-'

      # The `__Secure-` name prefix.
      SECURE_PREFIX = '__Secure-'

      # Tests if storing +cookie+ in +jar+ should be rejected, and
      # returns a reason symbol or nil.
      def self.reject_add_reason(jar, cookie)
        prefix_rejection(cookie) || shadow_rejection(jar, cookie)
      end

      # Tests if deleting +cookie+ from +jar+ should be rejected.
      # Expiration of a Secure cookie over an insecure channel is
      # the same shadowing attack as an overwrite, so the exact same
      # checks as for #reject_add_reason apply.
      class << self
        alias reject_delete_reason reject_add_reason
      end

      # :section: Internal helpers

      def self.prefix_rejection(cookie)
        name = cookie.name
        if name.start_with?(HOST_PREFIX)
          if !secure_origin?(cookie)
            :host_prefix_insecure_origin
          elsif !cookie.secure?
            :host_prefix_not_secure
          elsif cookie.for_domain?
            :host_prefix_with_domain
          elsif cookie.path != '/'
            :host_prefix_nonroot_path
          end
        elsif name.start_with?(SECURE_PREFIX)
          if !secure_origin?(cookie)
            :secure_prefix_insecure_origin
          elsif !cookie.secure?
            :secure_prefix_not_secure
          end
        end
      end

      def self.shadow_rejection(jar, cookie)
        return nil if secure_origin?(cookie)
        jar.store.each { |existing|
          next unless existing.secure?
          next unless existing.name == cookie.name
          next unless domains_overlap?(existing, cookie)
          next unless paths_overlap?(existing, cookie)
          return :insecure_shadow_of_secure
        }
        nil
      end
      private_class_method :prefix_rejection, :shadow_rejection
    end

    REASON_MESSAGES = {
      :secure_prefix_not_secure =>
        'a cookie with the "__Secure-" name prefix must carry the "Secure" attribute',
      :secure_prefix_insecure_origin =>
        'a cookie with the "__Secure-" name prefix must be set from a secure (HTTPS) origin',
      :host_prefix_not_secure =>
        'a cookie with the "__Host-" name prefix must carry the "Secure" attribute',
      :host_prefix_insecure_origin =>
        'a cookie with the "__Host-" name prefix must be set from a secure (HTTPS) origin',
      :host_prefix_with_domain =>
        'a cookie with the "__Host-" name prefix must not carry a "Domain" attribute',
      :host_prefix_nonroot_path =>
        'a cookie with the "__Host-" name prefix must have "Path=/"',
      :insecure_shadow_of_secure =>
        'a cookie from a non-secure origin must not shadow an existing Secure cookie with the same name and an overlapping domain and path',
    }.freeze
  end
end
