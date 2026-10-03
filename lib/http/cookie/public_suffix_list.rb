# :markup: markdown
# frozen_string_literal: true
# Load the parent class unless it is fully defined already.  A plain
# defined?(HTTP::Cookie) check is not enough because the constant may
# just be an autoload placeholder.
require 'http/cookie' unless defined?(HTTP::Cookie::MAX_LENGTH)

class HTTP::Cookie
  # Pluggable public suffix rule providers for HTTP::CookieJar.
  #
  # A public suffix list decides which domain names are "public
  # suffixes" (e.g. +com+, +co.uk+, +github.io+) that a domain cookie
  # must never be scoped to.  The list is updated over time, and
  # private deployments often need extra internal rules, so
  # HTTP::CookieJar accepts an injectable provider instead of
  # hard-coding one.
  #
  # A provider is any object that responds to:
  #
  #     public_suffix?(hostname) -> true or false
  #
  # It may raise HTTP::Cookie::PublicSuffixList::Error (or any
  # StandardError) to signal that the rules are unavailable.  Callers
  # treat a lookup failure as "public suffix" (fail closed): a domain
  # cookie is never allowed by default when the rules cannot be
  # consulted.
  module PublicSuffixList
    # Raised by rule providers when the rule set is unavailable.
    class Error < StandardError; end

    # Returns the default provider, which derives public suffixes
    # from the +domain_name+ gem, the same data HTTP::Cookie has
    # always used.
    def self.default
      @default ||= DomainNameList.new
    end

    # The default provider, backed by DomainName.
    class DomainNameList
      def public_suffix?(hostname)
        domain_name = hostname.is_a?(DomainName) ? hostname : DomainName.new(hostname.to_s)
        return false if domain_name.ipaddr?
        domain_name.domain.nil?
      end
    end

    # A tiny in-memory rule set, mainly useful for tests and private
    # deployments with a handful of internal suffixes.
    #
    #     rules = HTTP::Cookie::PublicSuffixList::InMemory.new(['internal', '*.svc'])
    #     rules.public_suffix?('internal')      # => true
    #     rules.public_suffix?('apps.internal') # => false
    #     rules.public_suffix?('web.svc')       # => true
    #
    # Each rule is either an exact host name or a wildcard of the
    # form +*.example+, which matches exactly one label.  IP
    # addresses are never public suffixes.
    class InMemory
      def initialize(suffixes = [])
        @exact = {}
        @wildcards = {}
        suffixes.each { |rule|
          rule = self.class.normalize(rule)
          if rule.start_with?('*.')
            @wildcards[rule[2..-1]] = true
          else
            @exact[rule] = true
          end
        }
      end

      def public_suffix?(hostname)
        host = self.class.normalize(hostname)
        return false if host.empty? || self.class.ip_address?(host)
        return true if @exact.key?(host)
        if (dot = host.index('.'))
          @wildcards.key?(host[(dot + 1)..-1])
        else
          false
        end
      end

      def self.normalize(hostname)
        hostname.to_s.downcase.sub(/\A\.+/, '').sub(/\.+\z/, '')
      end

      def self.ip_address?(host)
        host.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/) || host.include?(':')
      end
    end
  end
end
