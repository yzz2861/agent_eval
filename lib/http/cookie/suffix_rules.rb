# :markup: markdown
require 'http/cookie'

class HTTP::Cookie
  # Pluggable public-suffix rule providers.
  #
  # A suffix rule provider is any object that responds to
  # #public_suffix?(hostname) and returns whether the given host name
  # itself is a public suffix (a.k.a. eTLD).  Cookies with a Domain
  # attribute must not target a public suffix (RFC 6265 5.3).
  #
  # Public suffix lists are updated over time, and test environments
  # often need to declare internal domains as effective public
  # suffixes, so HTTP::CookieJar accepts an injected provider via the
  # :suffix_rules option and HTTP::CookieJar#replace_suffix_rules.
  #
  # A provider may raise an error when its rules are unavailable.
  # Callers must not treat a provider failure as "not a public
  # suffix"; HTTP::CookieJar fails closed in that case.
  module SuffixRules
    # An in-memory suffix rule provider built from a list of rules.
    #
    # A host name is a public suffix when it equals a rule, following
    # the matching semantics of the Public Suffix List; names below a
    # rule are ordinary registrable domains:
    #
    #     rules = HTTP::Cookie::SuffixRules::List.new(%w[com appspot.com])
    #     rules.public_suffix?('com')             # => true
    #     rules.public_suffix?('appspot.com')     # => true
    #     rules.public_suffix?('foo.appspot.com') # => false
    #     rules.public_suffix?('example.com')     # => false
    class List
      # The normalized rules this provider was built from.
      attr_reader :rules

      def initialize(rules)
        @rules = rules.map { |rule|
          rule.to_s.downcase.sub(/\A\.+/, '')
        }.reject(&:empty?).uniq.freeze
      end

      def public_suffix?(host)
        @rules.include?(host.to_s.downcase)
      end
    end

    # The default provider, backed by the Public Suffix List bundled
    # with the domain_name gem.
    class DomainNameAdapter
      def public_suffix?(host)
        domain_name = DomainName.new(host)
        domain_name.domain.nil? && !domain_name.ipaddr?
      end
    end

    # Returns the process-wide default provider.
    def self.default
      @default ||= DomainNameAdapter.new
    end
  end
end
