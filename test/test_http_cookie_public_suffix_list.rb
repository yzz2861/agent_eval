# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))
require 'http/cookie_jar'

module TestHTTPCookiePublicSuffixList
  InMemory = HTTP::Cookie::PublicSuffixList::InMemory

  class TestProviders < Test::Unit::TestCase
    def test_in_memory_exact_and_wildcard_rules
      rules = InMemory.new(['com', 'apps.internal', '*.svc'])

      assert_equal true,  rules.public_suffix?('com')
      assert_equal true,  rules.public_suffix?('apps.internal')
      assert_equal true,  rules.public_suffix?('web.svc')

      # a subdomain of a public suffix is registrable
      assert_equal false, rules.public_suffix?('www.apps.internal')
      # a wildcard matches exactly one label
      assert_equal false, rules.public_suffix?('a.b.svc')
      assert_equal false, rules.public_suffix?('svc')
      # unknown names are ordinary domains
      assert_equal false, rules.public_suffix?('internal')
      assert_equal false, rules.public_suffix?('example.com')
    end

    def test_in_memory_normalization
      rules = InMemory.new(['Apps.Internal.'])
      assert_equal true, rules.public_suffix?('APPS.internal.')
      assert_equal true, rules.public_suffix?('.apps.internal')
    end

    def test_in_memory_ip_addresses_are_never_public_suffixes
      rules = InMemory.new(['192.168.0.1', '::1'])
      assert_equal false, rules.public_suffix?('192.168.0.1')
      assert_equal false, rules.public_suffix?('::1')
    end

    def test_default_provider_matches_domain_name
      list = HTTP::Cookie::PublicSuffixList.default
      assert_equal true,  list.public_suffix?('com')
      assert_equal true,  list.public_suffix?('co.uk')
      assert_equal false, list.public_suffix?('example.com')
      assert_equal false, list.public_suffix?('localhost')
      assert_equal false, list.public_suffix?('127.0.0.1')
    end
  end

  class TestJarIntegration < Test::Unit::TestCase
    ORIGIN = 'http://www.apps.internal/'

    # Two tiny in-memory rule sets: under rules A "apps.internal" is
    # an ordinary registrable domain; under rules B it has been
    # designated a public suffix.
    def rules_a
      InMemory.new(%w[com internal])
    end

    def rules_b
      InMemory.new(%w[com internal apps.internal])
    end

    def test_domain_becoming_a_public_suffix
      jar = HTTP::CookieJar.new(:public_suffix_list => rules_a)

      jar.parse('session=abc; Domain=apps.internal; Path=/', ORIGIN)
      jar.parse('token=xyz; Path=/', ORIGIN)

      domain_cookie = jar.each.find { |c| c.name == 'session' }
      host_cookie   = jar.each.find { |c| c.name == 'token' }
      assert_equal true,  domain_cookie.for_domain?
      assert_equal false, host_cookie.for_domain?
      assert_equal 2, jar.cookies(ORIGIN).size

      # "apps.internal" becomes a public suffix: existing domain
      # cookies are re-adjudicated, not just new writes.
      report = jar.replace_public_suffix_list(rules_b)

      assert_equal [domain_cookie], report.removed
      assert_equal [host_cookie],   report.kept
      assert_equal :public_suffix,  report.reason_for(domain_cookie)
      assert_equal :host_only,      report.reason_for(host_cookie)
      assert_equal [host_cookie],   jar.cookies(ORIGIN)

      # the report stays queryable afterwards
      assert_equal report, jar.last_recheck
      assert_equal :public_suffix, jar.last_recheck.reason_for(domain_cookie)
      assert_equal 1, jar.rules_version
      assert_equal 1, report.rules_version

      # new domain-cookie writes for the suffix are refused
      jar.parse('session2=def; Domain=apps.internal; Path=/', ORIGIN)
      assert_nil jar.each.find { |c| c.name == 'session2' }

      # a subdomain of the new public suffix is still registrable
      jar.parse('sub=1; Domain=www.apps.internal; Path=/', ORIGIN)
      assert_not_nil jar.each.find { |c| c.name == 'sub' }
    end

    def test_new_writes_are_checked_against_the_injected_rules
      jar = HTTP::CookieJar.new(:public_suffix_list => rules_b)

      jar.parse('session=abc; Domain=apps.internal; Path=/', ORIGIN)
      assert_equal true, jar.empty?

      # host-only cookies on a public suffix host are still fine
      jar.parse('token=xyz; Path=/', ORIGIN)
      assert_equal 1, jar.cookies(ORIGIN).size
    end

    def test_default_jar_uses_domain_name_rules
      jar = HTTP::CookieJar.new
      assert_kind_of HTTP::Cookie::PublicSuffixList::DomainNameList, jar.public_suffix_list
      assert_equal 0, jar.rules_version
      assert_nil jar.last_recheck

      cookie = HTTP::Cookie.new('a', '1', :domain => 'example.com',
                                  :for_domain => true, :path => '/',
                                  :origin => 'http://www.example.com/')
      jar.add(cookie)
      assert_equal false, jar.empty?

      # a domain cookie manually forced onto a public suffix is refused
      bad = HTTP::Cookie.new('b', '2', :domain => 'com', :path => '/')
      bad.for_domain = true
      jar.add(bad)
      assert_nil jar.each.find { |c| c.name == 'b' }
    end

    def test_provider_failure_fails_closed
      failing = Object.new
      def failing.public_suffix?(_host)
        raise HTTP::Cookie::PublicSuffixList::Error, 'rules unavailable'
      end

      jar = HTTP::CookieJar.new(:public_suffix_list => rules_a)
      jar.parse('session=abc; Domain=apps.internal; Path=/', ORIGIN)
      jar.parse('token=xyz; Path=/', ORIGIN)
      domain_cookie = jar.each.find { |c| c.name == 'session' }
      host_cookie   = jar.each.find { |c| c.name == 'token' }

      # new domain-cookie writes are refused while the provider is down
      jar2 = HTTP::CookieJar.new(:public_suffix_list => failing)
      jar2.parse('session=abc; Domain=apps.internal; Path=/', ORIGIN)
      assert_equal true, jar2.empty?
      # host-only cookies do not consult the provider
      jar2.parse('token=xyz; Path=/', ORIGIN)
      assert_equal 1, jar2.each.to_a.size

      # rechecking with a failing provider never defaults to allowing
      report = jar.replace_public_suffix_list(failing)
      assert_equal :provider_error, report.reason_for(domain_cookie)
      assert_equal :host_only,     report.reason_for(host_cookie)
      assert_equal [domain_cookie], report.removed
      assert_equal [host_cookie],   jar.each.to_a
    end

    def test_invalid_provider_is_rejected
      assert_raise(ArgumentError) {
        HTTP::CookieJar.new(:public_suffix_list => Object.new)
      }
      jar = HTTP::CookieJar.new
      assert_raise(ArgumentError) {
        jar.replace_public_suffix_list(Object.new)
      }
    end

    def test_reads_see_a_consistent_rules_version_during_recheck
      jar = HTTP::CookieJar.new(:public_suffix_list => rules_a)
      jar.parse('session=abc; Domain=apps.internal; Path=/', ORIGIN)

      entered = Queue.new
      gate = Queue.new
      blocking = Object.new
      blocking.define_singleton_method(:public_suffix?) do |_host|
        entered << true
        gate.pop
        true
      end

      replacer = Thread.new { jar.replace_public_suffix_list(blocking) }
      entered.pop # the recheck is now in progress, holding the rules lock

      reader = Thread.new { jar.cookies(ORIGIN) }
      sleep 0.1
      # the reader cannot observe a half-updated jar: it is blocked
      # until the swap and the recheck have both completed
      assert_equal true, reader.alive?

      gate << true
      replacer.join(5)
      seen = reader.value
      assert_equal [], seen
      assert_equal 1, jar.rules_version
    end
  end
end
