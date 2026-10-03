# frozen_string_literal: false
require File.expand_path('helper', File.dirname(__FILE__))

module TestHTTPCookieJarPolicy
  Policy = HTTP::CookieJar::Policy
  BrowserSecure = Policy::BrowserSecure

  EXPIRES_PAST = 'Thu, 01 Jan 1970 00:00:00 GMT'

  class TestLogger
    attr_reader :messages

    def initialize
      @messages = []
    end

    def warn(message)
      @messages << message
    end
  end

  module CommonPolicyTests
    def policy_store_options
      { :store => :hash }
    end

    def new_jar(store_options = nil)
      HTTP::CookieJar.new(policy_store_options.merge(
        :policy => :browser
      ).merge(store_options || {}))
    end

    def mozilla_store?
      policy_store_options[:store] == :mozilla
    end

    def reject_reason(jar, set_cookie, origin)
      cookie, = HTTP::Cookie.parse(set_cookie, origin)
      BrowserSecure.reject_add_reason(jar, cookie)
    end

    def cookie_pairs(jar, uri)
      jar.cookies(uri).map { |cookie| [cookie.name, cookie.value] }
    end

    def test_default_policy_is_lenient
      jar = HTTP::CookieJar.new
      assert_same Policy::Lenient, jar.policy
    end

    def test_browser_policy_aliases
      assert_same BrowserSecure, HTTP::CookieJar.new(:policy => :browser).policy
      assert_same BrowserSecure,
        HTTP::CookieJar.new(:policy => :browser_secure).policy
    end

    def test_unknown_policy_is_an_argument_error
      assert_raise(ArgumentError) {
        HTTP::CookieJar.new(:policy => :unknown)
      }
    end

    def test_custom_policy_object
      custom = Object.new
      def custom.reject_add_reason(_jar, _cookie); nil end
      def custom.reject_delete_reason(_jar, _cookie); :nope end
      jar = HTTP::CookieJar.new(:policy => custom)
      assert_same custom, jar.policy
    end

    def test_clone_keeps_the_policy
      if mozilla_store?
        assert_raise(TypeError) { new_jar.clone }
      else
        jar = new_jar
        cloned = jar.clone
        assert_same BrowserSecure, cloned.policy
        assert_not_same jar.store, cloned.store
      end
    end

    def test_secure_prefix_requires_secure_origin
      jar = new_jar
      assert_equal :secure_prefix_insecure_origin,
        reject_reason(jar, '__Secure-SID=evil; Path=/',
                      'http://example.com/')
      assert_nil reject_reason(
        jar, '__Secure-SID=ok; Path=/; Secure', 'https://example.com/')
    end

    def test_secure_prefix_requires_secure_attribute
      jar = new_jar
      assert_equal :secure_prefix_not_secure,
        reject_reason(jar, '__Secure-SID=evil; Path=/',
                      'https://example.com/')
    end

    def test_secure_prefix_cookie_from_http_is_not_stored
      jar = new_jar
      added = jar.parse('__Secure-SID=evil; Path=/',
                        'http://example.com/')
      assert_equal [], added
      assert jar.empty?
    end

    def test_host_prefix_requirements
      jar = new_jar

      assert_nil reject_reason(
        jar, '__Host-SID=ok; Path=/; Secure', 'https://example.com/')

      assert_equal :host_prefix_insecure_origin,
        reject_reason(jar, '__Host-SID=evil; Path=/; Secure',
                      'http://example.com/')
      assert_equal :host_prefix_not_secure,
        reject_reason(jar, '__Host-SID=evil; Path=/',
                      'https://example.com/')
      assert_equal :host_prefix_with_domain,
        reject_reason(jar,
                      '__Host-SID=evil; Path=/; Secure; Domain=example.com',
                      'https://example.com/')
      assert_equal :host_prefix_nonroot_path,
        reject_reason(jar, '__Host-SID=evil; Path=/login; Secure',
                      'https://example.com/')
    end

    def test_host_prefix_with_nonroot_default_path
      jar = new_jar
      assert_equal :host_prefix_nonroot_path,
        reject_reason(jar, '__Host-SID=evil; Secure',
                      'https://example.com/login/foo')
    end

    def test_http_cannot_overwrite_secure_cookie_with_same_name
      jar = new_jar
      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')

      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/', 'http://example.com/')

      jar.parse('SID=evil; Path=/', 'http://example.com/')
      assert_equal [['SID', 'secure']],
        cookie_pairs(jar, 'https://example.com/')
    end

    def test_http_cannot_expire_secure_cookie
      jar = new_jar
      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')

      jar.parse("SID=; Path=/; Expires=#{EXPIRES_PAST}",
                'http://example.com/')
      assert_equal [['SID', 'secure']],
        cookie_pairs(jar, 'https://example.com/')

      expiring, = HTTP::Cookie.parse(
        "SID=; Path=/; Expires=#{EXPIRES_PAST}",
        'http://example.com/')
      assert_equal :insecure_shadow_of_secure,
        BrowserSecure.reject_delete_reason(jar, expiring)
      jar.delete(expiring)
      assert_equal [['SID', 'secure']],
        cookie_pairs(jar, 'https://example.com/')
    end

    def test_https_can_replace_and_expire_secure_cookie
      jar = new_jar
      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')

      jar.parse('SID=updated; Path=/; Secure',
                'https://example.com/')
      assert_equal [['SID', 'updated']],
        cookie_pairs(jar, 'https://example.com/')

      jar.parse("SID=; Path=/; Secure; Expires=#{EXPIRES_PAST}",
                'https://example.com/')
      assert_equal [], jar.to_a
    end

    def test_path_overlap_is_considered
      jar = new_jar
      jar.parse('SID=secure; Path=/admin; Secure',
                'https://example.com/admin')

      assert_nil reject_reason(jar, 'SID=evil; Path=/other',
                               'http://example.com/other')

      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/admin/x',
                      'http://example.com/admin/x')
      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/',
                      'http://example.com/')
    end

    def test_disjoint_path_http_cookie_coexists
      jar = new_jar
      jar.parse('SID=secure; Path=/admin; Secure',
                'https://example.com/admin')
      jar.parse('SID=plain; Path=/other',
                'http://example.com/other')

      assert_equal [['SID', 'plain']],
        cookie_pairs(jar, 'http://example.com/other')
      assert_equal [['SID', 'secure']],
        cookie_pairs(jar, 'https://example.com/admin/index')
    end

    def test_host_only_flag_is_considered
      jar = new_jar
      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')

      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/; Domain=example.com',
                      'http://www.example.com/')

      assert_nil reject_reason(jar, 'SID=evil; Path=/',
                               'http://www.example.net/')
    end

    def test_domain_cookie_is_shadowed_on_subdomains
      jar = new_jar
      jar.parse('SID=secure; Path=/; Secure; Domain=example.com',
                'https://example.com/')

      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/',
                      'http://sub.example.com/')
      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/login',
                      'http://sub.example.com/login')
    end

    def test_host_only_cookies_do_not_cross_hosts
      jar = new_jar
      jar.parse('SID=secure; Path=/; Secure',
                'https://www.example.com/')

      assert_nil reject_reason(jar, 'SID=evil; Path=/',
                               'http://mail.example.com/')
    end

    def test_shadow_check_is_case_insensitive_on_domains
      jar = new_jar
      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')

      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/',
                      'http://EXAMPLE.com/')
    end

    def test_only_secure_cookies_are_protected
      jar = new_jar
      jar.parse('SID=plain; Path=/', 'http://example.com/')

      jar.parse('SID=over; Path=/', 'http://example.com/')
      assert_equal [['SID', 'over']],
        cookie_pairs(jar, 'http://example.com/')

      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')
      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'SID=evil; Path=/', 'http://example.com/')
    end

    def test_interleaved_http_and_https_responses
      jar = new_jar

      # 1) Secure cookies are established over HTTPS.
      assert_equal %w[SID __Host-Token], jar.parse(
        'SID=v1; Path=/; Secure, __Host-Token=t1; Path=/; Secure',
        'https://example.com/').map(&:name)

      # 2) A plain HTTP response tries to shadow them in various ways
      # and also sets an unrelated cookie.
      added = jar.parse(
        "SID=stolen; Path=/, " \
        "__Host-Token=t2; Path=/; Secure, " \
        "SID=; Path=/; Expires=#{EXPIRES_PAST}, " \
        "Other=fine; Path=/",
        'http://example.com/')

      assert_equal ['Other'], added.map(&:name)
      assert_equal [%w[Other fine], %w[SID v1], %w[__Host-Token t1]].sort,
        cookie_pairs(jar, 'https://example.com/').sort
      assert_equal %w[Other],
        jar.cookies('http://example.com/').map(&:name)

      # 3) A Secure domain cookie is protected on its subdomains,
      # while the host-only SID is not visible on another host.
      jar.parse('CSRF=c; Path=/; Secure; Domain=example.com',
                'https://example.com/')
      assert_equal :insecure_shadow_of_secure,
        reject_reason(jar, 'CSRF=x; Path=/',
                      'http://api.example.com/')
      assert_nil reject_reason(jar, 'SID=x; Path=/',
                               'http://api.example.com/')
      jar.parse('CSRF=x; Path=/', 'http://api.example.com/')
      assert_equal 'c', jar.cookies('https://api.example.com/').find {
        |cookie| cookie.name == 'CSRF'
      }.value

      # 4) A valid HTTPS response replaces values and may delete.
      jar.parse('SID=v2; Path=/; Secure', 'https://example.com/')
      jar.parse("__Host-Token=; Path=/; Secure; Expires=#{EXPIRES_PAST}",
                'https://example.com/')
      final = cookie_pairs(jar, 'https://example.com/').to_h
      assert_equal 'v2', final['SID']
      assert_not_include final.keys, '__Host-Token'
    end

    def test_rejection_is_logged
      logger = TestLogger.new
      jar = new_jar(:logger => logger)
      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')
      jar.parse('SID=evil; Path=/', 'http://example.com/')

      assert_equal 1, logger.messages.size
      assert_match(/SID/, logger.messages.first)
      assert_match(/Secure cookie/, logger.messages.first)
    end

    def test_lenient_policy_keeps_the_legacy_behavior
      logger = TestLogger.new
      jar = HTTP::CookieJar.new(:policy => :lenient, :logger => logger)

      jar.parse('SID=plain; Secure', 'http://example.com/')
      assert_equal 1, jar.cookies('https://example.com/').size

      jar.parse('SID=secure; Path=/; Secure',
                'https://example.com/')
      jar.parse('SID=evil; Path=/', 'http://example.com/')
      assert_equal [['SID', 'evil']],
        cookie_pairs(jar, 'https://example.com/')
      jar.parse("SID=; Path=/; Expires=#{EXPIRES_PAST}",
                'http://example.com/')
      assert_equal [], jar.to_a
      assert_equal [], logger.messages
    end
  end

  class WithHashStore < Test::Unit::TestCase
    include CommonPolicyTests
  end

  class WithMozillaStore < Test::Unit::TestCase
    include CommonPolicyTests

    def policy_store_options
      { :store => :mozilla, :filename => ':memory:' }
    end
  end if begin
    require 'sqlite3'
    true
  rescue LoadError
    false
  end
end
