# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))

module TestHTTPCookieJar
  # Tests that run against every store backend.  The policy logic
  # itself is store-agnostic, but it iterates stored records, so the
  # key scenarios are exercised for each backend.
  module AcceptPolicyCommonTests
    SECURE_HOST = 'https://example.com/'
    INSECURE_HOST = 'http://example.com/'
    EXPIRED = 'Thu, 01 Jan 1970 00:00:00 GMT'

    def new_jar(options = nil)
      rejected = []
      jar = HTTP::CookieJar.new(store_options.merge({
        :accept_policy => :browser_secure,
        :on_reject => lambda { |cookie, reason|
          rejected << [cookie.name, reason]
        },
      }).merge(options || {}))
      [jar, rejected]
    end

    def store_options
      {}
    end

    def test_explicit_rfc6265_policy
      jar = HTTP::CookieJar.new(:accept_policy => :rfc6265)
      assert_kind_of HTTP::CookieJar::AcceptPolicy::RFC6265Policy, jar.accept_policy
    end

    def test_browser_secure_policy_instance
      jar = HTTP::CookieJar.new(:accept_policy => :browser_secure)
      assert_kind_of HTTP::CookieJar::AcceptPolicy::BrowserSecurePolicy, jar.accept_policy
    end

    def test_policy_class_and_instance
      policy_class = HTTP::CookieJar::AcceptPolicy::BrowserSecurePolicy
      jar = HTTP::CookieJar.new(:accept_policy => policy_class)
      assert_kind_of policy_class, jar.accept_policy

      custom = Object.new
      def custom.rejection_reason(cookie, jar); :custom; end
      jar2 = HTTP::CookieJar.new(:accept_policy => custom)
      assert_same custom, jar2.accept_policy
    end

    def test_unknown_policy_symbol_raises
      assert_raise_with_message(ArgumentError,
        /cookie acceptance policy unavailable: :nope/) {
        HTTP::CookieJar.new(:accept_policy => :nope)
      }
    end

    def test_secure_prefix_from_insecure_origin
      jar, rejected = new_jar
      added = jar.parse('__Secure-sid=v1', INSECURE_HOST)
      assert_equal [], added
      assert_equal [["__Secure-sid", :secure_prefix_insecure_origin]], rejected
      assert jar.empty?
    end

    def test_secure_prefix_without_secure_attribute
      jar, rejected = new_jar
      jar.parse('__Secure-sid=v1', SECURE_HOST)
      assert_equal [["__Secure-sid", :secure_prefix_without_secure]], rejected
      assert jar.empty?
    end

    def test_secure_prefix_accepted
      jar, rejected = new_jar
      jar.parse('__Secure-sid=v1; Secure; Path=/', SECURE_HOST)
      assert_equal [], rejected
      assert_equal 1, jar.cookies(SECURE_HOST).size
    end

    def test_host_prefix_from_insecure_origin
      jar, rejected = new_jar
      jar.parse('__Host-sid=v1; Secure; Path=/', INSECURE_HOST)
      assert_equal [["__Host-sid", :host_prefix_insecure_origin]], rejected
      assert jar.empty?
    end

    def test_host_prefix_without_secure_attribute
      jar, rejected = new_jar
      jar.parse('__Host-sid=v1; Path=/', SECURE_HOST)
      assert_equal [["__Host-sid", :host_prefix_without_secure]], rejected
      assert jar.empty?
    end

    def test_host_prefix_with_domain_attribute
      jar, rejected = new_jar
      jar.parse('__Host-sid=v1; Secure; Path=/; Domain=example.com', SECURE_HOST)
      assert_equal [["__Host-sid", :host_prefix_with_domain]], rejected
      assert jar.empty?
    end

    def test_host_prefix_with_non_root_path
      jar, rejected = new_jar
      jar.parse('__Host-sid=v1; Secure; Path=/admin', SECURE_HOST)
      assert_equal [["__Host-sid", :host_prefix_path_not_root]], rejected
      assert jar.empty?
    end

    def test_host_prefix_accepted_when_host_only_root_path
      jar, rejected = new_jar
      jar.parse('__Host-sid=v1; Secure; Path=/', SECURE_HOST)
      assert_equal [], rejected
      cookies = jar.cookies(SECURE_HOST)
      assert_equal 1, cookies.size
      cookie = cookies.first
      assert cookie.secure?
      assert_equal false, cookie.for_domain?
      assert_equal '/', cookie.path
    end

    def test_non_prefixed_secure_cookie_from_insecure_origin
      jar, rejected = new_jar
      jar.parse('sid=v1; Secure; Path=/', INSECURE_HOST)
      assert_equal [["sid", :secure_cookie_from_insecure_origin]], rejected
      assert jar.empty?
    end

    def test_insecure_same_name_overwrite_of_secure_is_blocked
      jar, rejected = new_jar
      jar.parse('sid=v1; Path=/; Secure', SECURE_HOST)
      added = jar.parse('sid=v2; Path=/', INSECURE_HOST)
      assert_equal [], added
      assert_equal [["sid", :insecure_overwrite_of_secure]], rejected
      assert_equal ['v1'], jar.cookies(SECURE_HOST).map(&:value)
    end

    def test_insecure_expiration_of_secure_is_blocked
      jar, rejected = new_jar
      jar.parse("sid=v1; Path=/; Secure", SECURE_HOST)
      jar.parse("sid=; Path=/; Expires=#{EXPIRED}", INSECURE_HOST)
      assert_equal [["sid", :insecure_overwrite_of_secure]], rejected
      assert_equal ['v1'], jar.cookies(SECURE_HOST).map(&:value)
    end

    def test_secure_expiration_over_https_is_allowed
      jar, rejected = new_jar
      jar.parse('sid=v1; Path=/; Secure', SECURE_HOST)
      jar.parse("sid=; Path=/; Expires=#{EXPIRED}", SECURE_HOST)
      assert_equal [], rejected
      assert_equal [], jar.cookies(SECURE_HOST)
    end

    def test_https_update_replaces_old_value
      jar, rejected = new_jar
      jar.parse('sid=v1; Path=/; Secure', SECURE_HOST)
      jar.parse('sid=v2; Path=/; Secure', SECURE_HOST)
      assert_equal [], rejected
      assert_equal ['v2'], jar.cookies(SECURE_HOST).map(&:value)
      assert_equal 1, jar.to_a.size
    end

    def test_path_overlap_blocks_insecure_overwrite
      jar, rejected = new_jar
      jar.parse('sid=v1; Path=/admin; Secure', SECURE_HOST)
      # The new path is a parent of the stored one, so it overlaps.
      jar.parse('sid=v2; Path=/', INSECURE_HOST)
      assert_equal [["sid", :insecure_overwrite_of_secure]], rejected
      assert_equal ['v1'], jar.cookies('https://example.com/admin').map(&:value)
    end

    def test_non_overlapping_path_does_not_block
      jar, rejected = new_jar
      jar.parse('sid=v1; Path=/a; Secure', SECURE_HOST)
      jar.parse('sid=v2; Path=/b', 'http://example.com/b')
      assert_equal [], rejected
      assert_equal ['v2'], jar.cookies('http://example.com/b').map(&:value)
      assert_equal ['v1'], jar.cookies('https://example.com/a').map(&:value)
    end

    def test_domain_cookie_from_insecure_origin_blocks_host_only_secure
      jar, rejected = new_jar
      # Host-only Secure cookie on a subdomain.
      jar.parse('sid=v1; Path=/; Secure', 'https://www.example.com/')
      # A Domain cookie from the parent domain over HTTP covers the
      # host-only cookie's host.
      jar.parse('sid=v2; Path=/; Domain=example.com', 'http://example.com/')
      assert_equal [["sid", :insecure_overwrite_of_secure]], rejected
      assert_equal ['v1'], jar.cookies('https://www.example.com/').map(&:value)
    end

    def test_unrelated_domain_does_not_block
      jar, rejected = new_jar
      jar.parse('sid=v1; Path=/; Secure', 'https://secure.example.net/')
      added = jar.parse('sid=v2; Path=/', 'http://other.example.com/')
      assert_equal 1, added.size
      assert_equal [], rejected
    end

    def test_add_directly_also_enforces_policy
      jar, rejected = new_jar
      cookie = HTTP::Cookie.parse('__Secure-sid=v1', INSECURE_HOST).first
      jar.add(cookie)
      assert_equal [["__Secure-sid", :secure_prefix_insecure_origin]], rejected
      assert jar.empty?
    end

    def test_parse_block_filter_still_enforces_policy
      jar, rejected = new_jar
      jar.parse('sid=v1; Path=/; Secure', SECURE_HOST)
      added = jar.parse('sid=v2; Path=/', INSECURE_HOST) { |cookie|
        true
      }
      assert_equal [], added
      assert_equal ['v1'], jar.cookies(SECURE_HOST).map(&:value)
    end

    def test_lenient_policy_allows_insecure_overwrite
      jar = HTTP::CookieJar.new
      jar.parse('sid=v1; Path=/; Secure', SECURE_HOST)
      jar.parse('sid=v2; Path=/', INSECURE_HOST)
      assert_equal ['v2'], jar.cookies(SECURE_HOST).map(&:value)
    end

    def test_interleaved_http_https_responses
      jar, rejected = new_jar

      # 1. HTTPS establishes a Secure session cookie.
      jar.parse('session=secure1; Path=/; Secure', SECURE_HOST)
      # 2. HTTP tries to shadow it with the same name and path.
      jar.parse('session=http1; Path=/', INSECURE_HOST)
      # 3. HTTP may set its own unrelated, non-overlapping cookie.
      jar.parse('cart=1; Path=/shop', 'http://example.com/shop')
      # 4. HTTPS rotates the Secure cookie to a new value.
      jar.parse('session=secure2; Path=/; Secure', SECURE_HOST)
      # 5. HTTP attempts to expire the Secure cookie.
      jar.parse("session=; Path=/; Expires=#{EXPIRED}", INSECURE_HOST)
      # 6. HTTPS sets __Secure- and __Host- cookies; malformed ones
      #    interleaved on HTTP are dropped.
      jar.parse('__Secure-csrf=t; Secure; Path=/', SECURE_HOST)
      jar.parse('__Secure-csrf=fake; Path=/', INSECURE_HOST)
      jar.parse('__Host-uid=42; Secure; Path=/', SECURE_HOST)
      jar.parse('__Host-uid=43; Secure; Path=/; Domain=example.com', SECURE_HOST)
      # 7. HTTP expiry of the __Secure- cookie is blocked by the
      #    prefix origin check even when Secure is attached.
      jar.parse("__Secure-csrf=; Path=/; Secure; Expires=#{EXPIRED}", INSECURE_HOST)
      # 8. HTTPS finally expires the Secure session cookie legally.
      jar.parse("session=; Path=/; Expires=#{EXPIRED}", SECURE_HOST)

      assert_equal [
        ["session", :insecure_overwrite_of_secure],
        ["session", :insecure_overwrite_of_secure],
        ["__Secure-csrf", :secure_prefix_insecure_origin],
        ["__Host-uid", :host_prefix_with_domain],
        ["__Secure-csrf", :secure_prefix_insecure_origin],
      ], rejected

      final = jar.cookies(SECURE_HOST).map { |cookie|
        [cookie.name, cookie.value, cookie.secure?]
      }
      assert_equal [
        ['__Host-uid', '42', true],
        ['__Secure-csrf', 't', true],
      ], final

      # The plain HTTP cookie lives independently on its own path.
      assert_equal [['cart', '1']],
        jar.cookies('http://example.com/shop').map { |cookie|
          [cookie.name, cookie.value]
        }
    end
  end

  class AcceptPolicyWithHashStore < Test::Unit::TestCase
    include AcceptPolicyCommonTests

    def test_default_policy_is_rfc6265
      jar = HTTP::CookieJar.new
      assert_kind_of HTTP::CookieJar::AcceptPolicy::RFC6265Policy, jar.accept_policy
    end
  end

  class AcceptPolicyWithMozillaStore < Test::Unit::TestCase
    include AcceptPolicyCommonTests

    def store_options
      { :store => :mozilla, :filename => ':memory:' }
    end
  end
end
