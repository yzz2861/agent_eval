# frozen_string_literal: true
require File.expand_path('helper.rb', File.dirname(__FILE__))
require 'http/cookie_jar'

class TestSuffixRules < Test::Unit::TestCase
  List = HTTP::Cookie::SuffixRules::List

  # Two tiny in-memory rule sets.  Under RULES_V1, example.com is an
  # ordinary registrable domain; under RULES_V2 it has become a
  # public suffix (e.g. the list was updated, or a test environment
  # declared an internal domain as an effective TLD).
  RULES_V1 = List.new(%w[com])
  RULES_V2 = List.new(%w[com example.com])

  ORIGIN = 'http://www.example.com/'

  # A provider whose rules are unavailable.
  class BrokenRules
    def public_suffix?(host)
      raise 'suffix rules unavailable'
    end
  end

  def test_list_provider_semantics
    rules = List.new(%w[com appspot.com])
    assert_equal true,  rules.public_suffix?('com')
    assert_equal true,  rules.public_suffix?('appspot.com')
    assert_equal true,  rules.public_suffix?('APPSPOT.COM')
    assert_equal false, rules.public_suffix?('example.com')
    assert_equal false, rules.public_suffix?('foo.appspot.com')
    assert_equal false, rules.public_suffix?('www.example.com')
  end

  def test_default_provider
    rules = HTTP::Cookie::SuffixRules.default
    assert_equal true,  rules.public_suffix?('com')
    assert_equal true,  rules.public_suffix?('co.uk')
    assert_equal false, rules.public_suffix?('example.com')
    assert_equal false, rules.public_suffix?('127.0.0.1')
  end

  def test_default_provider_is_used_when_none_injected
    jar = HTTP::CookieJar.new
    assert_equal HTTP::Cookie::SuffixRules.default, jar.suffix_rules
    assert_equal 0, jar.suffix_rules_version
  end

  # The whole life cycle of a domain going from an ordinary domain to
  # a public suffix, driven by swapping the two tiny rule sets.
  def test_domain_becoming_public_suffix
    jar = HTTP::CookieJar.new(:suffix_rules => RULES_V1)

    # Under RULES_V1, example.com is an ordinary domain: a domain
    # cookie and a host-only cookie are both accepted.
    jar.parse('id=1; Domain=example.com; Path=/', ORIGIN)
    jar.parse('sess=2; Path=/', ORIGIN)
    assert_equal %w[id sess], jar.cookies.map(&:name).sort
    domain_cookie, host_only_cookie = jar.cookies.sort_by(&:name)
    assert_equal true,  domain_cookie.for_domain?
    assert_equal false, host_only_cookie.for_domain?

    # Swap the rules: example.com is now a public suffix.  Existing
    # cookies are re-adjudicated, not just new writes.
    report = jar.replace_suffix_rules(RULES_V2)
    assert_equal 1, jar.suffix_rules_version
    assert_equal 1, report.version
    assert_same report, jar.last_recheck_report

    # The domain cookie is removed because its domain became a public
    # suffix; the host-only cookie is kept because suffix rules do
    # not apply to it.  Both reasons are queryable.
    assert_equal :public_suffix, report.reason_for(domain_cookie)
    assert_equal :host_only,     report.reason_for(host_only_cookie)
    assert_equal [domain_cookie],    report.removed.map(&:cookie)
    assert_equal [host_only_cookie], report.kept.map(&:cookie)
    assert_equal %w[sess], jar.cookies.map(&:name)

    # New writes are adjudicated against the new rules too: a domain
    # cookie for example.com is now rejected, while host-only writes
    # are still accepted.
    jar.parse('x=9; Domain=example.com; Path=/', ORIGIN)
    jar.parse('y=1; Path=/', ORIGIN)
    assert_equal %w[sess y], jar.cookies.map(&:name).sort
  end

  # A test environment declaring an internal domain as an effective
  # public suffix via injected rules.
  def test_custom_internal_suffix
    internal = List.new(%w[com corp.internal])
    jar = HTTP::CookieJar.new(:suffix_rules => internal)

    jar.parse('a=1; Domain=team.corp.internal; Path=/', 'http://team.corp.internal/')
    jar.parse('b=1; Domain=corp.internal; Path=/', 'http://team.corp.internal/')
    jar.parse('c=1; Path=/', 'http://team.corp.internal/')

    # The domain cookie for the internal suffix itself is rejected;
    # the one below it and the host-only one are accepted.
    assert_equal %w[a c], jar.cookies.map(&:name).sort
  end

  def test_provider_failure_fails_closed
    jar = HTTP::CookieJar.new(:suffix_rules => RULES_V1)
    jar.parse('id=1; Domain=example.com; Path=/', ORIGIN)
    jar.parse('sess=2; Path=/', ORIGIN)

    report = jar.replace_suffix_rules(BrokenRules.new)

    # A provider failure must not default to allowing a public
    # suffix: the domain cookie is removed with :provider_error and
    # the exception is recorded; the host-only cookie is kept.
    removed = report.removed
    assert_equal 1, removed.size
    assert_equal 'id', removed.first.cookie.name
    assert_equal :provider_error, removed.first.reason
    assert_kind_of RuntimeError, removed.first.error
    assert_equal %w[sess], jar.cookies.map(&:name)

    # While the provider is broken, new domain-cookie writes are
    # rejected as well (fail closed), but host-only writes still work.
    jar.parse('x=1; Domain=other.com; Path=/', 'http://other.com/')
    jar.parse('y=1; Path=/', 'http://other.com/')
    assert_equal %w[sess y], jar.cookies.map(&:name).sort
  end

  def test_replace_suffix_rules_validates_provider
    jar = HTTP::CookieJar.new(:suffix_rules => RULES_V1)
    assert_raise(ArgumentError) { jar.replace_suffix_rules(nil) }
    assert_raise(ArgumentError) { jar.replace_suffix_rules(Object.new) }
    # A failed replacement leaves the old rules and contents intact.
    assert_equal RULES_V1, jar.suffix_rules
    assert_equal 0, jar.suffix_rules_version
  end

  def test_reads_observe_a_consistent_rule_version_during_recheck
    jar = HTTP::CookieJar.new(:suffix_rules => RULES_V1)
    20.times { |i|
      jar.parse("c#{i}=1; Domain=example.com; Path=/", ORIGIN)
    }

    # A slow provider widens the recheck window so a concurrent reader
    # would observe a torn state if replacement were not atomic.
    slow_rules = Class.new do
      def initialize(rules)
        @rules = rules
      end

      def public_suffix?(host)
        sleep 0.01
        @rules.public_suffix?(host)
      end
    end.new(RULES_V2)

    snapshots = []
    reader = Thread.new do
      100.times do
        # A version read that brackets a content read with the same
        # version on both sides is a consistent snapshot.
        v1 = jar.suffix_rules_version
        names = jar.cookies.map(&:name)
        v2 = jar.suffix_rules_version
        snapshots << [v1, names] if v1 == v2
        sleep 0.001
      end
    end
    sleep 0.01
    jar.replace_suffix_rules(slow_rules)
    reader.join

    assert_not_empty snapshots
    snapshots.each { |version, names|
      if version == 0
        assert_equal 20, names.size, 'old rules must come with the old contents'
      else
        assert_equal [], names, 'new rules must come with the rechecked contents'
      end
    }
    assert snapshots.any? { |version, _| version == 1 }, 'reader should have observed the new version'
  end
end
