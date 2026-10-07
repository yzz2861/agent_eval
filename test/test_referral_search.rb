# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestReferralSearch < Test::Unit::TestCase
  # A stub directory server. All network interaction in these tests goes
  # through this object: it plays back scripted responses and records the
  # searches it received.
  class StubDirectory
    attr_reader :host, :port, :searches
    attr_accessor :auth

    def initialize(host, port)
      @host = host
      @port = port
      @searches = []
      @responses = []
    end

    # Queue a response. +references+ are delivered as SearchResultReference
    # entries, +final_referrals+ accompany the final search result (which
    # typically carries result code 10).
    def respond(entries: [], references: [], final_referrals: [], code: 0, message: "")
      @responses << {
        entries: entries,
        references: references,
        final_referrals: final_referrals,
        code: code,
        message: message,
      }
    end

    def search(args)
      @searches << args
      response = @responses.shift or raise "no scripted response for #{host}:#{port}"
      response[:entries].each { |entry| yield entry }
      (response[:references] + response[:final_referrals]).each do |url|
        referral = Net::LDAP::Entry.new
        referral[:search_referrals] = [url]
        yield referral
      end
      @operation_result = OpenStruct.new(
        code: response[:code],
        error_message: response[:message],
        message: response[:message])
      nil
    end

    def get_operation_result
      @operation_result
    end
  end

  # Stands in for Net::LDAP::Connection when exercising the follow_referrals
  # mode through Net::LDAP#search. Returns a Hash-like result so that both
  # Net::LDAP#search (which reads +result_code+) and
  # Net::LDAP#get_operation_result (which reads Hash keys) work.
  class FakeConnection
    class Result < Hash
      def result_code
        self[:resultCode]
      end
    end

    def initialize(directory)
      @directory = directory
    end

    def search(args, &block)
      @directory.search(args, &block)
      op = @directory.get_operation_result
      Result[:resultCode => op.code, :errorMessage => op.error_message]
    end
  end

  def setup
    @directories = {}
    @connections = []
    @factory = lambda do |host, port, auth, scheme|
      @connections << { host: host, port: port, auth: auth, scheme: scheme }
      dir = @directories.fetch([host, port])
      dir.auth = auth
      dir
    end
  end

  def directory(host, port = 389)
    @directories[[host, port]] = StubDirectory.new(host, port)
  end

  def entry(dn)
    Net::LDAP::Entry.new(dn)
  end

  def chase(root, args = {})
    Net::LDAP::ReferralSearch.new(
      root,
      { connection_factory: @factory }.merge(args)
    ).run
  end

  def search_args
    {
      base: "dc=example,dc=com",
      filter: Net::LDAP::Filter.eq("objectClass", "*"),
      attributes: ["cn"],
      scope: Net::LDAP::SearchScope_WholeSubtree,
    }
  end

  def test_missing_url_fields_inherit_search_parameters
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root_entry = entry("cn=root,dc=example,dc=com")
    branch_entry = entry("cn=branch,dc=example,dc=com")
    root.respond(entries: [root_entry], references: ["ldap://b.example.com/"])
    branch.respond(entries: [branch_entry])

    result = chase(root, search_args)

    assert result.success?
    assert_equal [root_entry, branch_entry], result.entries
    assert_equal [{ url: "ldap://b.example.com/", depth: 1, status: :followed }], result.referrals

    received = branch.searches.first
    assert_equal "dc=example,dc=com", received[:base]
    assert_equal ["cn"], received[:attributes]
    assert_equal Net::LDAP::SearchScope_WholeSubtree, received[:scope]
    assert_equal "(objectClass=*)", received[:filter].to_s
  end

  def test_url_fields_override_search_parameters
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root.respond(references: ["ldap://b.example.com/ou=people,dc=example,dc=com?cn,mail?one?(objectClass=person)"])
    branch.respond(entries: [entry("cn=branch,ou=people,dc=example,dc=com")])

    result = chase(root, search_args)

    assert result.success?
    received = branch.searches.first
    assert_equal "ou=people,dc=example,dc=com", received[:base]
    assert_equal ["cn", "mail"], received[:attributes]
    assert_equal Net::LDAP::SearchScope_SingleLevel, received[:scope]
    assert_equal "(objectClass=person)", received[:filter].to_s
  end

  def test_percent_encoded_url_fields_are_decoded
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root.respond(references: ["ldap://b.example.com/dc=example%2Cdc=com???(cn%3D*)"])
    branch.respond(entries: [entry("cn=branch,dc=example,dc=com")])

    result = chase(root, search_args)

    assert result.success?
    received = branch.searches.first
    assert_equal "dc=example,dc=com", received[:base]
    assert_equal "(cn=*)", received[:filter].to_s
    assert_equal ["cn"], received[:attributes]
    assert_equal Net::LDAP::SearchScope_WholeSubtree, received[:scope]
  end

  def test_final_referral_result_is_followed
    root = directory("a.example.com")
    branch = directory("b.example.com")
    branch_entry = entry("cn=branch,dc=example,dc=com")
    root.respond(final_referrals: ["ldap://b.example.com/dc=example,dc=com"],
                 code: Net::LDAP::ResultCodeReferral)
    branch.respond(entries: [branch_entry])

    result = chase(root, search_args)

    assert result.success?
    assert_equal [branch_entry], result.entries
    assert_equal :followed, result.referrals.first[:status]
  end

  def test_mutual_referrals_are_detected_as_cycles
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root_entry = entry("cn=root,dc=example,dc=com")
    branch_entry = entry("cn=branch,dc=example,dc=com")
    root.respond(entries: [root_entry],
                 references: ["ldap://b.example.com/dc=example,dc=com?cn?sub?(objectClass=*)"])
    branch.respond(entries: [branch_entry],
                   references: ["ldap://a.example.com/dc=example,dc=com?cn?sub?(objectClass=*)"])

    result = chase(root, search_args)

    assert result.success?
    assert_equal [root_entry, branch_entry], result.entries
    assert_equal [:followed, :cycle], result.referrals.map { |r| r[:status] }
    assert_equal 1, root.searches.size
    assert_equal 1, branch.searches.size
  end

  def test_referral_depth_limit
    root = directory("a.example.com")
    branch = directory("b.example.com")
    leaf = directory("c.example.com")
    root.respond(references: ["ldap://b.example.com/"])
    branch.respond(references: ["ldap://c.example.com/"])

    result = chase(root, search_args.merge(max_referral_depth: 1))

    assert result.success?
    assert_equal [:followed, :depth_limit], result.referrals.map { |r| r[:status] }
    assert_equal 0, leaf.searches.size
  end

  def test_total_referral_limit
    root = directory("a.example.com")
    branch = directory("b.example.com")
    leaf = directory("c.example.com")
    root.respond(references: ["ldap://b.example.com/", "ldap://c.example.com/"])
    branch.respond(entries: [entry("cn=branch,dc=example,dc=com")])

    result = chase(root, search_args.merge(max_referrals: 1))

    assert result.success?
    assert_equal [:followed, :limit_exceeded], result.referrals.map { |r| r[:status] }
    assert_equal 1, branch.searches.size
    assert_equal 0, leaf.searches.size
  end

  def test_failed_branch_yields_partial_results_and_failure_list
    root = directory("a.example.com")
    broken = directory("b.example.com")
    healthy = directory("c.example.com")
    root_entry = entry("cn=root,dc=example,dc=com")
    healthy_entry = entry("cn=healthy,dc=example,dc=com")
    root.respond(entries: [root_entry],
                 references: ["ldap://b.example.com/", "ldap://c.example.com/"])
    broken.respond(code: Net::LDAP::ResultCodeNoSuchObject, message: "no such object")
    healthy.respond(entries: [healthy_entry])

    result = chase(root, search_args)

    refute result.success?
    assert_equal [root_entry, healthy_entry], result.entries
    assert_equal 1, result.failures.size
    failure = result.failures.first
    assert_equal "ldap://b.example.com/", failure[:url]
    assert_equal "b.example.com", failure[:host]
    assert_equal Net::LDAP::ResultCodeNoSuchObject, failure[:code]
    assert_equal "no such object", failure[:message]
  end

  def test_root_failure_is_reported
    root = directory("a.example.com")
    root.respond(code: Net::LDAP::ResultCodeUnavailable, message: "server down")

    result = chase(root, search_args)

    refute result.success?
    assert_equal 1, result.failures.size
    assert_nil result.failures.first[:url]
    assert_equal Net::LDAP::ResultCodeUnavailable, result.failures.first[:code]
  end

  def test_invalid_referral_url_is_reported_as_failure
    root = directory("a.example.com")
    root.respond(entries: [entry("cn=root,dc=example,dc=com")],
                 references: ["not-a-ldap-url"])

    result = chase(root, search_args)

    refute result.success?
    assert_equal 1, result.failures.size
    assert_equal "not-a-ldap-url", result.failures.first[:url]
    assert_equal Net::LDAP::ResultCodeProtocolError, result.failures.first[:code]
  end

  def test_referrals_default_to_anonymous_auth_without_reusing_credentials
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root.respond(references: ["ldap://b.example.com/"])
    branch.respond(entries: [])

    result = chase(root, search_args)

    assert result.success?
    assert_equal({ method: :anonymous }, @connections.first[:auth])
    refute @connections.first[:auth].key?(:password)
  end

  def test_referral_policy_may_deny_access
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root.respond(references: ["ldap://b.example.com/"])

    result = chase(root, search_args.merge(referral_policy: ->(_info) { false }))

    assert result.success?
    assert_equal [:skipped], result.referrals.map { |r| r[:status] }
    assert_equal 0, branch.searches.size
    assert_empty @connections
  end

  def test_referral_policy_supplies_credentials_and_receives_target_info
    root = directory("a.example.com")
    branch = directory("b.example.com", 1389)
    root.respond(references: ["ldap://b.example.com:1389/"])
    branch.respond(entries: [])

    seen = []
    policy = lambda do |info|
      seen << info
      { method: :simple, username: "cn=chaser", password: "s3cret" }
    end

    result = chase(root, search_args.merge(referral_policy: policy))

    assert result.success?
    assert_equal [{ url: "ldap://b.example.com:1389/", host: "b.example.com", port: 1389, depth: 1 }], seen
    assert_equal({ method: :simple, username: "cn=chaser", password: "s3cret" },
                 @connections.first[:auth])
  end

  def test_same_dn_from_different_sources_is_not_deduplicated
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root.respond(entries: [entry("cn=shared,dc=example,dc=com")],
                 references: ["ldap://b.example.com/"])
    branch.respond(entries: [entry("cn=shared,dc=example,dc=com")])

    result = chase(root, search_args)

    assert result.success?
    assert_equal ["cn=shared,dc=example,dc=com", "cn=shared,dc=example,dc=com"],
                 result.entries.map(&:dn)
    assert_equal [0, 1], result.sources.map { |s| s[:depth] }
  end

  def test_ldap_search_with_follow_referrals_returns_aggregated_result
    root = directory("a.example.com")
    branch = directory("b.example.com")
    root_entry = entry("cn=root,dc=example,dc=com")
    branch_entry = entry("cn=branch,dc=example,dc=com")
    root.respond(entries: [root_entry], references: ["ldap://b.example.com/"])
    branch.respond(entries: [branch_entry])

    ldap = Net::LDAP.new(host: "a.example.com", port: 389,
                         instrumentation_service: MockInstrumentationService.new)
    ldap.connection = FakeConnection.new(root)

    result = ldap.search(search_args.merge(
                           follow_referrals: true,
                           ignore_server_caps: true,
                           connection_factory: @factory))

    assert_kind_of Net::LDAP::ReferralSearchResult, result
    assert result.success?
    assert_equal [root_entry, branch_entry], result.to_a
    assert_equal Net::LDAP::ResultCodeSuccess, ldap.get_operation_result.code
  end

  def test_ldap_search_operation_result_reflects_branch_failure
    root = directory("a.example.com")
    broken = directory("b.example.com")
    root.respond(entries: [entry("cn=root,dc=example,dc=com")],
                 references: ["ldap://b.example.com/"])
    broken.respond(code: Net::LDAP::ResultCodeNoSuchObject, message: "no such object")

    ldap = Net::LDAP.new(host: "a.example.com", port: 389,
                         instrumentation_service: MockInstrumentationService.new)
    ldap.connection = FakeConnection.new(root)

    result = ldap.search(search_args.merge(
                           follow_referrals: true,
                           ignore_server_caps: true,
                           connection_factory: @factory))

    refute result.success?
    assert_equal Net::LDAP::ResultCodeNoSuchObject, ldap.get_operation_result.code
    assert_equal "no such object", ldap.get_operation_result.error_message
  end
end
