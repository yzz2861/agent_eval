# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestReferralSearch < Test::Unit::TestCase
  class ReferralResult
    attr_reader :code, :message, :referral_uris

    def initialize(code = Net::LDAP::ResultCodeSuccess, message = "Success", referral_uris = [])
      @code = code
      @message = message
      @referral_uris = referral_uris
    end

    def result_code
      @code
    end

    def error_message
      @message
    end
  end

  class FakeReferralClient
    attr_reader :searches

    def initialize(name, responses)
      @name = name
      @responses = responses
      @searches = []
    end

    def search_once(args)
      @searches << args
      response = @responses.fetch(args[:base]) { @responses.fetch(:default) }

      if response[:error]
        raise response[:error]
      end

      entries = Array(response[:entries]).dup
      entries.each { |entry| yield entry }
      [entries, ReferralResult.new(
        response.fetch(:code, Net::LDAP::ResultCodeSuccess),
        response.fetch(:message, "Success"),
        response.fetch(:referral_uris, []),
      )]
    end

    def close
    end
  end

  class FakeRoot
    attr_reader :host, :port, :base, :encryption

    def initialize(client)
      @client = client
      @host = "a.example"
      @port = 1389
      @base = "dc=example,dc=org"
      @encryption = nil
      @auth = { method: :anonymous }
    end

    def search_once(args, &block)
      @client.search_once(args, &block)
    end
  end

  def entry(dn, attributes = {})
    entry = Net::LDAP::Entry.new(dn)
    attributes.each { |name, value| entry[name] = value }
    entry
  end

  def test_follow_referrals_requires_a_boolean_or_callable
    error = assert_raise ArgumentError do
      Net::LDAP::ReferralSearch.options({ allow: true }, {})
    end

    assert_equal "follow_referrals must be true or a callable policy", error.message
  end

  def search_args(overrides = {})
    {
      base: "dc=example,dc=org",
      scope: Net::LDAP::SearchScope_WholeSubtree,
      filter: "(objectClass=*)",
      attributes: ["cn"],
      ignore_server_caps: true,
    }.merge(overrides)
  end

  def run_referrals(root_responses, clients, args = {}, policy = nil)
    root_client = FakeReferralClient.new("root", root_responses)
    root = FakeRoot.new(root_client)
    options = Net::LDAP::ReferralSearch.options(policy || true, args)
    factory = proc { |target| clients.fetch(target[:host]) }

    Net::LDAP::ReferralSearch.new(root, search_args(args), options, factory).run
  end

  def test_ldap_url_defaults_inherit_parent_search_fields
    root_responses = {
      default: {
        entries: [],
        referral_uris: ["ldap://b.example"],
      },
    }
    child = FakeReferralClient.new("b", default: { entries: [entry("cn=B")] })
    result = run_referrals(root_responses, "b.example" => child)

    assert result.success?, result.failures.inspect
    assert_equal ["cn=B"], result.entries.map(&:dn)
    search = child.searches.first
    assert_equal "dc=example,dc=org", search[:base]
    assert_equal Net::LDAP::SearchScope_WholeSubtree, search[:scope]
    assert_equal "(objectClass=*)", search[:filter]
    assert_equal ["cn"], search[:attributes]
  end

  def test_explicit_default_port_is_preserved_from_referral_url
    root_responses = {
      default: { entries: [], referral_uris: ["ldap://b.example:389"] },
    }
    child = FakeReferralClient.new("b", default: { entries: [] })
    targets = []
    root = FakeRoot.new(FakeReferralClient.new("root", root_responses))
    result = Net::LDAP::ReferralSearch.new(
      root,
      search_args,
      Net::LDAP::ReferralSearch.options(true, {}),
      proc { |target| targets << target; child },
    ).run

    assert result.success?
    assert_equal 389, targets.first[:port]
  end

  def test_ldap_url_fields_override_and_percent_decode_search_fields
    root_responses = {
      default: {
        entries: [],
        referral_uris: [
          "ldap://b.example/ou=teams,dc=example,dc=org?mail,cn?one?(cn=Anna%20B%C3%A9)",
        ],
      },
    }
    child = FakeReferralClient.new("b", default: { entries: [entry("cn=Anna Bé")] })
    result = run_referrals(root_responses, "b.example" => child)

    assert result.success?
    search = child.searches.first
    assert_equal "ou=teams,dc=example,dc=org", search[:base]
    assert_equal Net::LDAP::SearchScope_SingleLevel, search[:scope]
    assert_equal "(cn=Anna Bé)", search[:filter]
    assert_equal %w[mail cn], search[:attributes]
  end

  def test_empty_ldap_url_attribute_projection_requests_no_attributes
    child = FakeReferralClient.new(
      "b",
      default: { entries: [] },
    )
    result = run_referrals(
      { default: { entries: [], referral_uris: ["ldap://b.example/dc=example,dc=org??"] } },
      { "b.example" => child },
    )

    assert result.success?
    assert_equal [], child.searches.first[:attributes]
  end

  def test_empty_ldap_url_filter_is_invalid
    child = FakeReferralClient.new("b", default: { entries: [] })
    result = run_referrals(
      { default: { entries: [], referral_uris: ["ldap://b.example/dc=example,dc=org??sub?"] } },
      { "b.example" => child },
    )

    refute result.success?
    assert_equal :invalid_referral_uri, result.failures.first[:reason]
    assert_empty child.searches
  end

  def test_search_result_reference_and_final_referral_are_followed
    intermediate = FakeReferralClient.new(
      "b",
      default: {
        entries: [entry("cn=intermediate")],
        referral_uris: ["ldap://c.example/dc=c??sub?(uid=c)"],
      },
    )
    final = FakeReferralClient.new(
      "c",
      "dc=c" => {
        code: Net::LDAP::ResultCodeReferral,
        message: "Referral",
        entries: [entry("cn=final")],
        referral_uris: ["ldap://c.example/dc=c??sub?(uid=c)"],
      },
    )
    root_responses = {
      default: {
        entries: [],
        referral_uris: ["ldap://b.example"],
      },
    }

    result = run_referrals(root_responses, "b.example" => intermediate, "c.example" => final)

    assert result.success?
    assert_equal %w[cn=intermediate cn=final], result.entries.map(&:dn)
    assert_equal ["(uid=c)"], final.searches.map { |search| search[:filter] }
  end

  def test_mutual_referrals_detect_cycles_and_preserve_equal_dn_entries
    shared_dn = "uid=shared,ou=people,dc=example,dc=org"
    a = FakeReferralClient.new(
      "a",
      default: {
        entries: [entry(shared_dn, cn: "from-a")],
        referral_uris: ["ldap://b.example:2389/dc=example,dc=org"],
      },
    )
    b = FakeReferralClient.new(
      "b",
      default: {
        entries: [entry(shared_dn, cn: "from-b")],
        referral_uris: ["ldap://a.example:1389/dc=example,dc=org"],
      },
    )

    root = FakeRoot.new(a)
    policy = proc do |target|
      if target[:host] == "a.example" && target[:port] == 1389
        target.merge(client: a, auth: { method: :anonymous })
      else
        target.merge(client: b)
      end
    end
    options = Net::LDAP::ReferralSearch.options(policy, {})
    result = Net::LDAP::ReferralSearch.new(
      root,
      search_args,
      options,
      proc { |target| target },
    ).run

    assert result.success?
    assert_equal [shared_dn, shared_dn], result.entries.map(&:dn)
    assert_equal %w[from-a from-b], result.entries.flat_map { |search_entry| search_entry.cn }
    assert_equal :referral_cycle, result.skipped.first[:reason]
  end

  def test_policy_receives_target_and_may_provide_explicit_credentials
    seen_targets = []
    clients = {
      "b.example" => FakeReferralClient.new(
        "b",
        default: { entries: [entry("cn=B")] },
      ),
    }
    policy = proc do |target|
      seen_targets << target
      {
        client: clients["b.example"],
        auth: {
          method: :simple,
          username: "cn=referral-user,dc=example,dc=org",
          password: "referral-secret",
        },
      }
    end
    result = run_referrals(
      { default: { entries: [], referral_uris: ["ldap://b.example"] } },
      clients,
      {},
      policy,
    )

    assert result.success?
    assert_equal "b.example", seen_targets.first[:host]
    assert_equal(
      "cn=referral-user,dc=example,dc=org",
      clients["b.example"].searches.first[:auth][:username],
    )
    assert_equal "referral-secret", clients["b.example"].searches.first[:auth][:password]
  end

  def test_policy_may_return_a_preconfigured_client
    child = FakeReferralClient.new("b", default: { entries: [entry("cn=client")] })
    result = run_referrals(
      { default: { entries: [], referral_uris: ["ldap://b.example"] } },
      { "b.example" => child },
      {},
      proc { child },
    )

    assert result.success?
    assert_equal ["cn=client"], result.entries.map(&:dn)
  end

  def test_original_password_is_not_used_by_default_policy
    child = FakeReferralClient.new("b", default: { entries: [] })
    result = run_referrals(
      { default: { entries: [], referral_uris: ["ldap://b.example"] } },
      "b.example" => child,
      auth: { method: :simple, username: "cn=root", password: "root-secret" },
    )

    assert result.success?
    assert_equal :anonymous, child.searches.first[:auth][:method]
    refute child.searches.first[:auth].key?(:password)
  end

  def test_denied_policy_creates_failure_but_keeps_partial_entries
    child = FakeReferralClient.new("b", default: { entries: [] })
    result = run_referrals(
      { default: { entries: [entry("cn=root-entry")], referral_uris: ["ldap://b.example"] } },
      { "b.example" => child },
      {},
      proc { false },
    )

    refute result.success?
    assert_equal ["cn=root-entry"], result.entries.map(&:dn)
    assert_equal :referral_denied, result.failures.first[:reason]
  end

  def test_policy_exception_creates_policy_error_without_opening_target
    child = FakeReferralClient.new("b", default: { entries: [] })
    result = run_referrals(
      { default: { entries: [], referral_uris: ["ldap://b.example"] } },
      { "b.example" => child },
      {},
      proc { raise "not allowed by policy" },
    )

    refute result.success?
    assert_equal :policy_error, result.failures.first[:reason]
    assert_equal "not allowed by policy", result.failures.first[:error].message
    assert_empty child.searches
  end

  def test_failed_branch_keeps_partial_results_and_failure_details
    child = FakeReferralClient.new(
      "b",
      default: {
        code: Net::LDAP::ResultCodeInvalidCredentials,
        message: "Invalid Credentials",
      },
    )
    result = run_referrals(
      { default: { entries: [entry("cn=root-entry")], referral_uris: ["ldap://b.example"] } },
      { "b.example" => child },
    )

    refute result.success?
    assert_equal ["cn=root-entry"], result.entries.map(&:dn)
    failure = result.failures.first
    assert_equal :search_failed, failure[:reason]
    assert_equal Net::LDAP::ResultCodeInvalidCredentials, failure[:result_code]
  end

  def test_depth_and_branch_limits_stop_search_graph
    root_responses = {
      default: {
        entries: [],
        referral_uris: 2.times.map { |index| "ldap://#{index}.example" },
      },
    }
    clients = 2.times.each_with_object({}) do |index, hash|
      hash["#{index}.example"] = FakeReferralClient.new(
        index.to_s,
        default: { entries: [entry("cn=#{index}")] },
      )
    end
    result = run_referrals(root_responses, clients, max_referral_branches: 1)

    refute result.success?
    assert_equal 1, result.followed_branches
    assert_equal :max_branches_exceeded, result.failures.first[:reason]
  end
end
