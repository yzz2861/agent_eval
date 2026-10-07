# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestSearch < Test::Unit::TestCase
  class FakeConnection
    def search(args)
      OpenStruct.new(:result_code => Net::LDAP::ResultCodeOperationsError, :message => "error", :success? => false)
    end
  end

  def setup
    @service = MockInstrumentationService.new
    @connection = Net::LDAP.new :instrumentation_service => @service
    @connection.instance_variable_set(:@open_connection, FakeConnection.new)
  end

  def test_true_result
    assert_nil @connection.search(:return_result => true)
  end

  def test_false_result
    refute @connection.search(:return_result => false)
  end

  def test_no_result
    assert_nil @connection.search
  end

  def test_instrumentation_publishes_event
    events = @service.subscribe "search.net_ldap"

    @connection.search(:filter => "test")

    payload, result = events.pop
    assert payload.key?(:result)
    assert payload.key?(:filter)
    assert_equal "test", payload[:filter]
  end

  def test_follow_referrals_returns_partial_results_and_failures
    entry = Net::LDAP::Entry.new("cn=partial")
    failure = {
      reason: :search_failed,
      uri: "ldap://other.example",
      result_code: Net::LDAP::ResultCodeInvalidCredentials,
    }
    result = Net::LDAP::ReferralResult.new(
      [entry],
      OpenStruct.new(result_code: Net::LDAP::ResultCodeSuccess, error_message: ""),
      [failure],
      [],
      1,
    )
    flexmock(Net::LDAP::ReferralSearch).new_instances.should_receive(:run)
                                              .and_yield(entry)
                                              .and_return(result)

    returned_entries = @connection.search(follow_referrals: true)

    assert_nil returned_entries
    operation_result = @connection.get_operation_result
    assert_equal [failure], operation_result.referral_failures
    assert_equal [entry], operation_result.partial_results
    assert_equal Net::LDAP::ResultCodeOther, operation_result.code
  end

  def test_follow_referrals_boolean_result_reflects_branch_failures
    result = Net::LDAP::ReferralResult.new(
      [],
      OpenStruct.new(result_code: Net::LDAP::ResultCodeSuccess, error_message: ""),
      [{ reason: :referral_denied }],
      [],
      0,
    )
    flexmock(Net::LDAP::ReferralSearch).new_instances.should_receive(:run).and_return(result)

    refute @connection.search(follow_referrals: true, return_result: false)
    assert_equal Net::LDAP::ResultCodeInsufficientAccessRights,
                 @connection.get_operation_result.code
  end
end
