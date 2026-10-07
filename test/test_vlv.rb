# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'
require_relative 'support/vlv_stub_socket'

class TestVLV < Test::Unit::TestCase
  BASE = 'ou=people,dc=example,dc=org'

  def build_connection(responses)
    socket = VLVStubSocket.new(responses)
    Net::LDAP::Connection.new(:socket => socket).tap do |conn|
      conn.instance_variable_set(:@conn, socket)
    end
  end

  def build_ldap(responses)
    conn = build_connection(responses)
    socket = conn.instance_variable_get(:@conn)
    ldap = Net::LDAP.new
    ldap.instance_variable_set(:@open_connection, conn)
    [ldap, socket]
  end

  def result_with_controls(message_id, target, count, context_id,
                           vlv_code = 0, sort_code = 0)
    controls = [
      VLVStubSocket::Helpers.sort_response_control(sort_code),
      VLVStubSocket::Helpers.vlv_response_control(target, count, vlv_code,
                                         context_id),
    ].to_ber_contextspecific(0)
    VLVStubSocket::Helpers.result_pdu(message_id, Net::LDAP::ResultCodeSuccess,
                             '', controls)
  end

  # Two-round offset browse: the first request carries no contextID; the
  # server issues one and the second request must present it along with the
  # contentCount the server estimated in round one.
  def test_two_round_offset_search_reuses_context
    responses = [
      VLVStubSocket::Helpers.entry_pdu(1, 'cn=a,ou=people,dc=example,dc=org',
                              'cn' => 'a', 'sn' => 'aa'),
      result_with_controls(1, 1, 215, 'CTX-A'),
      VLVStubSocket::Helpers.entry_pdu(2, 'cn=b,ou=people,dc=example,dc=org',
                              'cn' => 'b', 'sn' => 'bb'),
      result_with_controls(2, 11, 215, 'CTX-B'),
    ]
    ldap, socket = build_ldap(responses)

    window1 = nil
    ldap.vlv_session(:sort => 'sn', :base => BASE) do |vlv|
      window1 = vlv.at(1, :after_count => 5)
      assert window1.success?
      window2 = vlv.at(11, :after_count => 5)
      assert window2.success?

      assert_equal 1, window1.target_position
      assert_equal 215, window1.estimated_content_count
      assert_equal 'CTX-A', window1.context.id
      assert_equal 11, window2.target_position
      assert_equal 'CTX-B', window2.context.id
    end

    assert_equal 2, socket.written.length
    first  = VLVStubSocket::Helpers.find_control(socket.written[0],
                                        Net::LDAP::VLV::VLV_REQUEST)
    second = VLVStubSocket::Helpers.find_control(socket.written[1],
                                        Net::LDAP::VLV::VLV_REQUEST)

    first_vlv  = VLVStubSocket::Helpers.parse_vlv_request(first[:value])
    second_vlv = VLVStubSocket::Helpers.parse_vlv_request(second[:value])

    assert_equal 1, first_vlv[:offset]
    assert_equal 0, first_vlv[:content_count]
    assert_nil first_vlv[:context_id]
    assert_equal 11, second_vlv[:offset]
    # contentCount is continued from the round-one estimate.
    assert_equal 215, second_vlv[:content_count]
    assert_equal 'CTX-A', second_vlv[:context_id]

    # Both controls must be critical by default.
    assert_equal true, first[:criticality]
    assert_equal true, second[:criticality]

    sort_first = VLVStubSocket::Helpers.find_control(
      socket.written[0], Net::LDAP::LDAPControls::SORT_REQUEST)
    assert_equal true, sort_first[:criticality]

    # No RFC 2696 paging control is mixed into a VLV search.
    assert_nil VLVStubSocket::Helpers.find_control(
      socket.written[0], Net::LDAP::LDAPControls::PAGED_RESULTS)
  end

  def test_greater_than_or_equal_search_returns_window
    responses = [
      VLVStubSocket::Helpers.entry_pdu(1, 'cn=smith,ou=people,dc=example,dc=org',
                              'sn' => 'Smith'),
      result_with_controls(1, 42, 215, 'CTX-S'),
    ]
    ldap, socket = build_ldap(responses)

    window = ldap.search_vlv(:sort => 'sn', :base => BASE,
                             :greater_than_or_equal => 'Smith',
                             :before_count => 2, :after_count => 10)

    assert window.success?
    assert_equal 42, window.target_position
    assert_equal 215, window.estimated_content_count
    assert_equal 1, window.entries.length
    assert_equal 'Smith', window.entries.first[:sn].first

    vlv = VLVStubSocket::Helpers.find_control(
      socket.written[0], Net::LDAP::VLV::VLV_REQUEST)
    parsed = VLVStubSocket::Helpers.parse_vlv_request(vlv[:value])
    assert_equal 'Smith', parsed[:greater_than_or_equal]
    assert_equal 2, parsed[:before_count]
    assert_equal 10, parsed[:after_count]
  end

  def test_estimated_content_count_is_not_assumed_permanent
    responses = [
      result_with_controls(1, 1, 215, 'CTX-C'),
    ]
    ldap, _socket = build_ldap(responses)
    window = ldap.search_vlv(:sort => 'sn', :base => BASE,
                             :offset => 1, :after_count => 5)
    assert_equal 215, window.estimated_content_count
    # The estimate is just an accessor on this window, not cached state.
    refute_respond_to ldap, :estimated_content_count
  end

  def test_empty_window_is_success_not_error
    responses = [
      result_with_controls(1, 50, 215, 'CTX-E'),
    ]
    ldap, _socket = build_ldap(responses)
    window = ldap.search_vlv(:sort => 'sn', :base => BASE,
                             :offset => 50, :before_count => 1,
                             :after_count => 1)
    assert window.success?
    assert window.empty_window?
    assert_equal [], window.entries
    refute window.search_failure?
    refute window.sort_failure?
    refute window.vlv_failure?
  end

  def test_sort_failure_is_distinguished
    controls = [
      VLVStubSocket::Helpers.sort_response_control(
        Net::LDAP::ResultCodeNoSuchAttribute, 'bogusattr'),
    ].to_ber_contextspecific(0)
    responses = [
      VLVStubSocket::Helpers.result_pdu(1, Net::LDAP::ResultCodeSuccess, '',
                               controls),
    ]
    ldap, _socket = build_ldap(responses)
    window = ldap.search_vlv(:sort => 'bogusattr', :base => BASE,
                             :offset => 1)
    assert window.sort_failure?
    assert_equal :sort_error, window.status
    assert_equal Net::LDAP::ResultCodeNoSuchAttribute,
                 window.sort_result_code
    assert_equal 'bogusattr', window.sort_attribute_type
    refute window.search_failure?
    refute window.vlv_failure?
  end

  def test_vlv_failure_is_distinguished
    responses = [
      result_with_controls(1, 0, 0, nil,
                           Net::LDAP::VLV::ResultUnwillingToPerform),
    ]
    ldap, _socket = build_ldap(responses)
    window = ldap.search_vlv(:sort => 'sn', :base => BASE,
                             :offset => 1)
    assert window.vlv_failure?
    assert_equal :vlv_error, window.status
    assert_equal Net::LDAP::VLV::ResultUnwillingToPerform,
                 window.vlv_result_code
  end

  def test_plain_search_failure_is_distinguished
    responses = [
      VLVStubSocket::Helpers.result_pdu(1, Net::LDAP::ResultCodeInsufficientAccessRights,
                               'access denied'),
    ]
    ldap, _socket = build_ldap(responses)
    window = ldap.search_vlv(:sort => 'sn', :base => BASE,
                             :offset => 1)
    assert window.search_failure?
    assert_equal :search_error, window.status
    assert_equal Net::LDAP::ResultCodeInsufficientAccessRights,
                 window.search_code
    assert_equal 'access denied', window.search_error_message
  end

  def test_unsupported_server_is_reported
    # A critical VLV control that the server does not honor yields
    # unavailableCriticalExtension (12) at the search level.
    responses = [
      VLVStubSocket::Helpers.result_pdu(
        1, Net::LDAP::ResultCodeUnavailableCriticalExtension,
        'unsupported control'),
    ]
    ldap, _socket = build_ldap(responses)
    window = ldap.search_vlv(:sort => 'sn', :base => BASE,
                             :offset => 1)
    assert window.unsupported?
    assert_equal :unsupported, window.status
    refute window.success?
  end

  def test_context_is_invalid_when_query_changes
    responses = [
      VLVStubSocket::Helpers.entry_pdu(1, 'cn=a,ou=people,dc=example,dc=org'),
      result_with_controls(1, 1, 100, 'CTX-X'),
    ]
    ldap, _socket = build_ldap(responses)
    window = ldap.search_vlv(:sort => 'sn', :base => BASE,
                             :filter => '(objectClass=person)',
                             :offset => 1)
    context = window.context

    # Same query is fine.
    signature = Net::LDAP::VLV.signature(
      ['127.0.0.1', 389, nil], BASE, '(objectClass=person)', ['sn'])
    assert_equal signature, context.signature

    # Different base, filter, or sort cannot continue the context.
    assert_raise(Net::LDAP::VLV::ContextMismatchError) do
      ldap.search_vlv(:sort => 'sn', :base => 'ou=other,dc=example,dc=org',
                      :offset => 2, :context => context)
    end
    assert_raise(Net::LDAP::VLV::ContextMismatchError) do
      ldap.search_vlv(:sort => 'sn', :base => BASE,
                      :filter => '(objectClass=group)',
                      :offset => 2, :context => context)
    end
    assert_raise(Net::LDAP::VLV::ContextMismatchError) do
      ldap.search_vlv(:sort => 'cn', :base => BASE,
                      :offset => 2, :context => context)
    end
  end

  def test_server_rejected_context_is_restarted_without_context_id
    # Round one issues a context. Round two's first attempt is rejected by
    # the server; the client retries without contextID and succeeds.
    rejected_controls = [
      VLVStubSocket::Helpers.vlv_response_control(
        0, 215, Net::LDAP::VLV::ResultUnwillingToPerform, nil),
    ].to_ber_contextspecific(0)
    responses = [
      VLVStubSocket::Helpers.entry_pdu(1, 'cn=a,ou=people,dc=example,dc=org'),
      result_with_controls(1, 1, 215, 'CTX-Y'),
      # rejected first attempt of round two (message id 2)
      VLVStubSocket::Helpers.result_pdu(2, Net::LDAP::ResultCodeSuccess, '',
                               rejected_controls),
      # retried round two (message id 3), fresh context
      VLVStubSocket::Helpers.entry_pdu(3, 'cn=b,ou=people,dc=example,dc=org'),
      result_with_controls(3, 11, 215, 'CTX-Z'),
    ]
    ldap, socket = build_ldap(responses)

    window2 = nil
    ldap.vlv_session(:sort => 'sn', :base => BASE) do |vlv|
      vlv.at(1)
      window2 = vlv.at(11)
    end

    assert window2.success?
    assert window2.context_restarted?

    # Three writes: initial round, rejected continuation, clean retry.
    assert_equal 3, socket.written.length
    rejected_request = VLVStubSocket::Helpers.find_control(
      socket.written[1], Net::LDAP::VLV::VLV_REQUEST)
    retried_request = VLVStubSocket::Helpers.find_control(
      socket.written[2], Net::LDAP::VLV::VLV_REQUEST)
    assert_equal 'CTX-Y',
                 VLVStubSocket::Helpers.parse_vlv_request(rejected_request[:value])[:context_id]
    assert_nil VLVStubSocket::Helpers.parse_vlv_request(retried_request[:value])[:context_id]
  end

  def test_vlv_requires_sort_definition
    ldap, _socket = build_ldap([])
    assert_raise(ArgumentError) do
      ldap.search_vlv(:base => BASE, :offset => 1)
    end
  end

  def test_vlv_requires_target
    ldap, _socket = build_ldap([])
    assert_raise(ArgumentError) do
      ldap.search_vlv(:sort => 'sn', :base => BASE)
    end
  end

  def test_vlv_supported_checks_root_dse_controls
    ldap, _socket = build_ldap([])
    entry = Net::LDAP::Entry.new
    entry[:supportedcontrol] = [
      Net::LDAP::LDAPControls::PAGED_RESULTS,
      Net::LDAP::LDAPControls::SORT_REQUEST,
      Net::LDAP::LDAPControls::VLV_REQUEST,
    ]
    ldap.define_singleton_method(:search_root_dse) { entry }
    assert ldap.vlv_supported?

    entry2 = Net::LDAP::Entry.new
    entry2[:supportedcontrol] = [Net::LDAP::LDAPControls::SORT_REQUEST]
    ldap2, _s = build_ldap([])
    ldap2.define_singleton_method(:search_root_dse) { entry2 }
    refute ldap2.vlv_supported?
  end
end
