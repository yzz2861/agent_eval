# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestVirtualListViewBER < Test::Unit::TestCase
  def test_sort_request_is_critical
    connection = Net::LDAP::Connection.new
    encoded = connection.send(:encode_sort_controls, ['sn'], true)

    expected =
      "\x30\x25" \
      "\x04\x161.2.840.113556.1.4.473" \
      "\x01\x01\xFF" \
      "\x04\x08\x30\x06\x30\x04\x04\x02sn"

    assert_equal expected.b, encoded
  end

  def test_offset_request_bytes
    encoded = Net::LDAP::VirtualListView.encode_request_control(
      before_count: 2,
      after_count: 4,
      offset: 42
    )

    expected =
      "\x30\x2E" \
      "\x04\x172.16.840.1.113730.3.4.9" \
      "\x01\x01\xFF" \
      "\x04\x10\x30\x0E" \
      "\x02\x01\x02\x02\x01\x04" \
      "\xA0\x06\x02\x01\x2A\x02\x01\x01"

    assert_equal expected.b, encoded
  end

  def test_sort_value_request_bytes
    encoded = Net::LDAP::VirtualListView.encode_request_control(
      before_count: 2,
      after_count: 4,
      sort_value: 'Smith'
    )

    expected =
      "\x30\x2D" \
      "\x04\x172.16.840.1.113730.3.4.9" \
      "\x01\x01\xFF" \
      "\x04\x0F\x30\x0D" \
      "\x02\x01\x02\x02\x01\x04" \
      "\x81\x05Smith"

    assert_equal expected.b, encoded
  end

  def test_response_decodes_position_estimate_and_context
    value = [52, 100, 0, 'ctx-1'].map(&:to_ber).to_ber_sequence.to_s.to_ber
    control = [
      Net::LDAP::LDAPControls::VLV_RESPONSE.to_ber,
      false.to_ber,
      value,
    ].to_ber_sequence
    result_body = Net::BER::BerIdentifiedArray.new([0, '', ''])
    result_body.ber_identifier = Net::LDAP::PDU::SearchResult
    parsed_control = control.read_ber
    controls = Net::BER::BerIdentifiedArray.new([parsed_control])
    controls.ber_identifier = 0xa0
    pdu = Net::LDAP::PDU.new([1, result_body, controls])
    context = new_context

    result = Net::LDAP::VirtualListView.interpret(pdu, context)

    assert_equal 52, result.target_position
    assert_equal 52, result.actual_position
    assert_equal 100, result.estimated_content_count
    assert_equal 100, result.estimated_size
    assert_equal 'ctx-1', result.context.context_id
  end

  private

  def new_context
    Net::LDAP::VirtualListView::Context.new(
      server: [['localhost', 389]],
      base: 'ou=People,dc=example,dc=org',
      filter: '(uid=*)',
      sort_definitions: [['sn', '', false]]
    )
  end
end

class TestVirtualListViewConnection < Test::Unit::TestCase
  def test_two_rounds_reuse_opaque_context_and_return_metadata
    socket = VLVStubSocket.new
    socket.enqueue_entry('uid=alice,ou=People,dc=example,dc=org', 'alice')
    socket.enqueue_result(52, 100, 'ctx-1')
    socket.enqueue_entry('uid=zoe,ou=People,dc=example,dc=org', 'zoe')
    socket.enqueue_result(60, 99, 'ctx-2')
    connection = Net::LDAP::Connection.new(socket: socket)
    args = search_args(offset: 42, context: new_context)

    first = connection.search(args)
    second = connection.search(args.merge(vlv_context: first.context))

    assert_equal %w[alice], first.map { |entry| entry[:uid].first }
    assert_equal %w[zoe], second.map { |entry| entry[:uid].first }
    assert_equal 52, first.target_position
    assert_equal 100, first.estimated_content_count
    assert_equal 'ctx-1', first.context.context_id
    assert_equal 60, second.target_position
    assert_equal 99, second.estimated_content_count
    assert_equal 'ctx-2', second.context.context_id

    first_request = parse_request(socket.packets[0])
    second_request = parse_request(socket.packets[1])

    assert_request_controls(first_request, context_id: nil)
    assert_request_controls(second_request, context_id: 'ctx-1')
  end

  def test_empty_window_is_success
    socket = VLVStubSocket.new
    socket.enqueue_result(42, 100, 'ctx-1')
    connection = Net::LDAP::Connection.new(socket: socket)

    result = connection.search(search_args(offset: 42, context: new_context))

    assert_empty result
    assert result.result.success?
    assert_equal 42, result.target_position
    assert_equal 100, result.estimated_content_count
  end

  def test_server_unsupported_critical_extension_is_a_vlv_failure
    socket = VLVStubSocket.new
    socket.enqueue_ldap_result(Net::LDAP::ResultCodeUnavailableCriticalExtension)
    connection = Net::LDAP::Connection.new(socket: socket)

    error = assert_raise(Net::LDAP::VirtualListViewError) do
      connection.search(search_args(offset: 42, context: new_context))
    end

    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension, error.code
    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension,
                 error.result.result_code
  end

  def test_sort_failure_is_distinct_from_vlv_failure
    socket = VLVStubSocket.new
    socket.enqueue_result(0, 0, nil, sort_code: 17)
    connection = Net::LDAP::Connection.new(socket: socket)

    assert_raise(Net::LDAP::ServerSortError) do
      connection.search(search_args(offset: 42, context: new_context))
    end
  end

  def test_search_failure_is_distinct_from_control_failure
    socket = VLVStubSocket.new
    socket.enqueue_ldap_result(Net::LDAP::ResultCodeNoSuchObject)
    connection = Net::LDAP::Connection.new(socket: socket)

    assert_raise(Net::LDAP::SearchError) do
      connection.search(search_args(offset: 42, context: new_context))
    end
  end

  private

  def search_args(offset:, context:)
    {
      base: 'ou=People,dc=example,dc=org',
      filter: '(uid=*)',
      sort_controls: [['sn', '', false]],
      vlv_context: context,
      before_count: 2,
      after_count: 4,
      offset: offset,
    }
  end

  def new_context
    Net::LDAP::VirtualListView::Context.new(
      server: [['localhost', 389]],
      base: 'ou=People,dc=example,dc=org',
      filter: '(uid=*)',
      sort_definitions: [['sn', '', false]]
    )
  end

  def parse_request(packet)
    packet.dup.read_ber(Net::LDAP::AsnSyntax)
  end

  def assert_request_controls(request, context_id:)
    sort_control = request[2][0]
    vlv_control = request[2][1]

    assert_equal Net::LDAP::LDAPControls::SORT_REQUEST, sort_control[0]
    assert_equal true, sort_control[1]
    assert_equal Net::LDAP::LDAPControls::VLV_REQUEST, vlv_control[0]
    assert_equal true, vlv_control[1]

    vlv_value = vlv_control[2].read_ber(Net::LDAP::AsnSyntax)
    assert_equal [2, 4], vlv_value[0..1]
    assert_equal context_id, vlv_value[3]
  end
end

class TestVirtualListViewContext < Test::Unit::TestCase
  def test_context_is_invalid_when_any_scope_part_changes
    original_scope = {
      server: [['localhost', 389]],
      base: 'ou=People,dc=example,dc=org',
      filter: '(uid=*)',
      sort_definitions: [['sn', '', false]],
    }
    context = Net::LDAP::VirtualListView::Context.new(
      **original_scope.merge(context_id: 'ctx-1')
    )

    [
      { server: [['other.example', 389]] },
      { base: 'ou=Other,dc=example,dc=org' },
      { filter: '(cn=*)' },
      { sort_definitions: [['givenName', '', false]] },
    ].each do |changed|
      assert_raise(Net::LDAP::InvalidVirtualListViewContextError) do
        context.validate!(**original_scope.merge(changed))
      end
    end
  end
end

class TestVirtualListViewClient < Test::Unit::TestCase
  def test_high_level_success_validates_context_and_normalizes_query
    connection = FakeVLVConnection.new([result_pdu(52, 100, 'ctx-1')])
    ldap = Net::LDAP.new(host: 'localhost', port: 389)
    ldap.connection = connection

    result = ldap.search_vlv(
      base: 'ou=People,dc=example,dc=org',
      filter: '(uid=*)',
      sort_control: 'sn',
      offset: 42,
      before: 2,
      after: 4
    )

    assert_equal 52, result.target_position
    assert_equal 100, result.estimated_content_count
    assert_equal 'ctx-1', result.context.context_id
    args = connection.searches.first
    assert_equal [['sn', '', false]], args[:sort_controls]
    assert_equal '(uid=*)', args[:filter]
    assert_equal 2, args[:before_count]
    assert_equal 4, args[:after_count]
  end

  def test_high_level_context_becomes_invalid_when_query_changes
    connection = FakeVLVConnection.new([result_pdu(52, 100, 'ctx-1')])
    ldap = Net::LDAP.new(host: 'localhost', port: 389)
    ldap.connection = connection
    first = ldap.search_vlv(
      base: 'ou=People,dc=example,dc=org',
      filter: '(uid=*)',
      sort_control: 'sn',
      offset: 42
    )

    assert_raise(Net::LDAP::InvalidVirtualListViewContextError) do
      ldap.search_vlv(
        base: 'ou=Other,dc=example,dc=org',
        filter: '(uid=*)',
        sort_control: 'sn',
        offset: 42,
        context: first.context
      )
    end
  end

  def test_high_level_unsupported_server_raises_vlv_failure
    connection = FakeVLVConnection.new([unsupported_pdu])
    ldap = Net::LDAP.new(host: 'localhost', port: 389)
    ldap.connection = connection

    error = assert_raise(Net::LDAP::VirtualListViewError) do
      ldap.search_vlv(
        base: 'ou=People,dc=example,dc=org',
        sort_control: 'sn',
        offset: 42
      )
    end

    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension, error.code
    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension,
                 ldap.get_operation_result.code
  end

  private

  def result_pdu(position, content_count, context_id, code: 0)
    body = Net::BER::BerIdentifiedArray.new([0, '', ''])
    body.ber_identifier = Net::LDAP::PDU::SearchResult
    sort_value = [code.to_ber].to_ber_sequence.to_s.to_ber
    vlv_values = [position, content_count, code].map(&:to_ber)
    vlv_values << context_id.to_ber if context_id
    vlv_value = vlv_values.to_ber_sequence.to_s.to_ber
    controls = Net::BER::BerIdentifiedArray.new([
      [Net::LDAP::LDAPControls::SORT_RESPONSE.to_ber, false.to_ber, sort_value].to_ber_sequence.read_ber,
      [Net::LDAP::LDAPControls::VLV_RESPONSE.to_ber, false.to_ber, vlv_value].to_ber_sequence.read_ber,
    ],)
    controls.ber_identifier = 0xa0
    Net::LDAP::PDU.new([1, body, controls])
  end

  def unsupported_pdu
    body = Net::BER::BerIdentifiedArray.new(
      [Net::LDAP::ResultCodeUnavailableCriticalExtension, '', '']
    )
    body.ber_identifier = Net::LDAP::PDU::SearchResult
    Net::LDAP::PDU.new([1, body])
  end
end

class FakeVLVConnection
  attr_reader :searches

  def initialize(results)
    @results = results
    @searches = []
  end

  def search(args)
    @searches << args
    result = @results.shift
    Net::LDAP::VirtualListView.interpret(
      result,
      args[:vlv_context],
      []
    )
  end
end

class VLVStubSocket
  attr_reader :packets

  def initialize
    @messages = []
    @packets = []
  end

  def write(packet)
    @packets << packet
    @last_message_id = packet.dup.read_ber(Net::LDAP::AsnSyntax).first
    packet.bytesize
  end

  def read_ber(_syntax = nil)
    message = @messages.shift
    return unless message

    [@last_message_id || 1, *message]
  end

  def enqueue_entry(dn, uid)
    body = Net::BER::BerIdentifiedArray.new([dn, [['uid', [uid]]]])
    body.ber_identifier = Net::LDAP::PDU::SearchReturnedData
    @messages << [body]
  end

  def enqueue_result(position, content_count, context_id, sort_code: 0)
    controls = Net::BER::BerIdentifiedArray.new(
      [sort_control(sort_code), vlv_control(position, content_count, context_id)]
    )
    controls.ber_identifier = 0xa0
    body = Net::BER::BerIdentifiedArray.new([Net::LDAP::ResultCodeSuccess, '', ''])
    body.ber_identifier = Net::LDAP::PDU::SearchResult
    @messages << [body, controls]
  end

  def enqueue_ldap_result(code)
    body = Net::BER::BerIdentifiedArray.new([code, '', ''])
    body.ber_identifier = Net::LDAP::PDU::SearchResult
    @messages << [body]
  end

  private

  def sort_control(code)
    value = [code.to_ber].to_ber_sequence.to_s.to_ber
    [Net::LDAP::LDAPControls::SORT_RESPONSE.to_ber, false.to_ber, value].to_ber_sequence.read_ber
  end

  def vlv_control(position, content_count, context_id)
    values = [position, content_count, 0].map(&:to_ber)
    values << context_id.to_ber if context_id
    value = values.to_ber_sequence.to_s.to_ber
    [Net::LDAP::LDAPControls::VLV_RESPONSE.to_ber, false.to_ber, value].to_ber_sequence.read_ber
  end
end
