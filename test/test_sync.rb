# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'
require 'stringio'

class TestLDAPSync < Test::Unit::TestCase
  RecordedSocket = Struct.new(:read_io, :written) do
    def read(length = nil, _buffer = nil)
      read_io.read(length)
    end

    def getbyte
      read_io.getbyte
    end

    def write(data)
      written << data
      data.bytesize
    end

    def read_ber(*args, &block)
      read_io.read_ber(*args, &block)
    end

    def close
    end
  end

  def uuid(number)
    [format("%032x", number)].pack("H32").force_encoding(Encoding::BINARY)
  end

  def connection(bytes)
    RecordedSocket.new(StringIO.new(bytes.b), "".b).then do |socket|
      [Net::LDAP::Connection.new(:socket => socket), socket]
    end
  end

  def packet(message_id, app_tag, content, controls = nil)
    body =
      if content.respond_to?(:ber_identifier) && content.ber_identifier == (0x60 + app_tag)
        raw_application(app_tag, ber_content(content))
      else
        raw_application(app_tag, content.join)
      end
    raw_sequence([message_id.to_ber, body, controls].compact.join)
  end

  def ber_array(content, tag)
    array = Net::BER::BerIdentifiedArray.new(content)
    array.ber_identifier = tag
    array
  end

  def raw_sequence(content)
    "\x30#{content.bytesize.to_ber_length_encoding}#{content}".b
  end

  def raw_application(tag, content)
    [0x60 + tag].pack("C") + content.bytesize.to_ber_length_encoding + content
  end

  def context_wrapper(content, tag = 0)
    [0xa0 + tag].pack("C") + content.bytesize.to_ber_length_encoding + content
  end

  def ber_content(array)
    array.map(&:to_ber).join
  end

  def entry_packet(message_id, dn, state, id, cookie = nil)
    attributes = [
      ["entryUUID".to_ber, [id].to_ber_set].to_ber_sequence,
      ["cn".to_ber, ["name"].to_ber_set].to_ber_sequence,
    ].to_ber_sequence
    entry = ber_array([
      dn.to_ber,
      attributes,
    ], Net::LDAP::PDU::SearchReturnedData)
    value = [state.to_ber_enumerated, id.to_ber_bin(0x04)]
    value << cookie.to_ber_bin(0x80) if cookie
    packet(message_id,
           Net::LDAP::PDU::SearchReturnedData,
           entry,
           context_wrapper(sync_state_control(value.join)))
  end

  def result_packet(message_id, code = Net::LDAP::ResultCodeSuccess, controls = nil)
    result = ber_array([
      code.to_ber_enumerated,
      "".to_ber,
      "".to_ber,
    ], Net::LDAP::PDU::SearchResult)
    packet(message_id, Net::LDAP::PDU::SearchResult, result, controls)
  end

  def sync_done_control(cookie, refresh_deletes)
    value = []
    value << cookie.to_ber_bin(0x80) if cookie
    value << context_boolean(refresh_deletes, 0x81)
    context_wrapper(control(Net::LDAP::LDAPControls::SYNC_DONE, value.join))
  end

  def sync_state_control(value)
    control(Net::LDAP::LDAPControls::SYNC_STATE, value)
  end

  def control(oid, value, critical = true)
    [
      oid.to_ber(0x04),
      value.to_ber,
    ].to_ber_sequence
  end

  def intermediate_packet(message_id, choice)
    content = [
      Net::LDAP::LDAPControls::SYNC_INFO.to_ber_contextspecific(0),
      choice,
    ].join
    body = raw_application(Net::LDAP::PDU::IntermediateResponse, content)
    raw_sequence([message_id.to_ber, body].join)
  end

  def refresh_choice(cookie, refresh_deletes, refresh_done)
    content = []
    content << cookie.to_ber_bin(0x80) if cookie
    content << context_boolean(refresh_done, 0x81)
    tag = refresh_deletes ? 0xA1 : 0xA2
    content.join.to_ber(tag)
  end

  def sync_id_set_choice(cookie, refresh_deletes, uuids)
    uuid_set = uuids.map { |id| id.to_ber_bin(0x80) }.to_ber_contextspecific(2)
    [
      cookie.to_ber_bin(0x80),
      context_boolean(refresh_deletes, 0x81),
      uuid_set,
    ].join.to_ber_contextspecific(3)
  end

  def refresh_required_packet(message_id)
    result_packet(message_id, Net::LDAP::ResultCodeSyncRefreshRequired)
  end

  def sync(connection, args = {})
    events = []
    result = connection.sync(args.merge(base: "dc=example,dc=com")) do |event|
      events << event
    end
    [result, events]
  end

  def context_boolean(value, tag)
    [tag, 1, value ? 0xFF : 0x00].pack("CCC")
  end

  def test_refresh_only_present_add_move_and_persistent_delete
    old_id = uuid(1)
    new_id = uuid(2)
    bytes =
      entry_packet(1, "cn=old,dc=example,dc=com", 0, old_id) +
      intermediate_packet(1, refresh_choice("present-cookie", false, true)) +
      entry_packet(1, "cn=new,dc=example,dc=com", 1, new_id, "add-cookie") +
      entry_packet(1, "cn=moved,dc=example,dc=com", 2, old_id, "move-cookie") +
      entry_packet(1, "", 3, new_id, "delete-cookie") +
      result_packet(1,
                    Net::LDAP::ResultCodeSuccess,
                    sync_done_control("done-cookie", false))
    conn, socket = connection(bytes)

    result, events = sync(conn, mode: :refreshOnly)

    assert result.success?
    assert_equal [:present, :refresh_present, :refresh_done, :add, :modify, :delete, :sync_done],
                 events.map(&:type)
    assert_equal "cn=moved,dc=example,dc=com", events[4].entry.dn
    assert_equal old_id, events[4].uuid
    assert_equal "done-cookie", events.last.cookie
    assert_equal 1, socket.written.scan("1.3.6.1.4.1.4203.1.9.1.1").length
  end

  def test_refresh_delete_does_not_emit_deletions_until_refresh_completes
    present_id = uuid(3)
    deleted_id = uuid(4)
    bytes =
      entry_packet(1, "cn=kept,dc=example,dc=com", 0, present_id) +
      intermediate_packet(1, sync_id_set_choice("set-cookie", true, [deleted_id])) +
      result_packet(1,
                    Net::LDAP::ResultCodeSuccess,
                    sync_done_control("done-cookie", true))
    conn, _socket = connection(bytes)
    events = []

    result = conn.sync(base: "dc=example,dc=com", mode: :refreshOnly) { |event| events << event }

    assert result.success?
    assert_equal [:present, :refresh_delete, :delete, :refresh_done, :sync_done],
                 events.map(&:type)
    assert_equal deleted_id, events[2].uuid
    assert_equal "done-cookie", events.last.cookie
    assert_equal true, events.last.refresh_deletes
  end

  def test_refresh_and_persist_stays_open_for_live_changes
    id = uuid(5)
    bytes =
      intermediate_packet(1, refresh_choice(nil, false, false)) +
      entry_packet(1, "cn=live,dc=example,dc=com", 0, id) +
      intermediate_packet(1, refresh_choice("refresh-complete", false, true)) +
      entry_packet(1, "cn=live2,dc=example,dc=com", 1, id, "live-cookie")
    conn, _socket = connection(bytes)
    events = []

    assert_raise Net::LDAP::ResponseMissingOrInvalidError do
      conn.sync(base: "dc=example,dc=com", mode: :refreshAndPersist) { |event| events << event }
    end
    assert_equal [:refresh_present, :refresh_done, :present, :add], events.map(&:type)
    assert_equal "live-cookie", events.last.cookie
  end

  def test_reconnect_resumes_with_last_applied_cookie
    id = uuid(6)
    first_bytes =
      entry_packet(1, "cn=one,dc=example,dc=com", 0, id, "first-cookie")
    second_bytes =
      entry_packet(1, "cn=one,dc=example,dc=com", 2, id, "second-cookie") +
      result_packet(1,
                    Net::LDAP::ResultCodeSuccess,
                    sync_done_control("second-done", false))
    first, first_socket = connection(first_bytes)
    second, second_socket = connection(second_bytes)
    saved_cookie = nil

    assert_raise Net::LDAP::ResponseMissingOrInvalidError do
      first.sync(base: "dc=example,dc=com", mode: :refreshAndPersist) do |event|
        saved_cookie = event.cookie if event.cookie
      end
    end
    result, _events = sync(second, mode: :refreshAndPersist, cookie: saved_cookie)

    assert result.success?
    assert_equal "first-cookie", saved_cookie
    assert_includes second_socket.written, "first-cookie"
  end

  def test_server_refresh_required_notifies_caller_to_rebuild_state
    conn, _socket = connection(refresh_required_packet(1))
    events = []

    result = conn.sync(base: "dc=example,dc=com", mode: :refreshOnly) { |event| events << event }

    refute result.success?
    assert_equal [:refresh_required], events.map(&:type)
    assert_equal true, events.first.reload_hint
  end

  def test_callback_failure_prevents_later_cookie_application
    first_id = uuid(7)
    bytes =
      entry_packet(1, "cn=first,dc=example,dc=com", 1, first_id, "first-cookie")
    conn, _socket = connection(bytes)
    seen = []

    assert_raise RuntimeError do
      conn.sync(base: "dc=example,dc=com", mode: :refreshAndPersist) do |event|
        seen << event
        raise "stop" if event.cookie == "first-cookie"
      end
    end
    assert_equal ["first-cookie"], seen.map(&:cookie).compact
  end

  def test_truncated_response_is_safe_to_resume_from_last_cookie
    id = uuid(9)
    bytes =
      entry_packet(1, "cn=safe,dc=example,dc=com", 1, id, "safe-cookie") +
      "\x30\x10\x02\x01\x01\x64"
    conn, _socket = connection(bytes)
    seen = []

    assert_raise Net::BER::BerError do
      conn.sync(base: "dc=example,dc=com", mode: :refreshAndPersist) { |event| seen << event }
    end
    assert_equal ["safe-cookie"], seen.map(&:cookie)
  end
end
