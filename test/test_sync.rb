require_relative 'test_helper'
require 'stringio'

class TestLDAPSync < Test::Unit::TestCase
  class RecordedSocket
    attr_reader :requests

    def initialize(*responses)
      @read_io = StringIO.new(responses.join)
      @write_io = StringIO.new
      @requests = []
    end

    def write(data)
      @requests << data
      data.length
    end

    def read_ber(syntax = nil)
      @read_io.read_ber(syntax)
    end

    def close
    end
  end

  def control(oid, value = nil, criticality = true)
    fields = [Net::LDAP::Sync.oid_ber(oid)]
    fields << criticality.to_ber
    fields << value.to_s.to_ber if value
    fields.to_ber_sequence
  end

  def message(id, body, controls = nil)
    [id.to_ber, body, controls].compact.to_ber_sequence
  end

  def entry_body(dn, uuid)
    content = [dn.to_ber, [
      ['entryUUID'.to_ber, [uuid.to_ber].to_ber_set].to_ber_sequence,
      ['cn'.to_ber, [File.basename(dn, ',*').to_ber].to_ber_set].to_ber_sequence,
    ].to_ber_sequence].join
    [0x64].pack('C') + content.length.to_ber_length_encoding + content
  end

  def entry_message(dn, uuid, state, cookie = nil)
    value = [state.to_ber_enumerated, uuid.to_ber]
    value << cookie.to_ber if cookie
    controls = [
      control(Net::LDAP::Sync::STATE_OID, value.to_ber_sequence),
    ].to_ber_contextspecific(0)
    body = entry_body(dn, uuid)
    content = 1.to_ber + body + controls
    [0x30].pack('C') + content.length.to_ber_length_encoding + content
  end

  def intermediate(info_value)
    body = [''.to_ber, ''.to_ber].to_ber_appsequence(Net::LDAP::PDU::IntermediateResponse)
    controls = [
      control(Net::LDAP::Sync::INFO_OID, info_value.to_s),
    ].to_ber_contextspecific(0)
    message(1, body, controls)
  end

  def refresh_present(cookie, refresh_done: nil)
    content = cookie.to_ber_contextspecific(0)
    content += context_boolean(refresh_done, 2) unless refresh_done.nil?
    intermediate([0xa2].pack('C') + content.length.to_ber_length_encoding + content)
  end

  def refresh_delete(cookie, refresh_done: nil)
    content = cookie.to_ber_contextspecific(0)
    content += context_boolean(refresh_done, 1) unless refresh_done.nil?
    intermediate([0xa1].pack('C') + content.length.to_ber_length_encoding + content)
  end

  def sync_id_set(cookie, uuids, deletes)
    content = cookie.to_ber_contextspecific(0)
    content += context_boolean(deletes, 1)
    content += uuids.map(&:to_ber).to_ber_contextspecific(2) if uuids
    intermediate([0xa3].pack('C') + content.length.to_ber_length_encoding + content)
  end

  def new_cookie(cookie)
    intermediate(cookie.to_ber_contextspecific(0).to_s)
  end

  def context_boolean(value, code)
    [(0x80 + code), 1, value ? 0xFF : 0x00].pack('CCC')
  end

  def search_done(cookie, refresh_deletes, code = Net::LDAP::ResultCodeSuccess)
    value = [refresh_deletes.to_ber]
    value << cookie.to_ber if cookie
    controls = [
      control(Net::LDAP::Sync::DONE_OID, value.to_ber_sequence),
    ].to_ber_contextspecific(0)
    body = [
      code.to_ber_enumerated,
      ''.to_ber,
      ''.to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchResult)
    message(1, body, controls)
  end

  def connection(*responses)
    socket = RecordedSocket.new(*responses)
    Net::LDAP::Connection.new(socket: socket)
  end

  def event_types(events)
    events.map { |event| event[:type] }
  end

  def assert_sync_request(bytes, mode, cookie = nil)
    packet = StringIO.new(bytes).read_ber(Net::LDAP::AsnSyntax)
    sync = packet[2].first
    assert_equal Net::LDAP::Sync::OID, Net::LDAP::Sync.oid(sync[0])
    assert_equal true, sync[1]
    value = sync[2].read_ber(Net::LDAP::Sync::SyncSyntax)
    assert_equal mode, value[0]
    assert_equal cookie, value[1] if cookie
  end

  def test_refresh_only_present_add_move_and_delete_events
    original_dn = 'cn=User,ou=old,dc=example,dc=org'
    moved_dn = 'cn=User,ou=people,dc=example,dc=org'
    bytes = [
      refresh_present('before', refresh_done: false),
      entry_message(original_dn, 'uuid-1', Net::LDAP::Sync::STATE_PRESENT, 'present-cookie'),
      entry_message('cn=New,dc=example,dc=org', 'uuid-2', Net::LDAP::Sync::STATE_ADD, 'add-cookie'),
      entry_message(moved_dn, 'uuid-1', Net::LDAP::Sync::STATE_MODIFY, 'move-cookie'),
      entry_message(original_dn, 'uuid-3', Net::LDAP::Sync::STATE_DELETE, 'delete-cookie'),
      search_done('done-cookie', false),
    ].join
    conn = connection(bytes)
    events = []

    result = conn.synchronize(base: 'dc=example,dc=org', mode: :refresh_only) do |event|
      events << event
    end

    assert_equal(%i[refresh_start present add modify delete refresh_complete], event_types(events))
    assert_equal('uuid-1', events[3][:entry_uuid])
    assert_equal(moved_dn, events[3][:dn])
    assert_equal('done-cookie', result[:cookie])
    assert_sync_request(conn.socket.requests.first, Net::LDAP::Sync::REFRESH_ONLY)
  end

  def test_refresh_and_persist_completes_then_streams_and_reconnects
    first = [
      refresh_present('before', refresh_done: false),
      entry_message('cn=User,dc=example,dc=org', 'uuid-1', Net::LDAP::Sync::STATE_ADD, 'add-cookie'),
      new_cookie('refresh-cookie'),
      sync_id_set('persist-cookie', ['uuid-2'], false),
    ].join
    second = [
      sync_id_set('final-cookie', ['uuid-1'], true),
    ].join
    sockets = [RecordedSocket.new(first), RecordedSocket.new(second)]
    conns = [Net::LDAP::Connection.new(socket: sockets[0]), Net::LDAP::Connection.new(socket: sockets[1])]
    events = []
    calls = 0

    result = loop do
      result = conns[calls].synchronize(
        base: 'dc=example,dc=org',
        mode: :refresh_and_persist,
        cookie: calls.zero? ? nil : 'persist-cookie',
      ) { |event| events << event }
      calls += 1
      break result if calls == conns.length
    end

    assert_equal(%i[refresh_start add refresh_complete modify_ids delete_ids], event_types(events))
    assert_equal(%w[uuid-2], events[3][:entry_uuids])
    assert_equal(%w[uuid-1], events[4][:entry_uuids])
    assert_equal('final-cookie', result[:cookie])
    assert_sync_request(sockets[0].requests.first, Net::LDAP::Sync::REFRESH_AND_PERSIST)
    assert_sync_request(sockets[1].requests.first, Net::LDAP::Sync::REFRESH_AND_PERSIST, 'persist-cookie')
  end

  def test_refresh_delete_path_is_distinct
    bytes = [
      refresh_delete('before', refresh_done: false),
      entry_message('cn=User,dc=example,dc=org', 'uuid-1', Net::LDAP::Sync::STATE_PRESENT),
      search_done('delete-done-cookie', true),
    ].join
    events = []

    result = connection(bytes).synchronize(base: 'dc=example,dc=org') do |event|
      events << event
    end

    assert_equal(%i[refresh_start present refresh_complete], event_types(events))
    assert_equal(:refresh_delete, events.first[:phase])
    assert_equal(true, events.first[:refresh_deletes])
    assert_equal(true, events.last[:refresh_deletes])
    assert_equal('delete-done-cookie', result[:cookie])
  end

  def test_present_phase_does_not_imply_deletions
    bytes = [
      refresh_present('before', refresh_done: false),
      entry_message('cn=User,dc=example,dc=org', 'uuid-1', Net::LDAP::Sync::STATE_PRESENT),
      search_done('present-done-cookie', false),
    ].join
    events = []

    result = connection(bytes).synchronize(base: 'dc=example,dc=org') do |event|
      events << event
    end

    assert_equal(%i[refresh_start present refresh_complete], event_types(events))
    assert_equal(false, events.last[:refresh_deletes])
    assert_not_include(events.map(&:keys).flatten, :delete)
    assert_equal('present-done-cookie', result[:cookie])
  end

  def test_callback_failure_keeps_cookie_at_last_applied_event
    bytes = [
      refresh_present('before', refresh_done: false),
      entry_message('cn=First,dc=example,dc=org', 'uuid-1', Net::LDAP::Sync::STATE_ADD, 'first-cookie'),
      entry_message('cn=Second,dc=example,dc=org', 'uuid-2', Net::LDAP::Sync::STATE_ADD, 'second-cookie'),
      search_done('done-cookie', false),
    ].join
    applied = []

    assert_raise(RuntimeError) do
      connection(bytes).synchronize(base: 'dc=example,dc=org') do |event|
        applied << event
        raise 'stop' if event[:type] == :add && event[:entry_uuid] == 'uuid-2'
      end
    end

    assert_equal(%w[uuid-1 uuid-2], applied.select { |event| event[:type] == :add }.map { |event| event[:entry_uuid] })
    handler = Net::LDAP::Sync::Handler.new(->(_event) {})
    assert_nil(handler.acknowledged_cookie)
  end

  def test_sync_refresh_required_notifies_caller
    bytes = [
      search_done('stale-cookie', true, Net::LDAP::ResultCodeSyncRefreshRequired),
    ].join
    events = []

    result = connection(bytes).synchronize(base: 'dc=example,dc=org', cookie: 'old-cookie') do |event|
      events << event
    end

    assert_equal([:refresh_required], event_types(events))
    assert_equal(true, events.first[:refresh_deletes])
    assert_equal('stale-cookie', events.first[:cookie])
    assert_equal(:refresh_required, result[:status])
  end

  def test_halfway_truncation_does_not_complete_or_advance_cookie
    full = [
      refresh_present('before', refresh_done: false),
      entry_message('cn=User,dc=example,dc=org', 'uuid-1', Net::LDAP::Sync::STATE_ADD, 'entry-cookie'),
      search_done('done-cookie', false),
    ].join
    bytes = full.byteslice(0, full.bytesize - 4)
    events = []

    assert_raise(Net::LDAP::Sync::TruncatedError) do
      connection(bytes).synchronize(base: 'dc=example,dc=org') do |event|
        events << event
      end
    end

    assert_equal(%i[refresh_start add], event_types(events))
    assert_not_equal('done-cookie', events.last[:cookie])
  end
end
