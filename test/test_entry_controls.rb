require_relative 'test_helper'
require_relative 'support/fake_ldap_server'

# End-to-end tests for the RFC 4528 Assertion Control and RFC 4527
# Pre-/Post-Read controls over modify/rename/delete.  The fake server is
# reached over a socket pair and never answers a SearchRequest, proving
# the guarded write does not degrade into search-then-modify.
class TestEntryControls < Test::Unit::TestCase
  DN = "uid=user1,ou=People,dc=example,dc=org"

  INITIAL_ENTRY = {
    "uid"         => ["user1"],
    "cn"          => ["George Smith"],
    "sn"          => ["Smith"],
    "objectclass" => ["top", "person"],
    "jpegPhoto"   => ["\xff\xd8\x00".b],
  }.freeze

  def setup
    @server = FakeLDAPServer.new(DN => INITIAL_ENTRY.dup)
  end

  def teardown
    @client&.close rescue nil
    @server.join rescue nil
  end

  def connection
    @client, remote = Socket.pair(:UNIX, :STREAM, 0)
    @server.serve(@client, remote)
    Net::LDAP::Connection.new(:socket => @client)
  end

  def make_ldap
    conn = connection
    ldap = Net::LDAP.new
    ldap.connection = conn
    ldap
  end

  def test_modify_sends_assertion_and_read_controls_in_one_request
    conn = connection
    pdu = conn.modify(
      :dn => DN,
      :operations => [[:replace, "sn", ["Jones"]]],
      :assertion => Net::LDAP::Filter.eq("sn", "Smith"),
      :pre_read => [:sn],
      :post_read => [:sn])

    assert pdu.success?
    assert_equal ["Smith"], pdu.pre_read_entry.sn
    assert_equal ["Jones"], pdu.post_read_entry.sn

    # Exactly one request, and it was the modify itself - no search.
    assert_equal [FakeLDAPServer::MODIFY_REQUEST], @server.received_tags
  end

  def test_modify_with_assertion_failure_is_reported_distinctly
    conn = connection
    pdu = conn.modify(
      :dn => DN,
      :operations => [[:replace, "sn", ["Jones"]]],
      :assertion => Net::LDAP::Filter.eq("sn", "DoesNotExist"),
      :pre_read => true)

    assert pdu.assertion_failed?
    refute pdu.success?
    assert_equal Net::LDAP::ResultCodeAssertionFailed, pdu.result_code
    # Pre-read reflects the entry the assertion was evaluated against.
    assert_equal DN, pdu.pre_read_entry.dn
  end

  def test_assertion_guards_against_entry_changed_between_ui_read_and_write
    # Simulate another client changing sn after the UI showed "Smith".
    @server.mutate_after_request(DN) do |entries|
      entries[DN]["sn"] = ["SomeoneElse"]
    end

    client = make_ldap
    result = client.modify(
      :dn => DN,
      :operations => [[:replace, "sn", ["Jones"]]],
      :assertion => Net::LDAP::Filter.eq("sn", "Smith"),
      :pre_read => true)

    refute result
    operation = client.get_operation_result
    assert operation.assertion_failed
    assert_equal Net::LDAP::ResultCodeAssertionFailed, operation.code
    # The atomic pre-read shows the changed value, not the stale UI value.
    assert_equal ["SomeoneElse"], operation.pre_read_entry.sn

    # The guard rode on the modify request; there is no extra search window.
    assert_equal [FakeLDAPServer::MODIFY_REQUEST], @server.received_tags
  end

  def test_binary_attribute_survives_pre_and_post_read
    conn = connection
    new_photo = "\x89PNG\r\n\x1a\n".b
    pdu = conn.modify(
      :dn => DN,
      :operations => [[:replace, "jpegPhoto", [new_photo]]],
      :assertion => Net::LDAP::Filter.present("objectclass"),
      :pre_read => ["jpegPhoto"],
      :post_read => ["jpegPhoto"])

    assert pdu.success?
    assert_equal ["\xff\xd8\x00".b], pdu.pre_read_entry.jpegPhoto
    assert_equal [new_photo], pdu.post_read_entry.jpegPhoto
    assert_equal Encoding::BINARY,
                 pdu.post_read_entry.jpegPhoto.first.encoding
  end

  def test_multiple_response_controls_are_all_preserved
    conn = connection
    # Inject a second response control alongside pre/post read.
    def (@server = @server).controls_for(dn, pre, post, before = nil,
                                         after = nil, post_dn = dn)
      controls = super(dn, pre, post, before, after, post_dn)
      controls << ["9.9.9.9".to_ber, true.to_ber,
                   [1.to_ber].to_ber_sequence.to_s.to_ber].to_ber_sequence
      controls
    end

    pdu = conn.modify(
      :dn => DN,
      :operations => [[:replace, "sn", ["Jones"]]],
      :pre_read => true,
      :post_read => true)

    assert pdu.success?
    oids = pdu.result_controls.map(&:oid)
    assert_include oids, Net::LDAP::LDAPControls::PRE_READ_ENTRY
    assert_include oids, Net::LDAP::LDAPControls::POST_READ_ENTRY
    assert_include oids, "9.9.9.9"
    assert_equal 3, pdu.result_controls.length
  end

  def test_rename_carries_pre_and_post_read_controls
    conn = connection
    pdu = conn.rename(
      :olddn => DN,
      :newrdn => "uid=user2",
      :assertion => Net::LDAP::Filter.eq("sn", "Smith"),
      :pre_read => [:sn],
      :post_read => [:sn])

    assert pdu.success?
    assert_equal ["Smith"], pdu.pre_read_entry.sn
    assert pdu.post_read_entry.dn.start_with?("uid=user2,")
    assert_equal [FakeLDAPServer::MODIFY_RDN_REQUEST], @server.received_tags
  end

  def test_rename_post_read_returns_server_final_dn
    conn = connection
    pdu = conn.rename(
      :olddn => DN,
      :newrdn => "uid=renamed",
      :post_read => [:uid])

    assert pdu.success?
    assert_equal "uid=renamed,ou=People,dc=example,dc=org",
                 pdu.post_read_entry.dn
  end

  def test_delete_supports_assertion_and_pre_read
    conn = connection
    pdu = conn.delete(
      :dn => DN,
      :assertion => Net::LDAP::Filter.eq("sn", "Smith"),
      :pre_read => [:sn, :jpegPhoto])

    assert pdu.success?
    assert_equal ["Smith"], pdu.pre_read_entry.sn
    assert_equal ["\xff\xd8\x00".b], pdu.pre_read_entry.jpegPhoto
    assert_nil pdu.post_read_entry
    assert_equal [FakeLDAPServer::DELETE_REQUEST], @server.received_tags
  end

  def test_delete_rejects_post_read_client_side
    conn = connection
    assert_raise(Net::LDAP::ControlError) do
      conn.delete(:dn => DN, :post_read => true)
    end
    # Nothing was sent to the server.
    assert_equal [], @server.received_tags
  end

  def test_delete_assertion_failure_leaves_entry_in_place
    @server.mutate_after_request(DN) do |entries|
      entries[DN]["sn"] = ["Changed"]
    end
    conn = connection
    pdu = conn.delete(
      :dn => DN,
      :assertion => Net::LDAP::Filter.eq("sn", "Smith"),
      :pre_read => true)

    assert pdu.assertion_failed?
    assert_equal ["Changed"], pdu.pre_read_entry.sn
    assert_equal [FakeLDAPServer::DELETE_REQUEST], @server.received_tags
  end

  def test_public_api_surfaces_assertion_failure_and_entries
    client = make_ldap
    ok = client.modify(
      :dn => DN,
      :operations => [[:replace, "cn", ["G. Smith"]]],
      :pre_read => [:cn],
      :post_read => [:cn])

    assert ok
    result = client.get_operation_result
    refute result.assertion_failed
    assert_equal ["George Smith"], result.pre_read_entry.cn
    assert_equal ["G. Smith"], result.post_read_entry.cn
  end

  def test_unsupported_critical_control_fails_without_fallback
    conn = connection
    # Teach the fake server to reject the assertion control as unsupported.
    @server.define_singleton_method(:handle_modify) do |message_id, request, controls|
      if controls.key?(FakeLDAPServer::ASSERTION_OID)
        send_result(message_id, FakeLDAPServer::MODIFY_RESPONSE,
                    FakeLDAPServer::UNAVAILABLE_CRITICAL_EXT,
                    request[0], "unsupported control")
      else
        super(message_id, request, controls)
      end
    end

    pdu = conn.modify(
      :dn => DN,
      :operations => [[:replace, "sn", ["Jones"]]],
      :assertion => Net::LDAP::Filter.eq("sn", "Smith"))

    refute pdu.success?
    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension,
                 pdu.result_code
  end

  def test_connection_modify_includes_assertion_control_on_wire
    conn = connection
    captured = nil
    conn.define_singleton_method(:write) do |request, controls, message_id|
      captured = controls
      super(request, controls, message_id)
    end

    conn.modify(
      :dn => DN,
      :operations => [[:replace, "sn", ["Jones"]]],
      :assertion => Net::LDAP::Filter.eq("sn", "Smith"),
      :pre_read => [:sn])

    controls = captured.read_ber(Net::LDAP::AsnSyntax)
    oids = controls.map(&:first)
    assert_include oids, Net::LDAP::LDAPControls::ASSERTION
    assert_include oids, Net::LDAP::LDAPControls::PRE_READ_ENTRY

    assertion = controls.find { |c| c.first == Net::LDAP::LDAPControls::ASSERTION }
    # RFC 4528: criticality MUST be true.
    assert_equal true, assertion[1]
  end

end
