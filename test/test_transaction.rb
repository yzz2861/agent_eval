# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

# Tests the RFC 5805 block-form transaction API against a scripted socket
# stub. The stub records every BER request written to the wire and returns
# queued response PDUs, which lets us drive the four relevant timings:
# successful commit, cancel on block error, commit failure with failed
# requests/update controls, and a lost End Transaction response.
class TestLDAPTransactions < Test::Unit::TestCase
  TXN_ID = "txn-1".b

  class ScriptedSocket
    # Each queued item is a complete BER-encoded LDAP message (SEQUENCE of
    # message id, protocol op, optional controls).
    attr_reader :written
    attr_reader :responses

    def initialize(responses = [])
      @responses = responses.dup
      @written = []
    end

    def write(data)
      @written << data
      data.bytesize
    end


    # Returns the next complete BER message, or nil to simulate a closed /
    # silent connection (response lost).
    def read_ber(syntax = nil)
      return nil if @responses.empty?

      message = @responses.shift
      return nil if message.nil?

      message.read_ber(syntax)
    end

    def close
      @closed = true
    end

    def closed?
      @closed == true
    end
  end

  def setup
    @socket = ScriptedSocket.new
    @connection = Net::LDAP::Connection.new(:socket => @socket)
    @ldap = Net::LDAP.new(:host => "scripted.example", :port => 389)
    @ldap.connection = @connection
  end

  # -- PDU builders -------------------------------------------------------

  def ldap_result(code, dn = "", message = "")
    [code.to_ber_enumerated, dn.to_ber, message.to_ber]
  end

  def bind_result_message(message_id, code = 0)
    message(message_id, ldap_result(code).to_ber_appsequence(Net::LDAP::PDU::BindResult))
  end

  def add_response(message_id, code = 0)
    message(message_id, ldap_result(code).to_ber_appsequence(Net::LDAP::PDU::AddResponse))
  end

  def modify_response(message_id, code = 0)
    message(message_id, ldap_result(code).to_ber_appsequence(Net::LDAP::PDU::ModifyResponse))
  end

  def rename_response(message_id, code = 0)
    message(message_id, ldap_result(code).to_ber_appsequence(Net::LDAP::PDU::ModifyRDNResponse))
  end

  def delete_response(message_id, code = 0)
    message(message_id, ldap_result(code).to_ber_appsequence(Net::LDAP::PDU::DeleteResponse))
  end

  def extended_response(message_id, oid, code, message_text = "", value = nil)
    # RFC 4511: in ExtendedResponse responseName is context [10] and
    # responseValue is [11] (ExtendedRequest uses [0]/[1]).
    body = [oid.to_ber_contextspecific(10)]
    body << code.to_ber_enumerated
    body << "".to_ber
    body << message_text.to_ber
    body << value.to_ber_contextspecific(11) if value
    message(message_id, body.to_ber_appsequence(Net::LDAP::PDU::ExtendedResponse))
  end

  def start_response(message_id)
    value = [TXN_ID.to_ber_contextspecific(10)].to_ber_sequence
    extended_response(message_id, Net::LDAP::StartTransactionOid, 0, "", value)
  end

  # Builds an End Transaction response value naming one failed message id
  # and carrying an update control for it.
  def end_value(failed_message_id, control_oid = "1.3.6.1.4.1.4203.666.5.6")
    update_control = [
      context_integer(0, failed_message_id),
      # controls [0] Controls is a constructed context-specific field.
      [[
        control_oid.to_ber,
        true.to_ber,
        "update-control-value".to_ber,
      ].to_ber_sequence].to_ber_contextspecific(0),
    ].to_ber_sequence

    entries = []
    entries << context_integer(0, failed_message_id) unless @skip_top_level_message_id
    entries << [update_control].to_ber_contextspecific(1)
    entries.to_ber_sequence
  end

  def context_integer(tag, value)
    encoded = value.to_ber
    content = encoded.byteslice(2, encoded.bytesize - 2)
    [(0x80 + tag), content.length].pack("CC") + content
  end

  def message(message_id, protocol_op, controls = nil)
    [message_id.to_ber, protocol_op, controls].compact.to_ber_sequence
  end

  # Decodes a written BER message into [message_id, app_tag, raw_message].
  def decode_written(raw)
    # The End Transaction value includes a context-primitive [1] BOOLEAN
    # that Net::LDAP::AsnSyntax does not model, so a full decode raises.
    # Read the outer SEQUENCE, then just the message id INTEGER and the
    # application protocol-op tag directly from the raw TLVs.
    io = StringIO.new(raw)
    io.getbyte # outer SEQUENCE tag
    read_tlv_length(io) # outer SEQUENCE length
    io.getbyte # message id INTEGER tag
    message_id_length = read_tlv_length(io)
    message_id = integer_from_bytes(io.read(message_id_length))
    app_tag = io.getbyte & 0x1f
    read_tlv_length(io) # protocol-op length
    decoded =
      begin
        raw.read_ber(Net::LDAP::AsnSyntax)
      rescue Net::BER::BerError
        nil
      end
    [message_id, app_tag, decoded]
  end

  def read_tlv_length(io)
    first = io.getbyte
    return first if first <= 0x7f

    io.read(first & 0x7f).each_byte.reduce(0) { |value, byte| (value << 8) + byte }
  end

  def integer_from_bytes(bytes)
    bytes.each_byte.reduce(0) { |value, byte| (value << 8) + byte }
  end

  def app_tags_written
    @socket.written.map { |raw| decode_written(raw)[1] }
  end

  # Reads the controls attached to a written update request, returning the
  # parsed control OpenStructs.
  def controls_on(raw)
    message = raw.read_ber(Net::LDAP::AsnSyntax)
    return [] if message[2].nil?

    pdu = Net::LDAP::PDU.allocate
    pdu.instance_variable_set(:@ldap_controls, [])
    pdu.send(:parse_controls, message[2])
    pdu.result_controls
  end

  # -- Tests --------------------------------------------------------------

  def test_successful_transaction_uses_extended_start_and_end
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),       # Start Transaction
      add_response(2),         # add
      modify_response(3),      # modify
      extended_response(4, Net::LDAP::EndTransactionOid, 0),
    ])

    yielded = nil
    result = @ldap.transaction do |txn|
      yielded = txn
      @ldap.add(:dn => "cn=a", :attributes => { :cn => "a" })
      @ldap.modify(:dn => "cn=a", :operations => [[:replace, :sn, "A"]])
    end

    assert_same(yielded, result)
    tags = app_tags_written
    assert_equal(
      [Net::LDAP::PDU::ExtendedRequest,   # start
       Net::LDAP::PDU::AddRequest,
       Net::LDAP::PDU::ModifyRequest,
       Net::LDAP::PDU::ExtendedRequest],  # end
      tags
    )

    # Every participating operation carries the transaction spec control
    # with the identifier returned by Start Transaction.
    add_raw = @socket.written.find do |raw|
      decode_written(raw)[1] == Net::LDAP::PDU::AddRequest
    end
    add_controls = controls_on(add_raw)
    assert_equal(
      [Net::LDAP::LDAPControls::TRANSACTION_SPECIFICATION],
      add_controls.map(&:oid)
    )
    assert_equal(true, add_controls.first.criticality)
    assert_equal(TXN_ID, add_controls.first.value)

    modify_raw = @socket.written.find do |raw|
      decode_written(raw)[1] == Net::LDAP::PDU::ModifyRequest
    end
    modify_controls = controls_on(modify_raw)
    assert_equal(
      [Net::LDAP::LDAPControls::TRANSACTION_SPECIFICATION],
      modify_controls.map(&:oid)
    )

    assert(result.committed?)
    assert_equal([:add, :modify], result.operations.map { |op| op[:operation] })
    assert_equal([2, 3], result.operations.map { |op| op[:message_id] })
    assert_equal(4, result.end_message_id)

    # The final extended request is a commit (commit=TRUE).
    end_raw = @socket.written.last
    commit_index = end_raw.index([0x81, 0x01].pack("CC"))
    refute_nil(commit_index)
    assert_equal(0xFF, end_raw.getbyte(commit_index + 2))

    # And it names the Start Transaction request's message id.
    start_ref_index = end_raw.index([0x80, 0x01, 0x01].pack("CCC"))
    refute_nil(start_ref_index)
  end

  def test_transaction_pins_one_connection_for_all_operations
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      add_response(2),
      rename_response(3),
      delete_response(4),
      extended_response(5, Net::LDAP::EndTransactionOid, 0),
    ])

    @ldap.transaction do
      @ldap.add(:dn => "cn=a", :attributes => { :cn => "a" })
      @ldap.rename(:olddn => "cn=a", :newrdn => "cn=b")
      @ldap.delete(:dn => "cn=b")
    end

    # All requests share the single scripted connection: message ids are
    # contiguous and everything went to the same socket.
    assert_equal(
      [1, 2, 3, 4, 5],
      @socket.written.map { |raw| decode_written(raw)[0] }
    )

    rename_raw = @socket.written.find do |raw|
      decode_written(raw)[1] == Net::LDAP::PDU::ModifyRDNRequest
    end
    rename_controls = controls_on(rename_raw)
    assert_equal(
      [Net::LDAP::LDAPControls::TRANSACTION_SPECIFICATION],
      rename_controls.map(&:oid)
    )

    # The pinned connection is still open while the transaction has just
    # committed (the stub is reused via @ldap.connection=, not auto-closed).
    refute_predicate(@socket, :closed?)
  end

  def test_other_thread_cannot_borrow_the_transaction_connection
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      extended_response(2, Net::LDAP::EndTransactionOid, 0),
    ])

    inside_transaction = Queue.new
    attempt_result = Queue.new

    t = Thread.new do
      @ldap.transaction do
        inside_transaction << true
        # Wait until the main thread's attempt has completed before
        # committing, so the foreign operation races the open transaction.
        attempt_result.pop
      end
    end

    inside_transaction.pop
    error = nil
    begin
      @connection.assert_transaction_owner!
    rescue Net::LDAP::TransactionInProgressError
      error = $!
    end
    assert_kind_of(Net::LDAP::TransactionInProgressError, error)

    # No foreign request must have reached the pinned connection.
    assert_equal(
      [Net::LDAP::PDU::ExtendedRequest],
      app_tags_written
    )

    attempt_result << true
    t.join
  end


  def test_nested_transaction_rejected_before_second_start
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      extended_response(2, Net::LDAP::EndTransactionOid, 0),
    ])

    @ldap.transaction do
      assert_raise(Net::LDAP::TransactionAlreadyActiveError) do
        @ldap.transaction do
          flunk "nested block must never run"
        end
      end
    end

    # Only one Start Transaction request must ever be sent.
    # ExtendedRequest (app tag 23) is not in Net::LDAP::AsnSyntax, so count
    # the OIDs directly in the written bytes. The nested call is rejected
    # before the wire is touched.
    start_oid_bytes = Net::LDAP::StartTransactionOid
    end_oid_bytes = Net::LDAP::EndTransactionOid
    all_bytes = @socket.written.join
    assert_equal(1, all_bytes.scan(start_oid_bytes).length)
    assert_equal(1, all_bytes.scan(end_oid_bytes).length)
  end

  def test_block_exception_cancels_and_reraises
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      add_response(2),
      extended_response(3, Net::LDAP::EndTransactionOid, 0),
    ])

    error = assert_raise(RuntimeError) do
      @ldap.transaction do
        @ldap.add(:dn => "cn=a", :attributes => { :cn => "a" })
        raise "boom"
      end
    end
    assert_equal("boom", error.message)

    # The final extended request must be an abort: commit=FALSE.
    end_raw = @socket.written.last
    # EndTransactionRequestValue ::= SEQUENCE { messageID [0], commit [1]
    # BOOLEAN }. ExtendedRequest (app 23) is not in Net::LDAP::AsnSyntax, so
    # locate the commit [1] tag (0x81) and read its single content byte.
    commit_index = end_raw.index([0x81, 0x01].pack("CC"))
    refute_nil(commit_index)
    assert_equal(0x00, end_raw.getbyte(commit_index + 2))
  end

  def test_commit_failure_associates_failed_request_and_update_control
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      add_response(2),
      modify_response(3),
      extended_response(
        4, Net::LDAP::EndTransactionOid, 1, "commit conflict",
        end_value(2)
      ),
    ])

    error = assert_raise(Net::LDAP::TransactionCommitError) do
      @ldap.transaction do
        @ldap.add(:dn => "cn=a", :attributes => { :cn => "a" })
        @ldap.modify(:dn => "cn=a", :operations => [[:replace, :sn, "A"]])
      end
    end

    assert_equal(1, error.result_code)
    assert_equal("commit conflict", error.error_message)
    assert_equal(1, error.failed_operations.length)

    failed = error.failed_operations.first
    assert_equal(2, failed[:message_id])
    assert_equal(:add, failed[:operation])
    assert_equal("cn=a", failed[:args][:dn])
    assert_kind_of(Net::LDAP::PDU, failed[:pdu])
    assert_equal(1, failed[:controls].length)
    assert_equal("1.3.6.1.4.1.4203.666.5.6", failed[:controls].first.oid)
    assert_equal("update-control-value", failed[:controls].first.value)
  end

  def test_commit_failure_correlates_from_update_control_only
    @skip_top_level_message_id = true
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      modify_response(2),
      extended_response(
        3, Net::LDAP::EndTransactionOid, 1, "conflict", end_value(2)
      ),
    ])

    error = assert_raise(Net::LDAP::TransactionCommitError) do
      @ldap.transaction do
        @ldap.modify(:dn => "cn=a", :operations => [[:replace, :sn, "A"]])
      end
    end

    assert_equal(1, error.failed_operations.length)
    failed = error.failed_operations.first
    assert_equal(2, failed[:message_id])
    assert_equal(:modify, failed[:operation])
    assert_equal(1, failed[:controls].length)
  ensure
    @skip_top_level_message_id = false
  end

  def test_lost_commit_response_raises_unknown_without_replay
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      add_response(2),
      nil, # connection drops right after End Transaction
    ])

    write_count_before = nil
    error = assert_raise(Net::LDAP::TransactionResultUnknownError) do
      @ldap.transaction do
        @ldap.add(:dn => "cn=a", :attributes => { :cn => "a" })
        write_count_before = @socket.written.length
      end
    end

    assert_predicate(error, :commit?)
    assert_equal(1, error.operations.length)
    assert_equal(:add, error.operations.first[:operation])

    # Only the original Start/add/End requests: the block is not replayed.
    assert_equal(write_count_before + 1, @socket.written.length)
  end

  def test_lost_abort_response_keeps_original_block_error
    @socket.instance_variable_get(:@responses).concat([
      start_response(1),
      add_response(2),
      nil, # abort response lost
    ])

    error = assert_raise(RuntimeError) do
      @ldap.transaction do
        @ldap.add(:dn => "cn=a", :attributes => { :cn => "a" })
        raise "rollback-me"
      end
    end
    assert_equal("rollback-me", error.message)
    assert_kind_of(
      Net::LDAP::TransactionResultUnknownError,
      error.ldap_abort_error
    )
    refute_predicate(error.ldap_abort_error, :commit?)
  end

  def test_requires_a_block
    assert_raise(ArgumentError) { @ldap.transaction }
  end

  def test_start_failure_does_not_open_block
    @socket.instance_variable_get(:@responses).concat([
      extended_response(
        1, Net::LDAP::StartTransactionOid,
        Net::LDAP::ResultCodeUnwillingToPerform, "not supported"
      ),
    ])

    entered = false
    assert_raise(Net::LDAP::TransactionStartError) do
      @ldap.transaction { entered = true }
    end
    refute(entered)
  end

  def test_failed_bind_before_start_closes_connection_and_raises
    socket = ScriptedSocket.new([
      bind_result_message(1, Net::LDAP::ResultCodeInvalidCredentials),
    ])
    connection = Net::LDAP::Connection.new(:socket => socket)
    flexmock(Net::LDAP::Connection)
      .should_receive(:new)
      .and_return(connection)

    ldap = Net::LDAP.new(
      :host => "scripted.example",
      :port => 389,
      :auth => { :method => :simple, :username => "u", :password => "p" }
    )

    assert_raise(Net::LDAP::TransactionStartError) do
      ldap.transaction { flunk "block must not run" }
    end
    assert_predicate(socket, :closed?)
    # No Start Transaction request after the failed bind.
    tags = socket.written.map { |raw| decode_written(raw)[1] }
    assert_equal([Net::LDAP::PDU::BindRequest], tags)
  end

  def test_start_returns_unexpected_pdu_type
    @socket.instance_variable_get(:@responses).concat([
      message(1, ldap_result(0).to_ber_appsequence(Net::LDAP::PDU::BindResult)),
    ])

    entered = false
    assert_raise(Net::LDAP::ResponseMissingOrInvalidError) do
      @ldap.transaction { entered = true }
    end
    refute(entered)
  end

  def test_block_operations_share_the_connection_opened_by_transaction
    # No #connection= assignment: the transaction must open one connection,
    # bind, Start, run all block updates on that connection, commit, and
    # close it.
    socket = ScriptedSocket.new([
      bind_result_message(1),
      start_response(2),
      add_response(3),
      extended_response(4, Net::LDAP::EndTransactionOid, 0),
    ])
    ldap = Net::LDAP.new(
      :host => "scripted.example",
      :port => 389,
      :auth => { :method => :simple, :username => "u", :password => "p" }
    )
    connection = Net::LDAP::Connection.new(:socket => socket)
    flexmock(Net::LDAP::Connection)
      .should_receive(:new)
      .and_return(connection)

    txn = ldap.transaction do
      ldap.add(:dn => "cn=a", :attributes => { :cn => "a" })
    end

    assert(txn.committed?)
    assert_predicate(socket, :closed?)
    tags = socket.written.map { |raw| decode_written(raw)[1] }
    assert_equal(
      [Net::LDAP::PDU::BindRequest,
       Net::LDAP::PDU::ExtendedRequest,
       Net::LDAP::PDU::AddRequest,
       Net::LDAP::PDU::ExtendedRequest],
      tags
    )
  end
end
