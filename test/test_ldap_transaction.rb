require_relative 'test_helper'

class TestLDAPTransaction < Test::Unit::TestCase
  # A stub socket that records written packets and replays queued
  # responses, so transaction timings can be exercised without a
  # server. When responses run out, read_ber returns nil, simulating a
  # connection that dropped before the server answered.
  class StubSocket
    attr_reader :written

    def initialize
      @written = []
      @responses = []
      @closed = false
    end

    def queue_response(response)
      @responses << response
    end

    def write(packet)
      @written << packet
      packet.bytesize
    end

    def read_ber(_syntax = nil)
      @responses.shift
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  EXTENDED_REQUEST_SYNTAX = Net::BER.compile_syntax(
    :application => { :constructed => { Net::LDAP::PDU::ExtendedRequest => :array } },
    :context_specific => { :primitive => { 0 => :string, 1 => :string } }
  )

  USER_DN = "uid=jdoe,ou=people,dc=example,dc=org"

  def setup
    @socket = StubSocket.new
    @connection = Net::LDAP::Connection.new(:socket => @socket)
    @ldap = Net::LDAP.new
    @ldap.connection = @connection
  end

  def make_pdu(message_id, app_tag, code: Net::LDAP::ResultCodeSuccess,
               error_message: "", response_value: nil)
    content = [code, "", error_message]
    content << response_value unless response_value.nil?
    ber = Net::BER::BerIdentifiedArray.new(content)
    ber.ber_identifier = app_tag
    [message_id, ber]
  end

  def queue_start_transaction(message_id, identifier = "txn-1")
    @socket.queue_response(
      make_pdu(message_id, Net::LDAP::PDU::ExtendedResponse,
               :response_value => identifier.to_ber))
  end

  def queue_end_transaction(message_id, code: Net::LDAP::ResultCodeSuccess,
                            response_value: nil)
    @socket.queue_response(
      make_pdu(message_id, Net::LDAP::PDU::ExtendedResponse,
               :code => code, :response_value => response_value))
  end

  # Decodes a written ExtendedRequest packet into
  # [message_id, request_name, raw_request_value].
  def decode_extended_request(packet)
    message_id, request = packet.read_ber(EXTENDED_REQUEST_SYNTAX)
    [message_id, request[0], request[1]]
  end

  # Decodes a written End Transaction request into
  # [message_id, request_name, commit, identifier].
  def decode_end_txn_request(packet)
    message_id, name, value = decode_extended_request(packet)
    elements = value.read_ber
    if elements.length == 2
      commit, identifier = elements
    else
      # commit DEFAULT TRUE is omitted from the encoding
      commit, identifier = true, elements[0]
    end
    [message_id, name, commit, identifier]
  end

  # Decodes the controls attached to a written request packet.
  def decode_controls(packet, app_tag)
    syntax = Net::BER.compile_syntax(
      :application => { :constructed => { app_tag => :array } },
      :context_specific => { :constructed => { 0 => :array } }
    )
    _message_id, _request, controls = packet.read_ber(syntax)
    controls
  end

  def test_transaction_commits_updates_on_a_single_connection
    queue_start_transaction(1)
    @socket.queue_response(make_pdu(2, Net::LDAP::PDU::AddResponse))
    @socket.queue_response(make_pdu(3, Net::LDAP::PDU::ModifyResponse))
    @socket.queue_response(make_pdu(4, Net::LDAP::PDU::ModifyRDNResponse))
    queue_end_transaction(5)

    result = @ldap.transaction do |txn|
      assert txn.add(:dn => USER_DN,
                     :attributes => { :cn => "J Doe", :sn => "Doe",
                                      :objectclass => %w(top inetorgperson) })
      assert txn.modify(:dn => USER_DN,
                        :operations => [[:add, :mail, "jdoe@example.com"]])
      assert txn.rename(:olddn => USER_DN, :newrdn => "uid=john.doe")
    end

    assert_equal true, result
    assert_equal 5, @socket.written.size

    # Start Transaction extended request.
    message_id, name, value = decode_extended_request(@socket.written[0])
    assert_equal 1, message_id
    assert_equal Net::LDAP::StartTransactionOid, name
    assert_nil value

    # Each update operation carries the Transaction Specification
    # control with the identifier returned by the server.
    {
      1 => Net::LDAP::PDU::AddRequest,
      2 => Net::LDAP::PDU::ModifyRequest,
      3 => Net::LDAP::PDU::ModifyRDNRequest,
    }.each do |index, app_tag|
      controls = decode_controls(@socket.written[index], app_tag)
      assert_equal 1, controls.length
      oid, criticality, control_value = controls.first
      assert_equal Net::LDAP::LDAPControls::TRANSACTION_SPEC, oid
      assert_equal true, criticality
      assert_equal "txn-1", control_value.read_ber
    end

    # End Transaction extended request commits with the identifier.
    message_id, name, commit, identifier = decode_end_txn_request(@socket.written[4])
    assert_equal 5, message_id
    assert_equal Net::LDAP::EndTransactionOid, name
    assert_equal true, commit
    assert_equal "txn-1", identifier

    assert_equal 0, @ldap.get_operation_result.code
  end

  def test_transaction_opens_binds_and_closes_its_own_connection
    ldap = Net::LDAP.new
    flexmock(ldap).should_receive(:new_connection).and_return(@connection)

    @socket.queue_response(make_pdu(1, Net::LDAP::PDU::BindResult))
    queue_start_transaction(2)
    @socket.queue_response(make_pdu(3, Net::LDAP::PDU::AddResponse))
    queue_end_transaction(4)

    result = ldap.transaction do |txn|
      txn.add(:dn => USER_DN, :attributes => { :cn => "J Doe" })
    end

    assert_equal true, result
    assert_equal 4, @socket.written.size
    assert @socket.closed?
  end

  def test_transaction_cancels_when_block_raises
    queue_start_transaction(1)
    @socket.queue_response(make_pdu(2, Net::LDAP::PDU::AddResponse))
    queue_end_transaction(3)

    error = assert_raise(RuntimeError) do
      @ldap.transaction do |txn|
        txn.add(:dn => USER_DN, :attributes => { :cn => "J Doe" })
        raise "provisioning failed"
      end
    end
    assert_equal "provisioning failed", error.message

    # The cancel is an End Transaction request with commit=FALSE.
    assert_equal 3, @socket.written.size
    message_id, name, commit, identifier = decode_end_txn_request(@socket.written[2])
    assert_equal 3, message_id
    assert_equal Net::LDAP::EndTransactionOid, name
    assert_equal false, commit
    assert_equal "txn-1", identifier
  end

  def test_transaction_commit_failure_correlates_failed_operation
    update_controls = [
      ["1.2.840.113556.1.4.805".to_ber, true.to_ber, "control-value".to_ber].to_ber_sequence,
    ].to_ber_sequence
    end_txn_value = [3.to_ber, update_controls].to_ber_sequence

    queue_start_transaction(1)
    @socket.queue_response(make_pdu(2, Net::LDAP::PDU::AddResponse))
    @socket.queue_response(make_pdu(3, Net::LDAP::PDU::ModifyResponse))
    queue_end_transaction(4,
                          :code => Net::LDAP::ResultCodeConstraintViolation,
                          :response_value => end_txn_value)

    error = assert_raise(Net::LDAP::TransactionError) do
      @ldap.transaction do |txn|
        txn.add(:dn => USER_DN, :attributes => { :cn => "J Doe" })
        txn.modify(:dn => USER_DN,
                   :operations => [[:add, :mail, "jdoe@example.com"]])
      end
    end

    # The failed request referenced by the commit response is
    # correlated back to the modify operation that originated it.
    assert_equal Net::LDAP::ResultCodeConstraintViolation, error.result_code
    assert_equal 3, error.operation.message_id
    assert_equal :modify, error.operation.name
    assert_equal USER_DN, error.operation.args[:dn]
    assert_equal 1, error.controls.length
    assert_equal "1.2.840.113556.1.4.805", error.controls.first.oid
    assert_equal true, error.controls.first.criticality
    assert_equal "control-value", error.controls.first.value

    assert_equal Net::LDAP::ResultCodeConstraintViolation,
                 @ldap.get_operation_result.code
  end

  def test_transaction_commit_response_lost_leaves_result_unknown
    queue_start_transaction(1)
    @socket.queue_response(make_pdu(2, Net::LDAP::PDU::AddResponse))
    # No End Transaction response is queued: the connection drops after
    # the commit request is sent.

    runs = 0
    error = assert_raise(Net::LDAP::TransactionResultUnknownError) do
      @ldap.transaction do |txn|
        runs += 1
        txn.add(:dn => USER_DN, :attributes => { :cn => "J Doe" })
      end
    end

    assert_match(/unknown/, error.message)
    assert_equal 1, runs # the block is never replayed
    # Start, add and a single commit request; nothing is retried.
    assert_equal 3, @socket.written.size
  end

  def test_nested_transaction_rejected_before_second_start_request
    queue_start_transaction(1)
    queue_end_transaction(2)

    assert_raise(Net::LDAP::TransactionError) do
      @ldap.transaction do |_txn|
        @ldap.transaction { }
      end
    end

    # Only one Start Transaction request was sent; the second write is
    # the best-effort cancel of the outer transaction.
    assert_equal 2, @socket.written.size
    _message_id, name, _value = decode_extended_request(@socket.written[0])
    assert_equal Net::LDAP::StartTransactionOid, name
    _message_id, name, commit, _identifier = decode_end_txn_request(@socket.written[1])
    assert_equal Net::LDAP::EndTransactionOid, name
    assert_equal false, commit
  end

  def test_connection_rejects_unrelated_operations_from_other_threads
    queue_start_transaction(1)
    queue_end_transaction(3)

    errors = []
    @ldap.transaction do |_txn|
      Thread.new do
        begin
          @connection.add(:dn => "uid=other,ou=people,dc=example,dc=org",
                          :attributes => { :cn => "X" })
        rescue Net::LDAP::TransactionError => e
          errors << e
        end
      end.join
    end

    assert_equal 1, errors.length
    assert_match(/another thread/, errors.first.message)
    # The other thread's operation never reached the connection.
    assert_equal 2, @socket.written.size
  end
end
