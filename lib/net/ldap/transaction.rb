# -*- ruby encoding: utf-8 -*-
require 'ostruct'

##
# A block-scoped LDAP transaction (RFC 5805, "Lightweight Directory
# Access Protocol (LDAP) Transactions").
#
# Instances are created by Net::LDAP#transaction and yielded to its
# block. Update operations invoked on the transaction (#add, #modify,
# #delete, #rename) are sent on the reserved connection with the
# Transaction Specification control carrying the identifier returned by
# the server in the Start Transaction response.
class Net::LDAP::Transaction
  ##
  # A journal entry for an update operation performed within a
  # transaction. Used to correlate the failed request referenced by an
  # End Transaction response back to the operation that originated it.
  Operation = Struct.new(:message_id, :name, :args)

  # The transaction identifier returned by the server.
  attr_reader :identifier

  # The update operations performed so far, as Operation structs.
  attr_reader :operations

  # The last PDU exchanged for this transaction.
  attr_reader :result

  def initialize(connection) #:nodoc:
    @connection = connection
    @identifier = nil
    @operations = []
    @state = :new
    @result = nil
  end

  # True while the transaction is open for update operations.
  def active?
    @state == :started
  end

  # True when the transaction was committed by the server.
  def committed?
    @state == :committed
  end

  # Internal: Sends the Start Transaction extended request and records
  # the transaction identifier returned by the server.
  def start
    unless @state == :new
      raise Net::LDAP::TransactionError, "transaction already started"
    end

    pdu = @connection.start_transaction
    @result = pdu

    unless pdu.result_code == Net::LDAP::ResultCodeSuccess
      raise Net::LDAP::TransactionError.new(
        "server refused to start a transaction: #{pdu.error_message}",
        :result_code => pdu.result_code)
    end

    @identifier = parse_identifier(pdu)
    @state = :started
    self
  end

  # Adds a new entry as part of the transaction. Takes the same
  # arguments as Net::LDAP#add and returns true or false.
  def add(args)
    perform(:add, args)
  end

  # Modifies entry attributes as part of the transaction. Takes the
  # same arguments as Net::LDAP#modify and returns true or false.
  def modify(args)
    perform(:modify, args)
  end

  # Deletes an entry as part of the transaction. Takes the same
  # arguments as Net::LDAP#delete and returns true or false.
  def delete(args)
    perform(:delete, args)
  end

  # Renames an entry as part of the transaction. Takes the same
  # arguments as Net::LDAP#rename and returns true or false.
  def rename(args)
    perform(:rename, args)
  end

  # Internal: Sends the End Transaction extended request with
  # commit=TRUE. Raises Net::LDAP::TransactionError when the server
  # rejects the commit, correlating the failed request referenced in
  # the response back to the originating operation. Raises
  # Net::LDAP::TransactionResultUnknownError when the response is
  # lost after the commit request was sent.
  def commit
    unless active?
      raise Net::LDAP::TransactionError, "transaction is not active"
    end

    # Once the commit request is sent, the outcome is decided by the
    # server; the transaction must never be aborted or replayed.
    @state = :commit_sent

    pdu = begin
            @connection.end_transaction(true, @identifier)
          rescue StandardError => e
            @state = :unknown
            raise Net::LDAP::TransactionResultUnknownError,
                  "transaction commit was sent but its result is unknown: #{e.message}"
          end

    if pdu.nil?
      @state = :unknown
      raise Net::LDAP::TransactionResultUnknownError,
            "transaction commit was sent but the response was lost; the result is unknown"
    end

    @result = pdu

    if pdu.result_code == Net::LDAP::ResultCodeSuccess
      @state = :committed
      return true
    end

    @state = :aborted
    message_id, controls = parse_end_txn_response(pdu.extended_response)
    operation = message_id && @operations.find { |op| op.message_id == message_id }
    raise Net::LDAP::TransactionError.new(
      "transaction commit failed: #{pdu.error_message}",
      :operation => operation,
      :controls => controls,
      :result_code => pdu.result_code)
  end

  # Cancels the transaction by sending the End Transaction extended
  # request with commit=FALSE.
  def abort
    return false unless active?

    @state = :aborted
    pdu = @connection.end_transaction(false, @identifier)
    @result = pdu if pdu
    true
  end

  # Internal: Best-effort cancel used when the transaction block
  # raises; never masks the original exception.
  def attempt_abort
    abort if active?
  rescue StandardError
    nil
  end

  private

  def perform(name, args)
    unless active?
      raise Net::LDAP::TransactionError, "transaction is not active"
    end

    connection_args = args.dup
    connection_args[:controls] = Array(args[:controls]) + [transaction_spec_control]

    pdu = @connection.public_send(name, connection_args)
    @result = pdu
    @operations << Operation.new(pdu.message_id, name, args)
    pdu.success?
  end

  # RFC 5805 section 2.2: the Transaction Specification control has
  # criticality TRUE and a controlValue holding the BER-encoded
  # transaction identifier.
  def transaction_spec_control
    [
      Net::LDAP::LDAPControls::TRANSACTION_SPEC.to_ber,
      true.to_ber,
      @identifier.to_ber.to_ber,
    ].to_ber_sequence
  end

  # The Start Transaction response value carries a BER-encoded
  # transaction identifier (an OCTET STRING).
  def parse_identifier(pdu)
    value = pdu.extended_response
    if value.nil? || value.empty?
      raise Net::LDAP::TransactionError,
            "start transaction response did not include a transaction identifier"
    end
    value.read_ber
  end

  # RFC 5805 section 2.3: on commit failure the End Transaction
  # response value holds an EndTxnResponseValue identifying the failed
  # update request and the controls that would have been returned with
  # it.
  def parse_end_txn_response(value)
    return [nil, nil] if value.nil? || value.empty?

    ber = value.read_ber
    controls = (ber[1] || []).map do |control|
      parsed = OpenStruct.new
      parsed.oid, parsed.criticality, parsed.value = control[0], control[1], control[2]
      if parsed.criticality.is_a?(String)
        parsed.value = parsed.criticality
        parsed.criticality = false
      end
      parsed
    end
    [ber[0], controls]
  rescue StandardError
    [nil, nil]
  end
end
