# -*- ruby encoding: utf-8 -*-

# Support for the Lightweight Directory Access Protocol (LDAP) Transactions
# extension described in RFC 5805.
#
# A transaction groups several update operations (add, modify, rename and
# delete) so that they are either all applied together by the server or not
# applied at all. Only directory servers that advertise the
# "1.3.6.1.1.21.1" extended operation support this feature.
#
# Net::LDAP#transaction is the public entry point. The classes in this file
# describe the in-progress transaction and its outcome.
class Net::LDAP
  # Object identifier of the Start Transaction extended request/response, as
  # defined by RFC 5805 section 2.1.1.
  StartTransactionOid = '1.3.6.1.1.21.1'

  # Object identifier of the End Transaction extended request/response, as
  # defined by RFC 5805 section 2.2.1.
  EndTransactionOid = '1.3.6.1.1.21.3'

  module LDAPControls
    # RFC 5805 section 2.3: identifies the transaction an update request is
    # part of. The control value is the opaque transaction identifier handed
    # out by the server in the Start Transaction response.
    TRANSACTION_SPECIFICATION = "1.3.6.1.1.21.2"
  end

  # Base class for all transaction related errors raised by net-ldap.
  class TransactionError < Error; end

  # Raised when a transaction is started from inside another transaction.
  # Nested transactions are rejected before any protocol request is sent.
  class TransactionAlreadyActiveError < TransactionError; end

  # Raised when a thread other than the one that started a transaction
  # attempts to perform an operation on the pinned connection.
  class TransactionInProgressError < TransactionError; end

  # Raised when the Start Transaction extended operation fails or cannot be
  # understood.
  class TransactionStartError < TransactionError; end

  # Raised when the End Transaction response reports that the transaction
  # could not be committed. #failed_operations associates the message ids in
  # the response with the operations issued inside the block.
  class TransactionCommitError < TransactionError
    attr_reader :result_code, :error_message, :matched_dn,
                :failed_operations, :pdu

    def initialize(message = nil, pdu: nil, failed_operations: [])
      @pdu = pdu
      @result_code = pdu&.result_code
      @error_message = pdu&.error_message
      @matched_dn = (pdu && pdu.result[:matchedDN]) || ""
      @failed_operations = failed_operations
      super(message || default_message)
    end

    private

    def default_message
      parts = ["LDAP transaction commit failed"]
      parts << "(result #{@result_code})" if @result_code
      detail = @failed_operations.map { |op| op[:operation] }.uniq.join(", ")
      parts << "failed operations: #{detail}" unless detail.empty?
      parts.join(" ")
    end
  end

  # Raised when no End Transaction response is received after commit or
  # abort. The server may still apply or roll back the transaction; the
  # library deliberately does not replay the operations. See RFC 4511
  # section 4.1.11 for the response-vs-result guarantee.
  class TransactionResultUnknownError < TransactionError
    attr_reader :commit, :operations

    def initialize(commit, operations)
      @commit = commit
      @operations = operations
      action = commit ? "commit" : "abort"
      super("no response received for transaction #{action}; final result is unknown")
    end

    # True when the lost response belonged to a commit request.
    def commit?
      @commit
    end
  end

  # Represents a transaction while it is in progress. The same object is
  # yielded to the Net::LDAP#transaction block and returned on success.
  #
  # Readers that describe the outcome are only meaningful once the block has
  # completed and the End Transaction response has been processed.
  class Transaction
    # Opaque identifier returned by the server in the Start Transaction
    # response and attached (as the RFC 5805 transaction specification
    # control) to every operation belonging to the transaction.
    attr_reader :identifier

    # Message id used for the Start Transaction request.
    attr_reader :start_message_id

    # Message id used for the End Transaction request, once it has been sent.
    attr_accessor :end_message_id

    # Ordered list of operations performed inside the transaction. Each
    # entry is a Hash with :message_id, :operation and :args keys, followed
    # by :pdu once the corresponding response has been received.
    attr_reader :operations

    # The End Transaction response PDU, or nil while the transaction is
    # open or when the response was lost.
    attr_accessor :end_pdu

    def initialize(identifier, start_message_id)
      @identifier = identifier
      @start_message_id = start_message_id
      @end_message_id = nil
      @end_pdu = nil
      @operations = []
    end

    # Records an operation so that a failed End Transaction response can be
    # associated back to the caller's original request.
    def record(message_id, operation, args)
      @operations << {
        :message_id => message_id,
        :operation => operation,
        :args => args,
        :pdu => nil,
      }
    end

    # Records the response PDU for the operation previously sent with the
    # given message id.
    def record_response(message_id, pdu)
      entry = @operations.reverse.find { |op| op[:message_id] == message_id }
      entry[:pdu] = pdu if entry
    end

    # Returns the recorded operation whose request used the given message
    # id. Message ids in an End Transaction response refer to the operations
    # performed inside the transaction.
    def operation_for(message_id)
      @operations.find { |op| op[:message_id] == message_id }
    end

    # True when the End Transaction response reported success.
    def committed?
      !@end_pdu.nil? && @end_pdu.success?
    end
  end
end

