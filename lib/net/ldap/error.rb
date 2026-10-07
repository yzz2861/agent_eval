class Net::LDAP
  class Error < StandardError; end

  class AlreadyOpenedError < Error; end
  class SocketError < Error; end
  class ConnectionError < Error
    def self.new(errors)
      error = errors.first.first
      if errors.size == 1
        return error if error.is_a? Errno::ECONNREFUSED

        return Net::LDAP::Error.new(error.message)
      end

      super
    end

    def initialize(errors)
      message = "Unable to connect to any given server: \n  #{errors.map { |e, h, p| "#{e.class}: #{e.message} (#{h}:#{p})" }.join("\n  ")}"
      super(message)
    end
  end
  class NoOpenSSLError < Error; end
  class NoStartTLSResultError < Error; end
  class NoSearchBaseError < Error; end
  class StartTLSError < Error; end
  class EncryptionUnsupportedError < Error; end
  class EncMethodUnsupportedError < Error; end
  class AuthMethodUnsupportedError < Error; end
  class BindingInformationInvalidError < Error; end
  class NoBindResultError < Error; end
  class SASLChallengeOverflowError < Error; end
  class SearchSizeInvalidError < Error; end
  class SearchScopeInvalidError < Error; end
  class ResponseTypeInvalidError < Error; end
  class ResponseMissingOrInvalidError < Error; end
  class EmptyDNError < Error; end
  class InvalidDNError < Error; end
  class HashTypeUnsupportedError < Error; end
  class OperatorError < Error; end
  class SubstringFilterError < Error; end
  class SearchFilterError < Error; end
  class BERInvalidError < Error; end
  class SearchFilterTypeUnknownError < Error; end
  class BadAttributeError < Error; end
  class FilterTypeUnknownError < Error; end
  class FilterSyntaxInvalidError < Error; end
  class EntryOverflowError < Error; end

  # Raised for LDAP transaction (RFC 5805) failures: nested transactions,
  # a server refusing to start a transaction, or a commit that the server
  # rejected. When the commit was rejected, #operation identifies the
  # update request that failed (a Net::LDAP::Transaction::Operation) and
  # #controls carries the update controls the server returned for it.
  class TransactionError < Error
    attr_reader :operation, :controls, :result_code

    def initialize(message = nil, operation: nil, controls: nil, result_code: nil)
      @operation = operation
      @controls = controls
      @result_code = result_code
      super(message)
    end
  end

  # Raised when the connection was lost after the End Transaction (commit)
  # request was sent but before its response arrived. The transaction may
  # or may not have been committed by the server; the block is never
  # replayed automatically.
  class TransactionResultUnknownError < TransactionError; end
end
