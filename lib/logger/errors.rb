# frozen_string_literal: true

class Logger
  # not used after 1.2.7. just for compat.
  class Error < RuntimeError # :nodoc:
  end
  class ShiftingError < Error # :nodoc:
  end

  # Raised when a buffered logging block exceeds its configured size limit.
  class BatchBufferOverflow < Error
    def initialize(limit = nil)
      @limit = limit
      super("log batch buffer exceeds #{limit} bytes")
    end

    attr_reader :limit
  end
end
