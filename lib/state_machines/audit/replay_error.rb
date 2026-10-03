# frozen_string_literal: true

module StateMachines
  module Audit
    # A ReplayError locates a single validation failure at a precise record
    # position.  Records are never silently skipped: every failure is reported.
    class ReplayError
      # Zero-based index of the offending record in the supplied array.
      attr_reader :position

      # Declared sequence number on the offending record (may be nil).
      attr_reader :sequence

      # Symbolic error code, e.g. +:broken_chain+ or +:illegal_transition+.
      attr_reader :code

      # Human-readable explanation.
      attr_reader :message

      # The offending record, when one could be parsed.
      attr_reader :record

      def initialize(position:, code:, message:, sequence: nil, record: nil)
        @position = position
        @sequence = sequence
        @code = code
        @message = message
        @record = record
      end

      def to_h
        {
          position: position,
          sequence: sequence,
          code: code,
          message: message
        }
      end

      def inspect
        "#<#{self.class} position=#{position} sequence=#{sequence.inspect} #{code}: #{message}>"
      end
    end
  end
end
