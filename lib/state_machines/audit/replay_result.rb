# frozen_string_literal: true

module StateMachines
  module Audit
    # ReplayResult is the outcome of a pure replay.  It distinguishes three
    # situations per record:
    #
    # * verified      - every checkable claim held.
    # * unverified    - structurally valid, but some claim cannot be
    #   re-evaluated from the records alone (dynamic guard, unknown
    #   definition fingerprint, ...).
    # * invalid       - a concrete violation was found; replay stops there.
    class ReplayResult
      # All ReplayError objects found, ordered by position.
      attr_reader :errors

      # Projection of the records that form an unbroken, structurally legal
      # prefix.  Once a record is invalid, no later record is admitted.
      attr_reader :valid_prefix

      # The projected state reached after +valid_prefix+ (nil for an empty
      # prefix).
      attr_reader :projected_state

      # Per-record verification statuses, aligned by position with the input:
      # +:verified+, +:unverified+, +:invalid+ or +:unreached+ (never reached
      # because replay stopped at an earlier invalid record).
      attr_reader :statuses

      # Human-readable reasons keyed by position for records that are only
      # unverified (not invalid).
      attr_reader :unverified_reasons

      def initialize(errors:, valid_prefix:, projected_state:, statuses:, unverified_reasons:)
        @errors = errors
        @valid_prefix = valid_prefix
        @projected_state = projected_state
        @statuses = statuses
        @unverified_reasons = unverified_reasons
      end

      # True only when there are no invalid records at all.
      def valid?
        errors.empty?
      end

      # True when valid AND every record was fully re-verified (nothing left
      # un-checked because of missing external information).
      def fully_verified?
        valid? && statuses.none? { |status| status == :unverified }
      end

      # Positions whose status is +:unverified+.
      def unverified_positions
        statuses.each_index.select { |index| statuses[index] == :unverified }
      end

      # Positions whose status is +:invalid+.
      def invalid_positions
        statuses.each_index.select { |index| statuses[index] == :invalid }
      end

      # The projected chain of states implied by the legal prefix, e.g.
      # +[:parked, :idling, :first_gear]+.  Useful for debugging where a chain
      # diverges.
      def state_path
        return [] if valid_prefix.empty?

        [valid_prefix.first.from, *valid_prefix.map(&:to)]
      end

      def to_h
        {
          valid: valid?,
          fully_verified: fully_verified?,
          errors: errors.map(&:to_h),
          statuses: statuses,
          unverified: unverified_positions.map { |position| { position: position, reasons: unverified_reasons[position] || [] } },
          projected_state: projected_state,
          state_path: state_path
        }
      end
    end
  end
end
