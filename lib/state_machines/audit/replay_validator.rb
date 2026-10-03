# frozen_string_literal: true

module StateMachines
  module Audit
    # ReplayValidator replays an ordered list of structured TransitionRecords
    # and checks that they describe a single, legal state history.
    #
    # It is a *pure* replay: it never runs the machine's action, callbacks or
    # guards, and it never instantiates the audited object.  It checks only:
    #
    # 1. Record well-formedness (identity / fingerprint / event / states /
    #    sequence present and of the right shape).
    # 2. The declared transition relation - when a MachineDefinition snapshot
    #    for the record's fingerprint is available - i.e. the event connects
    #    +from+ to +to+.
    # 3. Chain continuity - each record starts exactly where the previous one
    #    ended, the machine identity is constant, and sequence numbers are
    #    consecutive.
    #
    # Things that depend on external/runtime information are *not* re-evaluated
    # and are reported as unverified instead of silently treated as passing:
    # * +:if+ / +:unless+ guards evaluated against the live object.
    # * Guards on other machines' states (+if_state+, +if_all_states+, ...).
    # * The success of the persistence action (never executed).
    # * Authorization against an unknown/unprovided definition fingerprint.
    # * A dynamic initial state (lambda) when the history is empty or begins
    #   before the first record.
    #
    # Invalid records are never skipped to produce a false "passed" result.
    # Replay stops at the first invalid record; the structurally legal prefix
    # and its projected state are still returned for troubleshooting.
    class ReplayValidator
      GUARD_REASONS = {
        if_unless: 'dynamic :if/:unless guard was not re-evaluated',
        state_guard: 'cross-machine state guard was not re-evaluated',
        action: 'persistence action was not executed',
        unknown_definition: 'no machine definition registered for fingerprint',
        dynamic_initial: 'initial state is dynamic and was not re-evaluated'
      }.freeze

      # Builds a validator.
      #
      # Configuration options:
      # * +definitions+ - Hash of MachineDefinition snapshots keyed by
      #   fingerprint (identity keys are also accepted).  When no definition
      #   is found for a record, its declared relation is left unverified
      #   rather than forced to pass/fail.
      # * +check_sequence+ - +:strict+ (default, must start at 1 and be
      #   gapless), +:present+ (must be present and strictly increasing) or
      #   +false+ (ignore sequence numbers).
      # * +initial_state+ - Expected state immediately before the first
      #   record's +from+.  When nil, the first record may start anywhere.
      # * +require_definition+ - When true, an unknown fingerprint is an
      #   +:unknown_definition+ error instead of an unverified condition.
      def initialize(definitions: {}, check_sequence: :strict, initial_state: nil, require_definition: false)
        @definitions = definitions.each_with_object({}) do |(key, definition), indexed|
          snapshot = MachineDefinition.coerce(definition)
          indexed[key] = snapshot
          indexed[snapshot.fingerprint] = snapshot
          indexed[snapshot.identity] = snapshot
        end
        @check_sequence = check_sequence
        @initial_state = initial_state&.to_sym
        @require_definition = require_definition
      end

      # Validates an array of records (Hashes or TransitionRecords).
      def validate(records)
        records = Array(records).each_with_index.map { |record, index| coerce(record, index) }

        errors = []
        statuses = Array.new(records.length)
        unverified = Hash.new { |hash, key| hash[key] = [] }

        # Pass 1: validate every record independently so that structural
        # problems after the replay cut-off are still reported.
        records.each_with_index do |record, index|
          structural_errors = validate_structure(record, index)
          if structural_errors.any?
            errors.concat(structural_errors)
            statuses[index] = :invalid
          end
        end

        # Pass 2: pure replay stops at the first invalid record.
        expected_state = @initial_state
        expected_sequence = first_sequence_number
        previous_sequence = nil
        expected_identity = nil
        prefix = []

        records.each_with_index do |record, index|
          if statuses[index] == :invalid
            mark_unreached(statuses, index + 1)
            break
          end

          position_errors = []
          reasons = []

          if expected_identity.nil?
            expected_identity = record.machine_identity
          elsif record.machine_identity != expected_identity
            position_errors << error(index, record, :identity_mismatch,
                                     "machine identity changed from #{expected_identity.inspect} to #{record.machine_identity.inspect}")
          end

          if !expected_state.nil? && record.from != expected_state
            position_errors << error(index, record, :broken_chain,
                                     "expected from #{expected_state.inspect} but record declares #{record.from.inspect}")
          end

          sequence_error = check_record_sequence(record, index, expected_sequence, previous_sequence)
          position_errors << sequence_error if sequence_error
          if record.sequenced?
            expected_sequence = record.sequence + 1 if @check_sequence == :strict
            previous_sequence = record.sequence
          end

          authorization = authorize_record(record, reasons, index)
          position_errors << authorization if authorization.is_a?(ReplayError)

          if position_errors.any?
            errors.concat(position_errors)
            statuses[index] = :invalid
            mark_unreached(statuses, index + 1)
            break
          end

          statuses[index] = reasons.any? ? :unverified : :verified
          unverified[index].concat(reasons) if reasons.any?
          prefix << record
          expected_state = record.to
        end

        projected_state = prefix.last&.to || @initial_state
        ReplayResult.new(
          errors: errors,
          valid_prefix: prefix,
          projected_state: projected_state,
          statuses: statuses,
          unverified_reasons: unverified
        )
      end

      # Bang variant that raises ReplayViolation unless the history is valid.
      def validate!(records)
        result = validate(records)
        raise ReplayViolation, result unless result.valid?

        result
      end

      private

      def first_sequence_number
        @check_sequence == :strict ? 1 : nil
      end

      def coerce(record, index)
        TransitionRecord.coerce(record)
      rescue ArgumentError => e
        MalformedRecord.new(index, e.message)
      end

      # Records that could not be coerced at all are represented by a
      # lightweight duck type so pass 1 can still locate them.
      class MalformedRecord # :nodoc:
        attr_reader :position, :reason

        def initialize(position, reason)
          @position = position
          @reason = reason
        end

        def machine_identity; nil; end
        def definition_fingerprint; nil; end
        def event; nil; end
        def from; nil; end
        def to; nil; end
        def sequence; nil; end
        def sequenced?; false; end
      end

      def validate_structure(record, index)
        return [error(index, record, :malformed_record, record.reason)] if record.is_a?(MalformedRecord)

        errors = []
        unless present_identifier?(record.machine_identity)
          errors << error(index, record, :missing_identity, 'machine identity is required')
        end
        unless present_identifier?(record.definition_fingerprint)
          errors << error(index, record, :missing_fingerprint, 'definition fingerprint is required')
        end
        if record.event.nil?
          errors << error(index, record, :missing_event, 'event is required')
        end
        if record.from.nil?
          errors << error(index, record, :missing_from, 'from state is required')
        end
        if record.to.nil?
          errors << error(index, record, :missing_to, 'to state is required')
        end
        if @check_sequence && record.sequence.nil?
          errors << error(index, record, :missing_sequence, 'sequence is required')
        end
        if record.sequenced? && !valid_sequence_value?(record.sequence)
          errors << error(index, record, :invalid_sequence, "sequence must be a positive integer, got #{record.sequence.inspect}")
        end
        errors
      end

      def valid_sequence_value?(value)
        value.is_a?(Integer) && value >= 1
      end

      def present_identifier?(value)
        (value.is_a?(String) && !value.empty?) ||
          (value.is_a?(Symbol) && value != :'')
      end

      def check_record_sequence(record, index, expected, previous_sequence = nil)
        return nil unless @check_sequence && record.sequenced?

        case @check_sequence
        when :strict
          return if record.sequence == expected

          error(index, record, :sequence_gap, "expected sequence #{expected}, got #{record.sequence}")
        when :present
          return if previous_sequence.nil? || record.sequence > previous_sequence

          error(index, record, :sequence_out_of_order, "sequence #{record.sequence} is not strictly increasing")
        end
      end

      def authorize_record(record, reasons, index)
        # Prefer the definition matching the record's fingerprint.  Identity is
        # only a fallback when no fingerprint key is registered, so an unknown
        # fingerprint cannot silently resolve to another definition.
        definition = if @definitions.key?(record.definition_fingerprint)
                       @definitions[record.definition_fingerprint]
                     elsif !fingerprints_registered? && @definitions.key?(record.machine_identity)
                       @definitions[record.machine_identity]
                     end

        if definition.nil?
          message = GUARD_REASONS[:unknown_definition] + " (#{record.definition_fingerprint.inspect})"
          if @require_definition
            return error(index, record, :unknown_definition, message)
          end

          reasons << message
          return nil
        end

        status = definition.authorize(record.event, record.from, record.to)
        case status
        when :allowed
          nil
        when :allowed_guarded
          definition.matching_edges(record.event, record.from, record.to)
                    .select(&:guarded?)
                    .flat_map(&:guard_types)
                    .uniq
                    .each { |type| reasons << GUARD_REASONS.fetch(type, "dynamic guard #{type.inspect} was not re-evaluated") }
          nil
        when :unknown_event
          error(index, record, :unknown_event, "event #{record.event.inspect} is not defined for #{definition.fingerprint.inspect}")
        when :unknown_state
          unknown_state_error(record, definition, index)
        when :illegal
          error(index, record, :illegal_transition,
                "event #{record.event.inspect} does not transition #{record.from.inspect} -> #{record.to.inspect} under #{definition.fingerprint.inspect}")
        end
      end

      def unknown_state_error(record, definition, index)
        unknown = [record.from, record.to].reject { |state| definition.known_state?(state) }
        error(index, record, :unknown_state,
                "state(s) #{unknown.map(&:inspect).join(', ')} not defined in #{definition.fingerprint.inspect}")
      end

      def fingerprints_registered?
        @fingerprints_registered ||= @definitions.values.map(&:fingerprint).any?
      end

      def mark_unreached(statuses, start_index)
        (start_index...statuses.length).each do |index|
          statuses[index] ||= :unreached
        end
      end

      def error(index, record, code, message)
        ReplayError.new(
          position: index,
          sequence: record&.sequence,
          code: code,
          message: message,
          record: record
        )
      end
    end

    # Raised by ReplayValidator#validate! when the history is not valid.
    class ReplayViolation < StandardError
      attr_reader :result

      def initialize(result)
        @result = result
        first = result.errors.first
        super("invalid transition history at record #{first.position}: #{first.code} - #{first.message}")
      end
    end
  end
end
