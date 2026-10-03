# frozen_string_literal: true

require_relative 'transition_record'

module StateMachines
  # Pure replay validator for chains of StateMachines::TransitionRecord.
  #
  # Given an ordered chain of transition records and a machine definition,
  # the validator checks -- without firing anything -- that the records form
  # a legal state history:
  #
  # * each record targets this machine (identity and definition fingerprint)
  # * sequence numbers strictly increase along the chain
  # * each record's +from+ state continues the previous record's +to+ state
  # * each +event+ / +from+ / +to+ triple is a transition actually declared
  #   on the machine
  #
  # The validator is intentionally *pure*:
  # * it never runs actions or callbacks
  # * it never re-evaluates guards (:if / :unless conditions and the
  #   :if_state family of state guards), because those depend on external
  #   object state that is not part of the records
  #
  # Branches that carry such conditions can only be matched structurally;
  # they are reported in Result#unverified as "not re-verified" so callers
  # know exactly which records relied on conditions this replay could not
  # check.
  #
  # Validation is fail-fast: the first illegal record is reported with its
  # position in the chain, and the projection of the valid prefix (the state
  # history up to that point) is returned so callers can investigate.
  #
  # == Examples
  #
  #   result = StateMachines::TransitionChainValidator.validate(records, Vehicle.state_machines[:state])
  #   result.valid?      # => false
  #   result.errors      # => [#<struct index=2, code=:broken_chain, ...>]
  #   result.projection  # => [:parked, :idling, :first_gear]
  class TransitionChainValidator
    # A single validation failure, located at the record's position in the
    # chain.  +record+ holds the offending record (or the raw value if it
    # could not even be coerced into a record).
    Error = Struct.new(:index, :code, :message, :record)

    # A guard condition that the pure replay could not re-evaluate.  +guards+
    # lists the kinds of conditions on the matched branch (e.g. +:if+,
    # +:unless+, +:if_state+).
    UnverifiedCondition = Struct.new(:index, :event, :guards, :detail)

    # The outcome of validating a record chain
    class Result
      # The failures found, in chain order.  Empty when the chain is legal.
      attr_reader :errors

      # The state history replayed from the longest valid prefix of the
      # chain: the +from+ state of the first valid record followed by the
      # +to+ state of every valid record.  Empty if the first record failed.
      attr_reader :projection

      # Guard conditions on matched branches that were not re-evaluated
      attr_reader :unverified

      # How many records replayed cleanly (the length of the valid prefix)
      attr_reader :checked_count

      # How many records were submitted for validation
      attr_reader :record_count

      def initialize(errors:, projection:, unverified:, checked_count:, record_count:)
        @errors = errors
        @projection = projection
        @unverified = unverified
        @checked_count = checked_count
        @record_count = record_count
      end

      # Whether the entire chain formed a legal state history
      def valid?
        errors.empty?
      end
    end

    # Validates the given chain of records (TransitionRecord instances or
    # plain hashes) against the given machine definition
    def self.validate(records, machine)
      new(machine).validate(records)
    end

    def initialize(machine)
      @machine = machine
      @expected_identity = TransitionRecord.machine_identity(machine)
      @expected_definition = TransitionRecord.definition_fingerprint(machine)
    end

    def validate(records)
      errors = []
      unverified = []
      projection = []
      previous = nil
      checked_count = 0

      records.each_with_index do |raw, index|
        record, coercion_error = coerce(raw)
        unless record
          errors << Error.new(index, :malformed_record, "record #{index} is malformed: #{coercion_error}", raw)
          break
        end

        record_errors = check_record(record, previous, index)
        if record_errors.empty?
          unverified << unverified_condition(record, index) if guarded?(record)
          projection << record.from if previous.nil?
          projection << record.to
          previous = record
          checked_count += 1
        else
          errors.concat(record_errors)
          break
        end
      end

      Result.new(
        errors: errors,
        projection: projection,
        unverified: unverified,
        checked_count: checked_count,
        record_count: records.length
      )
    end

    private

    # Coerces a raw value into a TransitionRecord, returning
    # [record, nil] on success or [nil, error message] on failure
    def coerce(raw)
      case raw
      when TransitionRecord
        [raw, nil]
      when Hash
        begin
          [TransitionRecord.from_h(raw), nil]
        rescue ArgumentError => e
          [nil, e.message]
        end
      else
        [nil, "expected a StateMachines::TransitionRecord or Hash, got #{raw.class}"]
      end
    end

    # All failures for a single record.  Chain-related checks are only run
    # when a previous record exists to chain from.
    def check_record(record, previous, index)
      errors = []

      unless record.sequence.is_a?(Integer)
        errors << failure(index, :invalid_sequence, record, "sequence must be an Integer, got #{record.sequence.inspect}")
      end

      if record.machine != @expected_identity
        errors << failure(index, :machine_mismatch, record, "machine #{record.machine.inspect} does not match #{@expected_identity.inspect}")
      end

      if record.definition != @expected_definition
        errors << failure(index, :definition_mismatch, record, "definition fingerprint #{record.definition.inspect} does not match current definition #{@expected_definition.inspect}")
      end

      if previous
        if record.sequence.is_a?(Integer) && previous.sequence.is_a?(Integer) && record.sequence <= previous.sequence
          errors << failure(index, :sequence_not_increasing, record, "sequence #{record.sequence} does not follow #{previous.sequence}")
        end

        if record.from != previous.to
          errors << failure(index, :broken_chain, record, "starts from #{record.from.inspect} but record #{index - 1} ended at #{previous.to.inspect}")
        end
      end

      errors.concat(check_declared_transition(record, index))

      errors
    end

    # Checks that the machine actually declares the record's event and a
    # from/to transition for it.  Guards are matched with :guard => false so
    # no object-dependent condition is ever evaluated.
    def check_declared_transition(record, index)
      event = @machine.events[record.event]
      return [failure(index, :unknown_event, record, "event #{record.event.inspect} is not defined on #{@expected_identity}")] unless event

      query = { on: record.event, from: record.from, to: record.to, guard: false }
      matched = event.branches.any? { |branch| branch.match(nil, query) }
      return [] if matched

      [failure(index, :undeclared_transition, record, "event #{record.event.inspect} declares no transition from #{record.from.inspect} to #{record.to.inspect}")]
    end

    # Whether the branch matching this record carries guard conditions that
    # a pure replay cannot re-evaluate
    def guarded?(record)
      !guard_kinds(record).empty?
    end

    def unverified_condition(record, index)
      guards = guard_kinds(record)
      UnverifiedCondition.new(
        index,
        record.event,
        guards,
        "guards #{guards.map(&:inspect).join(', ')} depend on external object state and were not re-evaluated"
      )
    end

    # The kinds of guards on the branch that matches the record's declared
    # transition
    def guard_kinds(record)
      event = @machine.events[record.event]
      return [] unless event

      query = { on: record.event, from: record.from, to: record.to, guard: false }
      branch = event.branches.find { |candidate| candidate.match(nil, query) }
      return [] unless branch

      kinds = []
      kinds << :if if branch.if_condition
      kinds << :unless if branch.unless_condition
      kinds.concat(branch.state_guards.keys)
      kinds
    end

    def failure(index, code, record, detail)
      Error.new(index, code, "record #{index}: #{detail}", record)
    end
  end
end
