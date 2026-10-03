# frozen_string_literal: true

require 'json'
require 'test_helper'

class TransitionChainValidatorTest < StateMachinesTest
  def setup
    @klass = Class.new do
      def self.name
        'Vehicle'
      end

      def seatbelt_on?
        raise 'guard must never be evaluated during replay'
      end
    end
    @machine = StateMachines::Machine.new(@klass, :state, initial: :parked)
    @machine.event(:ignite) { transition parked: :idling }
    @machine.event(:shift_up) { transition idling: :first_gear, if: :seatbelt_on? }
    @machine.event(:park) { transition idling: :parked }
    @machine.event(:reset) { transition parked: same }

    @identity = StateMachines::TransitionRecord.machine_identity(@machine)
    @definition = StateMachines::TransitionRecord.definition_fingerprint(@machine)
  end

  def build_record(event:, from:, to:, sequence:, machine: @identity, definition: @definition)
    StateMachines::TransitionRecord.new(
      machine: machine, definition: definition,
      event: event, from: from, to: to, sequence: sequence
    )
  end

  def valid_chain
    [
      build_record(event: :ignite, from: :parked, to: :idling, sequence: 1),
      build_record(event: :park, from: :idling, to: :parked, sequence: 2)
    ]
  end

  def test_should_accept_legal_chain
    result = StateMachines::TransitionChainValidator.validate(valid_chain, @machine)

    assert_predicate result, :valid?
    assert_empty result.errors
    assert_equal %i[parked idling parked], result.projection
    assert_equal 2, result.checked_count
    assert_equal 2, result.record_count
    assert_empty result.unverified
  end

  def test_should_accept_empty_chain
    result = StateMachines::TransitionChainValidator.validate([], @machine)

    assert_predicate result, :valid?
    assert_empty result.projection
    assert_equal 0, result.checked_count
  end

  def test_should_accept_loopback_transitions
    result = StateMachines::TransitionChainValidator.validate(
      [build_record(event: :reset, from: :parked, to: :parked, sequence: 1)], @machine
    )

    assert_predicate result, :valid?
    assert_equal %i[parked parked], result.projection
  end

  def test_should_accept_plain_hashes_from_serialized_records
    hashes = valid_chain.map { |record| JSON.parse(JSON.generate(record.to_h)) }

    result = StateMachines::TransitionChainValidator.validate(hashes, @machine)

    assert_predicate result, :valid?
    assert_equal %i[parked idling parked], result.projection
  end

  def test_should_reject_broken_chain_and_return_valid_prefix_projection
    records = valid_chain + [build_record(event: :shift_up, from: :idling, to: :first_gear, sequence: 3)]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal 1, result.errors.length
    error = result.errors.first
    assert_equal 2, error.index
    assert_equal :broken_chain, error.code
    assert_equal %i[parked idling parked], result.projection
    assert_equal 2, result.checked_count
    assert_equal 3, result.record_count
  end

  def test_should_reject_undeclared_transition
    records = [build_record(event: :ignite, from: :parked, to: :first_gear, sequence: 1)]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal :undeclared_transition, result.errors.first.code
    assert_equal 0, result.errors.first.index
    assert_empty result.projection
  end

  def test_should_reject_unknown_event
    records = [build_record(event: :fly, from: :parked, to: :idling, sequence: 1)]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal :unknown_event, result.errors.first.code
  end

  def test_should_reject_record_from_another_machine
    records = [build_record(event: :ignite, from: :parked, to: :idling, sequence: 1, machine: 'Vehicle#alarm(alarm)')]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal :machine_mismatch, result.errors.first.code
  end

  def test_should_reject_record_against_stale_definition
    records = [build_record(event: :ignite, from: :parked, to: :idling, sequence: 1, definition: 'stale-fingerprint')]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal :definition_mismatch, result.errors.first.code
  end

  def test_should_reject_non_increasing_sequence
    records = valid_chain
    records[1] = build_record(event: :park, from: :idling, to: :parked, sequence: 1)

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal :sequence_not_increasing, result.errors.first.code
    assert_equal 1, result.errors.first.index
  end

  def test_should_reject_non_integer_sequence
    records = [build_record(event: :ignite, from: :parked, to: :idling, sequence: 'one')]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal :invalid_sequence, result.errors.first.code
  end

  def test_should_reject_malformed_record
    result = StateMachines::TransitionChainValidator.validate([:not_a_record], @machine)

    refute_predicate result, :valid?
    assert_equal :malformed_record, result.errors.first.code
    assert_equal 0, result.errors.first.index
  end

  def test_should_reject_hash_with_missing_keys
    result = StateMachines::TransitionChainValidator.validate([{ machine: @identity }], @machine)

    refute_predicate result, :valid?
    assert_equal :malformed_record, result.errors.first.code
  end

  def test_should_stop_at_first_illegal_record_instead_of_skipping
    records = valid_chain + [
      build_record(event: :shift_up, from: :idling, to: :first_gear, sequence: 3),
      build_record(event: :fly, from: :nowhere, to: :nowhere, sequence: 4)
    ]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    refute_predicate result, :valid?
    assert_equal 1, result.errors.length
    assert_equal 2, result.errors.first.index
    assert_equal 2, result.checked_count
  end

  def test_should_not_evaluate_guards_but_report_them_as_unverified
    records = [
      build_record(event: :ignite, from: :parked, to: :idling, sequence: 1),
      build_record(event: :shift_up, from: :idling, to: :first_gear, sequence: 2)
    ]

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    assert_predicate result, :valid?
    assert_equal 1, result.unverified.length
    unverified = result.unverified.first
    assert_equal 1, unverified.index
    assert_equal :shift_up, unverified.event
    assert_equal [:if], unverified.guards
  end

  def test_should_report_state_guards_as_unverified
    StateMachines::Machine.new(@klass, :alarm_state, initial: :off)
    @machine.event(:secure) { transition parked: :idling, if_state: { alarm_state: :off } }
    @definition = StateMachines::TransitionRecord.definition_fingerprint(@machine)

    records = [build_record(event: :secure, from: :parked, to: :idling, sequence: 1)]
    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    assert_predicate result, :valid?
    assert_equal [[:if_state]], result.unverified.map(&:guards)
  end

  def test_should_locate_error_record
    records = valid_chain
    records[1] = build_record(event: :ignite, from: :idling, to: :parked, sequence: 2)

    result = StateMachines::TransitionChainValidator.validate(records, @machine)

    error = result.errors.first
    assert_equal records[1], error.record
    assert_match(/record 1/, error.message)
  end
end
