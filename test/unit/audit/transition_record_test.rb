# frozen_string_literal: true

require 'test_helper'

class AuditTransitionRecordTest < StateMachinesTest
  def test_builds_structured_record
    record = StateMachines::Audit::TransitionRecord.new(
      machine_identity: 'Vehicle#state',
      definition_fingerprint: 'abc123',
      event: 'ignite', from: 'parked', to: 'idling', sequence: 1
    )

    assert_equal 'Vehicle#state', record.machine_identity
    assert_equal 'abc123', record.definition_fingerprint
    assert_equal :ignite, record.event
    assert_equal :parked, record.from
    assert_equal :idling, record.to
    assert_equal 1, record.sequence
    assert_predicate record, :sequenced?
    refute_predicate record, :loopback?
  end

  def test_coerces_hash_and_strings
    record = StateMachines::Audit::TransitionRecord.coerce(
      machine_identity: 'M', definition_fingerprint: 'f',
      event: 'park', from: 'idling', to: 'idling', sequence: 4
    )

    assert_instance_of StateMachines::Audit::TransitionRecord, record
    assert_equal :park, record.event
    assert_predicate record, :loopback?
  end

  def test_builds_from_live_transition
    machine = StateMachines::Machine.new(Class.new, initial: :parked)
    machine.state :parked, :idling
    machine.event(:ignite) { transition parked: :idling }
    object = Object.new
    transition = StateMachines::Transition.new(object, machine, :ignite, :parked, :idling, false)

    record = StateMachines::Audit::TransitionRecord.from_transition(transition, sequence: 1)

    assert_equal :ignite, record.event
    assert_equal :parked, record.from
    assert_equal :idling, record.to
    assert_equal 1, record.sequence
    assert_equal StateMachines::Audit::MachineDefinition.fingerprint_for(machine), record.definition_fingerprint
  end

  def test_to_h_is_serializable
    record = StateMachines::Audit::TransitionRecord.new(
      machine_identity: 'M', definition_fingerprint: 'f',
      event: :ignite, from: :parked, to: :idling, sequence: 1,
      recorded_at: :t, metadata: { actor: 'audit' }
    )

    assert_equal(
      { machine_identity: 'M', definition_fingerprint: 'f', event: :ignite,
        from: :parked, to: :idling, sequence: 1, recorded_at: :t,
        metadata: { actor: 'audit' } },
      record.to_h
    )
  end
end
