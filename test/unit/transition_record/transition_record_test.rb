# frozen_string_literal: true

require 'test_helper'

class TransitionRecordTest < StateMachinesTest
  def setup
    @klass = Class.new do
      def self.name
        'Vehicle'
      end
    end
    @machine = StateMachines::Machine.new(@klass, :state, initial: :parked)
    @machine.event(:ignite) { transition parked: :idling }
    @object = @klass.new
    @transition = StateMachines::Transition.new(@object, @machine, :ignite, :parked, :idling)
  end

  def test_should_capture_all_fields_from_machine_and_transition
    record = StateMachines::TransitionRecord.capture(@machine, @transition, 7)

    assert_equal 'Vehicle#state(state)', record.machine
    assert_equal StateMachines::TransitionRecord.definition_fingerprint(@machine), record.definition
    assert_equal :ignite, record.event
    assert_equal :parked, record.from
    assert_equal :idling, record.to
    assert_equal 7, record.sequence
  end

  def test_should_identify_machine_by_owner_class_name_and_attribute
    machine = StateMachines::Machine.new(@klass, :alarm, attribute: :alarm_status)

    assert_equal 'Vehicle#alarm(alarm_status)', StateMachines::TransitionRecord.machine_identity(machine)
  end

  def test_should_generate_stable_definition_fingerprint
    assert_equal StateMachines::TransitionRecord.definition_fingerprint(@machine),
                 StateMachines::TransitionRecord.definition_fingerprint(@machine)
  end

  def test_should_change_fingerprint_when_transitions_change
    before = StateMachines::TransitionRecord.definition_fingerprint(@machine)
    @machine.event(:park) { transition idling: :parked }

    refute_equal before, StateMachines::TransitionRecord.definition_fingerprint(@machine)
  end

  def test_should_change_fingerprint_when_guards_change
    before = StateMachines::TransitionRecord.definition_fingerprint(@machine)
    machine = StateMachines::Machine.new(@klass, :state, initial: :parked)
    machine.event(:ignite) { transition parked: :idling, if: :seatbelt_on? }

    refute_equal before, StateMachines::TransitionRecord.definition_fingerprint(machine)
  end

  def test_should_differ_between_machines
    other = StateMachines::Machine.new(@klass, :alarm, initial: :parked)
    other.event(:ignite) { transition parked: :idling }

    refute_equal StateMachines::TransitionRecord.definition_fingerprint(@machine),
                 StateMachines::TransitionRecord.definition_fingerprint(other)
  end

  def test_should_round_trip_through_hash
    record = StateMachines::TransitionRecord.capture(@machine, @transition, 3)

    assert_equal record, StateMachines::TransitionRecord.from_h(record.to_h)
  end

  def test_should_build_from_string_keyed_hash
    record = StateMachines::TransitionRecord.capture(@machine, @transition, 3)
    hash = record.to_h.each_with_object({}) { |(key, value), memo| memo[key.to_s] = value }

    assert_equal record, StateMachines::TransitionRecord.from_h(hash)
  end

  def test_should_symbolize_string_event_and_states
    record = StateMachines::TransitionRecord.from_h(
      machine: 'Vehicle#state(state)', definition: 'abc', event: 'ignite',
      from: 'parked', to: 'idling', sequence: 1
    )

    assert_equal :ignite, record.event
    assert_equal :parked, record.from
    assert_equal :idling, record.to
  end

  def test_should_raise_on_unknown_keys
    exception = assert_raises(ArgumentError) do
      StateMachines::TransitionRecord.from_h(machine: 'm', definition: 'd', event: :e, from: :a, to: :b, sequence: 1, bogus: true)
    end

    assert_match(/Unknown keys: :bogus/, exception.message)
  end

  def test_should_raise_on_missing_keys
    exception = assert_raises(ArgumentError) do
      StateMachines::TransitionRecord.from_h(machine: 'm', definition: 'd')
    end

    assert_match(/Missing keys: :event, :from, :to, :sequence/, exception.message)
  end

  def test_should_expose_all_fields_in_hash
    record = StateMachines::TransitionRecord.capture(@machine, @transition, 1)

    assert_equal %i[machine definition event from to sequence], record.to_h.keys
  end

  def test_should_not_equal_record_with_different_sequence
    first = StateMachines::TransitionRecord.capture(@machine, @transition, 1)
    second = StateMachines::TransitionRecord.capture(@machine, @transition, 2)

    refute_equal first, second
  end
end
