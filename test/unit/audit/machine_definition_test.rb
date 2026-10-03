# frozen_string_literal: true

require 'test_helper'

class AuditMachineDefinitionTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass, initial: :parked)
    @machine.state :parked, :idling, :first_gear
    @machine.event(:ignite) { transition parked: :idling }
    @machine.event(:shift_up) { transition idling: :first_gear, if: :seatbelt_on? }
    @machine.event(:idle) { transition same => same }
    @definition = StateMachines::Audit::MachineDefinition.from_machine(@machine)
  end

  def test_captures_states_and_initial_state
    assert_equal %i[first_gear idling parked], @definition.states
    assert_equal :parked, @definition.initial_state
  end

  def test_authorizes_declared_unguarded_edge
    assert_equal :allowed, @definition.authorize(:ignite, :parked, :idling)
  end

  def test_rejects_illegal_combination
    assert_equal :illegal, @definition.authorize(:ignite, :parked, :first_gear)
  end

  def test_flags_guarded_edge_as_not_reevaluable
    assert_equal :allowed_guarded, @definition.authorize(:shift_up, :idling, :first_gear)
    edge = @definition.matching_edges(:shift_up, :idling, :first_gear).first
    assert_equal [:if_unless], edge.guard_types
  end

  def test_loopback_matcher_does_not_allow_cross_state_pair
    assert_equal :allowed, @definition.authorize(:idle, :idling, :idling)
    assert_equal :illegal, @definition.authorize(:idle, :parked, :idling)
  end

  def test_reports_unknown_event_and_state
    assert_equal :unknown_event, @definition.authorize(:explode, :parked, :idling)
    assert_equal :unknown_state, @definition.authorize(:ignite, :parked, :flying)
  end

  def test_fingerprint_is_stable_and_sensitive
    again = StateMachines::Audit::MachineDefinition.from_machine(@machine)
    assert_equal again.fingerprint, @definition.fingerprint

    other = StateMachines::Audit::MachineDefinition.new(
      identity: @definition.identity, states: @definition.states,
      edges: @definition.edges + [StateMachines::Audit::Edge.new(
        event: :ignite, pairs: [[:parked, :first_gear]], guarded: false, guard_types: []
      )]
    )
    refute_equal other.fingerprint, @definition.fingerprint
  end

  def test_records_cross_machine_state_guards
    machine = StateMachines::Machine.new(@klass, :alarm, initial: :off)
    machine.state :off, :on
    machine.event(:disable) { transition from: :on, to: :off, if_state: { alarm: :off } }

    definition = StateMachines::Audit::MachineDefinition.from_machine(machine)
    assert_equal :allowed_guarded, definition.authorize(:disable, :on, :off)
    assert_includes definition.edges.first.guard_types, :state_guard
  end
end
