# frozen_string_literal: true

require 'test_helper'

class AuditReplayValidatorTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass, initial: :parked)
    @machine.state :parked, :idling, :first_gear
    @machine.event(:ignite) { transition parked: :idling }
    @machine.event(:shift_up) { transition idling: :first_gear, if: :seatbelt_on? }
    @machine.event(:park) { transition first_gear: :parked }

    @definition = StateMachines::Audit::MachineDefinition.from_machine(@machine)
    @fp = @definition.fingerprint
    @id = @definition.identity
    @validator = StateMachines::Audit::ReplayValidator.new(definitions: { @fp => @definition })
  end

  def record(event, from, to, sequence, identity: nil, fingerprint: nil)
    { machine_identity: identity || @id, definition_fingerprint: fingerprint || @fp,
      event: event, from: from, to: to, sequence: sequence }
  end

  def test_accepts_fully_verified_history
    result = @validator.validate([record(:ignite, :parked, :idling, 1)])

    assert_predicate result, :valid?
    assert_predicate result, :fully_verified?
    assert_equal [:verified], result.statuses
    assert_equal :idling, result.projected_state
    assert_equal [:parked, :idling], result.state_path
  end

  def test_guarded_transition_is_unverified_but_not_invalid
    records = [record(:ignite, :parked, :idling, 1),
               record(:shift_up, :idling, :first_gear, 2)]
    result = @validator.validate(records)

    assert_predicate result, :valid?
    refute_predicate result, :fully_verified?
    assert_equal [:verified, :unverified], result.statuses
    assert_equal [1], result.unverified_positions
    assert_match(%r{:if/:unless}, result.unverified_reasons[1].join)
  end

  def test_broken_chain_is_located_at_record_position
    records = [record(:ignite, :parked, :idling, 1),
               record(:ignite, :parked, :idling, 2)]
    result = @validator.validate(records)

    refute_predicate result, :valid?
    assert_equal :broken_chain, result.errors.first.code
    assert_equal 1, result.errors.first.position
    assert_equal 2, result.errors.first.sequence
  end

  def test_illegal_transition_is_reported_and_not_skipped
    records = [record(:ignite, :parked, :first_gear, 1)]
    result = @validator.validate(records)

    refute_predicate result, :valid?
    assert_equal [:illegal_transition], result.errors.map(&:code)
    assert_equal 0, result.errors.first.position
    assert_empty result.valid_prefix
  end

  def test_valid_prefix_projection_stops_before_invalid_record
    records = [record(:ignite, :parked, :idling, 1),
               record(:ignite, :idling, :parked, 2),
               record(:park, :parked, :idling, 3)]
    result = @validator.validate(records)

    assert_equal 1, result.errors.first.position
    assert_equal [:idling], result.valid_prefix.map(&:to)
    assert_equal :idling, result.projected_state
    assert_equal [:verified, :invalid, :unreached], result.statuses
  end

  def test_sequence_gaps_are_detected
    result = @validator.validate([record(:ignite, :parked, :idling, 3)])

    refute_predicate result, :valid?
    assert_equal :sequence_gap, result.errors.first.code
  end

  def test_present_sequence_mode_allows_non_unit_start
    validator = StateMachines::Audit::ReplayValidator.new(
      definitions: { @fp => @definition }, check_sequence: :present
    )
    result = validator.validate([record(:ignite, :parked, :idling, 40),
                                 record(:shift_up, :idling, :first_gear, 41)])

    assert_predicate result, :valid?
  end

  def test_present_sequence_mode_detects_non_increasing_sequence
    validator = StateMachines::Audit::ReplayValidator.new(
      definitions: { @fp => @definition }, check_sequence: :present
    )
    result = validator.validate([record(:ignite, :parked, :idling, 2),
                                 record(:shift_up, :idling, :first_gear, 2)])

    refute_predicate result, :valid?
    assert_equal :sequence_out_of_order, result.errors.first.code
    assert_equal 1, result.errors.first.position
  end

  def test_sequence_can_be_disabled
    validator = StateMachines::Audit::ReplayValidator.new(
      definitions: { @fp => @definition }, check_sequence: false
    )
    result = validator.validate([record(:ignite, :parked, :idling, nil)])

    assert_predicate result, :valid?
  end

  def test_identity_mismatch_is_detected
    result = @validator.validate([
      record(:ignite, :parked, :idling, 1),
      record(:shift_up, :idling, :first_gear, 2, identity: 'Other#state')
    ])

    refute_predicate result, :valid?
    assert_equal :identity_mismatch, result.errors.first.code
    assert_equal 1, result.errors.first.position
  end

  def test_initial_state_is_enforced_when_configured
    validator = StateMachines::Audit::ReplayValidator.new(
      definitions: { @fp => @definition }, initial_state: :parked
    )
    valid = validator.validate([record(:ignite, :parked, :idling, 1)])
    invalid = validator.validate([record(:shift_up, :idling, :first_gear, 1)])

    assert_predicate valid, :valid?
    assert_equal :broken_chain, invalid.errors.first.code
  end

  def test_unknown_fingerprint_is_unverified_by_default
    result = @validator.validate([
      record(:ignite, :parked, :idling, 1, fingerprint: 'unknown-fp')
    ])

    assert_predicate result, :valid?
    refute_predicate result, :fully_verified?
    assert_equal [:unverified], result.statuses
    assert_match(/no machine definition/, result.unverified_reasons[0].join)
  end

  def test_unknown_fingerprint_is_an_error_when_required
    validator = StateMachines::Audit::ReplayValidator.new(
      definitions: { @fp => @definition }, require_definition: true
    )
    result = validator.validate([
      record(:ignite, :parked, :idling, 1, fingerprint: 'unknown-fp')
    ])

    refute_predicate result, :valid?
    assert_equal :unknown_definition, result.errors.first.code
  end

  def test_missing_fields_are_structural_errors
    result = @validator.validate([
      { machine_identity: nil, definition_fingerprint: nil, event: nil,
        from: nil, to: nil, sequence: nil }
    ])

    codes = result.errors.map(&:code)
    assert_includes codes, :missing_identity
    assert_includes codes, :missing_fingerprint
    assert_includes codes, :missing_event
    assert_includes codes, :missing_from
    assert_includes codes, :missing_to
    assert_includes codes, :missing_sequence
    assert_equal [:invalid], result.statuses
  end

  def test_all_structural_errors_are_reported_even_after_replay_stop
    records = [record(:ignite, :parked, :first_gear, 1),
               { machine_identity: @id, definition_fingerprint: @fp, event: nil,
                 from: nil, to: nil, sequence: 2 }]
    result = @validator.validate(records)

    assert_includes result.errors.map(&:code), :illegal_transition
    assert_includes result.errors.map(&:code), :missing_event
  end

  def test_unknown_event_and_unknown_state_are_positioned
    bad_event = [record(:explode, :parked, :idling, 1)]
    bad_state = [record(:ignite, :parked, :flying, 1)]

    assert_equal :unknown_event, @validator.validate(bad_event).errors.first.code
    assert_equal :unknown_state, @validator.validate(bad_state).errors.first.code
  end

  def test_validate_bang_raises_with_position
    error = assert_raises(StateMachines::Audit::ReplayViolation) do
      @validator.validate!([record(:ignite, :parked, :first_gear, 1)])
    end

    assert_match(/record 0/, error.message)
    refute_predicate error.result, :valid?
  end

  def test_empty_history_is_valid_and_not_fully_verified_without_initial_state
    result = @validator.validate([])

    assert_predicate result, :valid?
    assert_predicate result, :fully_verified?
    assert_nil result.projected_state
    assert_empty result.state_path
  end

  def test_does_not_run_action_or_guards
    machine = StateMachines::Machine.new(Class.new do
      def save
        raise 'action must never run during replay'
      end
    end, :state, action: :save, initial: :parked)
    machine.state :parked, :idling
    machine.event(:ignite) { transition parked: :idling, if: :never_called? }

    definition = StateMachines::Audit::MachineDefinition.from_machine(machine)
    validator = StateMachines::Audit::ReplayValidator.new(definitions: { definition.fingerprint => definition })
    record = StateMachines::Audit::TransitionRecord.new(
      machine_identity: definition.identity, definition_fingerprint: definition.fingerprint,
      event: :ignite, from: :parked, to: :idling, sequence: 1
    )

    result = validator.validate([record])
    assert_predicate result, :valid?
    assert_equal [:unverified], result.statuses
  end
end
