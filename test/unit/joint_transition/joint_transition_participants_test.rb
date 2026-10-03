# frozen_string_literal: true

require 'test_helper'

class JointTransitionParticipantsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      state_machine :state, initial: :open do
        event(:hand_off) { transition open: :assigned }
      end
    end
    @object = @klass.new
  end

  def test_should_accept_array_participants
    result = StateMachines::JointTransition.new([
                                                  [@object, :state, :hand_off]
                                                ]).perform

    assert_equal true, result
    assert_equal 'assigned', @object.state
  end

  def test_should_default_machine_to_state
    result = StateMachines::JointTransition.new([
                                                  { object: @object, event: :hand_off }
                                                ]).perform

    assert_equal true, result
    assert_equal 'assigned', @object.state
  end

  def test_should_accept_machine_instances
    machine = @klass.state_machines[:state]

    result = StateMachines::JointTransition.new([
                                                  { object: @object, machine: machine, event: :hand_off }
                                                ]).perform

    assert_equal true, result
    assert_equal 'assigned', @object.state
  end

  def test_should_raise_exception_if_no_participants_specified
    exception = assert_raises(ArgumentError) { StateMachines::JointTransition.new([]) }
    assert_equal 'Must specify at least one participant', exception.message
  end

  def test_should_raise_exception_if_participant_is_not_a_hash_or_array
    exception = assert_raises(ArgumentError) { StateMachines::JointTransition.new([@object]) }
    assert_match(/Invalid participant/, exception.message)
  end

  def test_should_raise_exception_if_array_participant_is_malformed
    exception = assert_raises(ArgumentError) { StateMachines::JointTransition.new([[@object, :hand_off]]) }
    assert_match(/Invalid participant/, exception.message)
  end

  def test_should_raise_exception_if_unknown_participant_key_specified
    exception = assert_raises(ArgumentError) do
      StateMachines::JointTransition.new([{ object: @object, event: :hand_off, invalid: true }])
    end
    assert_equal 'Unknown key: :invalid. Valid keys are: :object, :machine, :event', exception.message
  end

  def test_should_raise_exception_if_machine_is_unknown
    exception = assert_raises(ArgumentError) do
      StateMachines::JointTransition.new([{ object: @object, machine: :unknown, event: :hand_off }])
    end
    assert_match(/:unknown is not a state machine defined on/, exception.message)
  end

  def test_should_raise_exception_if_event_is_unknown
    exception = assert_raises(StateMachines::InvalidEvent) do
      StateMachines::JointTransition.new([{ object: @object, machine: :state, event: :invalid }])
    end
    assert_equal ':invalid is an unknown state machine event', exception.message
  end

  def test_should_raise_exception_if_same_object_listed_more_than_once
    other_class = Class.new do
      state_machine :state, initial: :busy do
        event(:assign) { transition busy: :working }
      end
    end

    exception = assert_raises(ArgumentError) do
      StateMachines::JointTransition.new([
                                           { object: @object, machine: :state, event: :hand_off },
                                           { object: other_class.new, machine: :state, event: :assign },
                                           { object: @object, machine: :state, event: :hand_off }
                                         ])
    end
    assert_equal 'Cannot perform a joint transition with the same object listed more than once', exception.message
  end

  def test_should_reject_duplicate_objects_before_executing_anything
    assert_raises(ArgumentError) do
      StateMachines::JointTransition.new([
                                           { object: @object, machine: :state, event: :hand_off },
                                           { object: @object, machine: :state, event: :hand_off }
                                         ])
    end

    assert_equal 'open', @object.state
  end
end
