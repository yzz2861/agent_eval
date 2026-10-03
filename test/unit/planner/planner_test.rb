# frozen_string_literal: true

require 'test_helper'

class PlannerTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition parked: :idling
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_raise_exception_if_invalid_option_specified
    assert_raises(ArgumentError) { StateMachines::Planner.new(@object, @machine, invalid: true) }
  end

  def test_should_raise_exception_if_no_target_state_specified
    exception = assert_raises(ArgumentError) { StateMachines::Planner.new(@object, @machine) }

    assert_equal 'Must specify a :to target state to plan towards', exception.message
  end

  def test_should_raise_exception_if_from_state_is_invalid
    assert_raises(IndexError) { StateMachines::Planner.new(@object, @machine, from: :invalid, to: :idling) }
  end

  def test_should_raise_exception_if_to_state_is_invalid
    assert_raises(IndexError) { StateMachines::Planner.new(@object, @machine, to: :invalid) }
  end

  def test_should_raise_exception_if_weight_override_is_negative
    exception = assert_raises(ArgumentError) { StateMachines::Planner.new(@object, @machine, to: :idling, weights: { ignite: -1 }) }

    assert_equal 'weight for event :ignite must be a non-negative number, got -1', exception.message
  end

  def test_should_raise_exception_if_weight_override_is_not_numeric
    assert_raises(ArgumentError) { StateMachines::Planner.new(@object, @machine, to: :idling, weights: { ignite: 'cheap' }) }
  end

  def test_should_have_an_object
    planner = StateMachines::Planner.new(@object, @machine, to: :idling)

    assert_equal @object, planner.object
  end

  def test_should_have_a_machine
    planner = StateMachines::Planner.new(@object, @machine, to: :idling)

    assert_equal @machine, planner.machine
  end

  def test_should_default_from_name_to_current_state
    planner = StateMachines::Planner.new(@object, @machine, to: :idling)

    assert_equal :parked, planner.from_name
  end

  def test_should_allow_custom_from_name
    planner = StateMachines::Planner.new(@object, @machine, from: :idling, to: :parked)

    assert_equal :idling, planner.from_name
  end

  def test_should_have_a_to_name
    planner = StateMachines::Planner.new(@object, @machine, to: :idling)

    assert_equal :idling, planner.to_name
  end
end
