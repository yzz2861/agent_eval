# frozen_string_literal: true

require 'test_helper'

class MachineWithPlanPathTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :ignite do
      transition parked: :idling
    end
    @machine.event :shift_up do
      transition idling: :first_gear
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_plan_path_for_object
    plan = @machine.plan_path_for(@object, to: :first_gear)
    assert_instance_of StateMachines::PathPlan, plan
    assert_equal %i[ignite shift_up], plan.events
    assert_equal 2, plan.total_cost
  end

  def test_should_pass_weights_through
    plan = @machine.plan_path_for(@object, to: :first_gear, weights: { shift_up: 5 })
    assert_equal 6, plan.total_cost
  end

  def test_should_provide_instance_helper
    plan = @object.state_plan_path(to: :first_gear)
    assert_instance_of StateMachines::PathPlan, plan
    assert_equal %i[ignite shift_up], plan.events
  end

  def test_should_use_custom_attribute_for_instance_helper
    machine = StateMachines::Machine.new(@klass, :alarm, initial: :off)
    machine.state :on
    machine.event(:enable) { transition off: :on }
    object = @klass.new

    plan = object.alarm_plan_path(to: :on)
    assert_equal [:enable], plan.events
  end
end
