# frozen_string_literal: true

require 'test_helper'

class MachinePlanForTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass, initial: :parked)
    @machine.state :idling
    @machine.event :ignite, weight: 2 do
      transition parked: :idling
    end
    @object = @klass.new
  end

  def test_should_build_a_plan_for_the_object
    plan = @machine.plan_for(@object, to: :idling)

    assert_instance_of StateMachines::Plan, plan
    assert_equal %i[ignite], plan.events
    assert_equal 2, plan.total_cost
  end

  def test_should_return_nil_when_target_is_unreachable
    @machine.state :stalled

    assert_nil @machine.plan_for(@object, to: :stalled)
  end

  def test_should_expose_instance_helper
    plan = @object.state_plan(to: :idling)

    assert_equal %i[ignite], plan.events
  end
end
