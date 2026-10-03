# frozen_string_literal: true

require 'test_helper'

class PlannerWithUnreachableTargetTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :stalled
    @machine.event :ignite do
      transition parked: :idling
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_return_nil_when_target_cannot_be_reached
    assert_nil StateMachines::Planner.new(@object, @machine, to: :stalled).plan
  end

  def test_should_return_empty_plan_when_already_at_target
    plan = StateMachines::Planner.new(@object, @machine, to: :parked).plan

    assert_instance_of StateMachines::Plan, plan
    assert_predicate plan, :empty?
    assert_empty plan.events
    assert_equal 0, plan.total_cost
    assert_predicate plan, :verified?
  end
end
