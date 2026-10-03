# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithStateGuardsTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @alarm_machine = StateMachines::Machine.new(@klass, :alarm, initial: :off)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition parked: :idling, if_state: { alarm: :off }
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_keep_state_guards_as_unverified_conditions
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    assert plan.reachable?
    assert_equal [
      { type: :if_state, condition: { alarm: :off }, event: :ignite, from: :parked, to: :idling }
    ], plan.unverified_guards
  end

  def test_should_not_evaluate_state_guards_even_when_whitelisted
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling, evaluate_guards: [{ alarm: :off }]).plan
    assert_equal 1, plan.unverified_guards.length
  end
end
