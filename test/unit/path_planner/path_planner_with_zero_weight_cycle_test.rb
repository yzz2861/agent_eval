# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithZeroWeightCycleTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :crank do
      transition parked: same
    end
    @machine.event :rev do
      transition idling: :parked
    end
    @machine.event :ignite do
      transition parked: :idling
    end
    @object = @klass.new
    @object.state = 'parked'
    @weights = { crank: 0, rev: 0, ignite: 0 }
  end

  def test_should_terminate_despite_zero_weight_cycles
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling, weights: @weights).plan
    assert plan.reachable?
  end

  def test_should_not_include_zero_weight_cycle_in_route
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling, weights: @weights).plan
    assert_equal [:ignite], plan.events
    assert_equal 0, plan.total_cost
  end

  def test_should_not_loop_back_through_zero_weight_states
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :parked, from: :idling, weights: @weights).plan
    assert_equal [:rev], plan.events
    assert_equal 0, plan.total_cost
  end
end
