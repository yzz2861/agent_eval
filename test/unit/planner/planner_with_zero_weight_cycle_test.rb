# frozen_string_literal: true

require 'test_helper'

class PlannerWithZeroWeightCycleTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :idle, weight: 0 do
      transition idling: same
    end
    @machine.event :rock, weight: 0 do
      transition parked: :idling, idling: :parked
    end
    @machine.event :shift_up, weight: 2 do
      transition idling: :first_gear
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_terminate_despite_zero_weight_cycles
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan

    assert_equal %i[rock shift_up], plan.events
    assert_equal 2, plan.total_cost
  end

  def test_should_not_include_zero_weight_loops_in_plan
    plan = StateMachines::Planner.new(@object, @machine, to: :idling).plan

    assert_equal %i[rock], plan.events
    assert_equal 0, plan.total_cost
  end

  def test_should_prefer_direct_route_over_zero_weight_detour_with_same_cost
    @machine.event :push, weight: 2 do
      transition parked: :first_gear
    end

    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan

    assert_equal %i[push], plan.events
  end
end
