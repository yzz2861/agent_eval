# frozen_string_literal: true

require 'test_helper'

class PlannerWithSimpleMachineTest < StateMachinesTest
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
    @machine.event :push, weight: 10 do
      transition parked: :first_gear
    end
    @object = @klass.new
    @object.state = 'parked'

    @plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan
  end

  def test_should_find_a_plan
    assert_instance_of StateMachines::Plan, @plan
  end

  def test_should_choose_cheapest_route_over_fewer_events
    assert_equal %i[ignite shift_up], @plan.events
  end

  def test_should_sum_event_weights_as_total_cost
    assert_equal 2, @plan.total_cost
  end

  def test_should_track_from_and_to_names
    assert_equal :parked, @plan.from_name
    assert_equal :first_gear, @plan.to_name
  end

  def test_should_build_steps_with_states_and_weights
    assert_equal [
      StateMachines::Plan::Step.new(event: :ignite, from_name: :parked, to_name: :idling, weight: 1, guards: {}),
      StateMachines::Plan::Step.new(event: :shift_up, from_name: :idling, to_name: :first_gear, weight: 1, guards: {})
    ], @plan.steps
  end

  def test_should_have_no_pending_guards
    assert_empty @plan.pending_guards
    assert_predicate @plan, :verified?
  end

  def test_should_plan_from_custom_from_state
    plan = StateMachines::Planner.new(@object, @machine, from: :idling, to: :first_gear).plan

    assert_equal %i[shift_up], plan.events
  end
end
