# frozen_string_literal: true

require 'test_helper'

class PlannerWithEventWeightsTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :ignite, weight: 5 do
      transition parked: :idling
    end
    @machine.event :shift_up, weight: 5 do
      transition idling: :first_gear
    end
    @machine.event :push, weight: 8 do
      transition parked: :first_gear
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_use_weights_defined_on_events
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan

    assert_equal %i[push], plan.events
    assert_equal 8, plan.total_cost
  end

  def test_should_allow_overriding_weights_per_planning_run
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear, weights: { push: 20 }).plan

    assert_equal %i[ignite shift_up], plan.events
    assert_equal 10, plan.total_cost
  end

  def test_should_not_mutate_event_weights_when_overriding
    StateMachines::Planner.new(@object, @machine, to: :first_gear, weights: { push: 20 }).plan

    assert_equal 8, @machine.events[:push].weight
  end

  def test_should_allow_zero_weight_overrides
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear, weights: { ignite: 0, shift_up: 0 }).plan

    assert_equal %i[ignite shift_up], plan.events
    assert_equal 0, plan.total_cost
  end
end
