# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithWeightsTest < StateMachinesTest
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
    @machine.event :jump do
      transition parked: :first_gear
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_prefer_cheaper_route_over_shorter_route
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 10 }).plan
    assert_equal %i[ignite shift_up], plan.events
    assert_equal 2, plan.total_cost
  end

  def test_should_prefer_direct_route_when_cheaper
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 1, shift_up: 5 }).plan
    assert_equal [:jump], plan.events
    assert_equal 1, plan.total_cost
  end

  def test_should_sum_weights_along_route
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { ignite: 3, shift_up: 4, jump: 100 }).plan
    assert_equal %i[ignite shift_up], plan.events
    assert_equal 7, plan.total_cost
  end

  def test_should_accept_string_event_names_in_weights
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { 'jump' => 10 }).plan
    assert_equal %i[ignite shift_up], plan.events
  end

  def test_should_accept_zero_weight
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 0 }).plan
    assert_equal [:jump], plan.events
    assert_equal 0, plan.total_cost
  end

  def test_should_raise_on_negative_weight
    assert_raises(ArgumentError) do
      StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: -1 })
    end
  end

  def test_should_raise_on_non_numeric_weight
    assert_raises(ArgumentError) do
      StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 'cheap' })
    end
  end

  def test_should_raise_on_unknown_event_in_weights
    assert_raises(ArgumentError) do
      StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { fly: 1 })
    end
  end

  def test_should_raise_on_non_hash_weights
    assert_raises(ArgumentError) do
      StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: [1, 2])
    end
  end
end
