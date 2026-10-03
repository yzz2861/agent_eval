# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithEquivalentRoutesTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :zap do
      transition parked: :idling
    end
    @machine.event :amp do
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

  def test_should_pick_lexicographically_smallest_event_sequence_on_full_tie
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    assert_equal [:amp], plan.events
    assert_equal 1, plan.total_cost
  end

  def test_should_pick_route_with_fewer_events_on_cost_tie
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 2 }).plan
    assert_equal [:jump], plan.events
    assert_equal 2, plan.total_cost
  end

  def test_should_be_deterministic_across_runs
    first = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 2 }).plan
    second = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 2 }).plan
    assert_equal first, second
  end
end
