# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithUnreachableTargetTest < StateMachinesTest
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

  def test_should_not_be_reachable
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :stalled).plan
    refute plan.reachable?
  end

  def test_should_have_empty_events
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :stalled).plan
    assert_equal [], plan.events
  end

  def test_should_have_nil_total_cost
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :stalled).plan
    assert_nil plan.total_cost
  end

  def test_should_have_no_unverified_guards
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :stalled).plan
    assert_equal [], plan.unverified_guards
  end
end
