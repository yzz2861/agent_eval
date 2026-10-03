# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithDuplicateBranchesTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition parked: :idling, if: :seatbelt_on?
      transition parked: :idling
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_keep_branch_requiring_fewest_verifications
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    assert_equal [:ignite], plan.events
    assert_equal [], plan.unverified_guards
  end
end
