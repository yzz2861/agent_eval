# frozen_string_literal: true

require 'test_helper'

class PathPlannerTest < StateMachinesTest
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
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_default_from_state_to_current_object_state
    planner = StateMachines::PathPlanner.new(@object, @machine, to: :idling)
    assert_equal :parked, planner.from_name
  end

  def test_should_allow_custom_from_state
    planner = StateMachines::PathPlanner.new(@object, @machine, from: :idling, to: :first_gear)
    assert_equal :idling, planner.from_name
  end

  def test_should_expose_target_state
    planner = StateMachines::PathPlanner.new(@object, @machine, to: :idling)
    assert_equal :idling, planner.to_name
  end

  def test_should_require_to_state
    assert_raises(ArgumentError) { StateMachines::PathPlanner.new(@object, @machine) }
  end

  def test_should_raise_on_invalid_option
    assert_raises(ArgumentError) { StateMachines::PathPlanner.new(@object, @machine, to: :idling, invalid: true) }
  end

  def test_should_raise_on_unknown_from_state
    assert_raises(IndexError) { StateMachines::PathPlanner.new(@object, @machine, from: :unknown, to: :idling) }
  end

  def test_should_raise_on_unknown_to_state
    assert_raises(IndexError) { StateMachines::PathPlanner.new(@object, @machine, to: :unknown) }
  end

  def test_should_plan_single_event_route
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    assert plan.reachable?
    assert_equal [:ignite], plan.events
    assert_equal 1, plan.total_cost
    assert_equal [], plan.unverified_guards
  end

  def test_should_plan_multi_event_route
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear).plan
    assert_equal %i[ignite shift_up], plan.events
    assert_equal 2, plan.total_cost
  end

  def test_should_plan_empty_route_when_already_on_target
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :parked).plan
    assert plan.reachable?
    assert_equal [], plan.events
    assert_equal 0, plan.total_cost
  end

  def test_should_not_modify_object_state
    StateMachines::PathPlanner.new(@object, @machine, to: :first_gear).plan
    assert_equal 'parked', @object.state
  end

  def test_should_not_run_machine_action
    klass = Class.new do
      attr_accessor :saved

      def save
        self.saved = true
      end
    end
    machine = StateMachines::Machine.new(klass, action: :save)
    machine.state :parked, :idling
    machine.event(:ignite) { transition parked: :idling }
    object = klass.new
    object.state = 'parked'

    StateMachines::PathPlanner.new(object, machine, to: :idling).plan
    refute object.saved
  end
end
