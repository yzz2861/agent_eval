# frozen_string_literal: true

require 'test_helper'

class PathPlanTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @object = @klass.new
  end

  def build_plan(options = {})
    StateMachines::PathPlan.new(**{ object: @object, machine: @machine, from_name: :parked, to_name: :idling }.merge(options))
  end

  def test_should_be_reachable_when_total_cost_is_present
    plan = build_plan(events: [:ignite], total_cost: 1)
    assert plan.reachable?
    assert_equal [:ignite], plan.events
    assert_equal 1, plan.total_cost
  end

  def test_should_not_be_reachable_by_default
    plan = build_plan
    refute plan.reachable?
    assert_equal [], plan.events
    assert_nil plan.total_cost
    assert_equal [], plan.unverified_guards
  end

  def test_should_freeze_events_and_unverified_guards
    plan = build_plan(events: [:ignite], total_cost: 1, unverified_guards: [{ type: :if, condition: :ready? }])
    assert plan.events.frozen?
    assert plan.unverified_guards.frozen?
  end

  def test_should_compare_equality_by_content
    first = build_plan(events: [:ignite], total_cost: 1)
    second = build_plan(events: [:ignite], total_cost: 1)
    assert_equal first, second
  end

  def test_should_not_equal_plan_with_different_events
    first = build_plan(events: [:ignite], total_cost: 1)
    second = build_plan(events: [:shift_up], total_cost: 1)
    refute_equal first, second
  end

  def test_should_not_equal_plan_with_different_cost
    first = build_plan(events: [:ignite], total_cost: 1)
    second = build_plan(events: [:ignite], total_cost: 2)
    refute_equal first, second
  end

  def test_should_inspect_reachable_plan
    plan = build_plan(events: [:ignite], total_cost: 1)
    assert_equal '#<StateMachines::PathPlan :parked -> :idling events=[:ignite] total_cost=1 unverified_guards=0>', plan.inspect
  end

  def test_should_inspect_unreachable_plan
    plan = build_plan
    assert_equal '#<StateMachines::PathPlan :parked -> :idling unreachable>', plan.inspect
  end
end
