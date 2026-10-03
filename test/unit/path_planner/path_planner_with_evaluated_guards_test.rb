# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithEvaluatedGuardsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :seatbelt_on, :turbo

      def seatbelt_on?
        @seatbelt_on
      end

      def turbo?
        @turbo
      end
    end
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :ignite do
      transition parked: :idling, if: :seatbelt_on?
    end
    @machine.event :boost do
      transition parked: :first_gear, unless: :turbo?
    end
    @machine.event :jump do
      transition parked: :first_gear
    end
    @object = @klass.new
    @object.state = 'parked'
    @object.seatbelt_on = false
    @object.turbo = false
  end

  def test_should_exclude_route_blocked_by_evaluated_if_guard
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling, evaluate_guards: [:seatbelt_on?]).plan
    refute plan.reachable?
  end

  def test_should_include_route_allowed_by_evaluated_if_guard
    @object.seatbelt_on = true
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling, evaluate_guards: [:seatbelt_on?]).plan
    assert_equal [:ignite], plan.events
    assert_equal [], plan.unverified_guards
  end

  def test_should_exclude_route_blocked_by_evaluated_unless_guard
    @object.turbo = true
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 10 }, evaluate_guards: [:turbo?]).plan
    assert_equal [:jump], plan.events
    assert_equal 10, plan.total_cost
  end

  def test_should_use_evaluated_unless_guard_when_it_passes
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 10 }, evaluate_guards: [:turbo?]).plan
    assert_equal [:boost], plan.events
    assert_equal 1, plan.total_cost
  end

  def test_should_evaluate_whitelisted_proc_guard
    guard = ->(object) { object.seatbelt_on? }
    klass = Class.new do
      attr_accessor :seatbelt_on

      def seatbelt_on?
        @seatbelt_on
      end
    end
    machine = StateMachines::Machine.new(klass)
    machine.state :parked, :idling
    machine.event(:ignite) { transition parked: :idling, if: guard }
    object = machine.owner_class.new
    object.state = 'parked'

    plan = StateMachines::PathPlanner.new(object, machine, to: :idling, evaluate_guards: [guard]).plan
    refute plan.reachable?
  end

  def test_should_not_evaluate_proc_guard_requiring_event_arguments
    guard = ->(object, force) { object.seatbelt_on? && force }
    klass = Class.new do
      def seatbelt_on?
        false
      end
    end
    machine = StateMachines::Machine.new(klass)
    machine.state :parked, :idling
    machine.event(:ignite) { transition parked: :idling, if: guard }
    object = machine.owner_class.new
    object.state = 'parked'

    plan = StateMachines::PathPlanner.new(object, machine, to: :idling, evaluate_guards: [guard]).plan
    assert plan.reachable?
    assert_equal [{ type: :if, condition: guard, event: :ignite, from: :parked, to: :idling }], plan.unverified_guards
  end

  def test_should_keep_unlisted_guards_unverified_even_when_listed_ones_pass
    @object.seatbelt_on = true
    @machine.event :shift_up do
      transition idling: :first_gear, if: :turbo?
    end
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :first_gear, weights: { jump: 10, boost: 10 }, evaluate_guards: [:seatbelt_on?]).plan
    assert_equal %i[ignite shift_up], plan.events
    assert_equal [{ type: :if, condition: :turbo?, event: :shift_up, from: :idling, to: :first_gear }], plan.unverified_guards
  end
end
