# frozen_string_literal: true

require 'test_helper'

class PathPlannerWithGuardsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :seatbelt_on

      def seatbelt_on?
        @seatbelt_on
      end

      def explosive_guard
        raise 'guard must not be evaluated during planning'
      end
    end
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition parked: :idling, if: :seatbelt_on?, unless: :explosive_guard
    end
    @object = @klass.new
    @object.state = 'parked'
    @object.seatbelt_on = false
  end

  def test_should_treat_unknown_guards_as_passable
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    assert plan.reachable?
    assert_equal [:ignite], plan.events
  end

  def test_should_not_evaluate_unlisted_guards
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    assert_equal [
      { type: :if, condition: :seatbelt_on?, event: :ignite, from: :parked, to: :idling },
      { type: :unless, condition: :explosive_guard, event: :ignite, from: :parked, to: :idling }
    ], plan.unverified_guards
  end

  def test_should_report_unverified_guards_only_once_per_route
    @machine.event :shift_up do
      transition idling: :parked, if: :seatbelt_on?
    end
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :parked, from: :idling).plan
    assert_equal 1, plan.unverified_guards.length
  end

  def test_should_still_recheck_guards_when_firing_planned_events
    @object.define_singleton_method(:explosive_guard) { false }
    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    assert_equal [:ignite], plan.events

    refute @object.ignite
    assert_equal 'parked', @object.state
  end

  def test_should_fire_planned_events_when_guards_actually_pass
    @object.seatbelt_on = true
    @object.define_singleton_method(:explosive_guard) { false }

    plan = StateMachines::PathPlanner.new(@object, @machine, to: :idling).plan
    plan.events.each { |event| assert @object.send(event) }
    assert_equal 'idling', @object.state
  end
end
