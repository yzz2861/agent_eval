# frozen_string_literal: true

require 'test_helper'

class PlannerWithGuardsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :seatbelt_on

      def seatbelt_on?
        !!seatbelt_on
      end
    end
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @machine.event :ignite do
      transition parked: :idling, if: :seatbelt_on?
    end
    @machine.event :shift_up do
      transition idling: :first_gear
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_not_evaluate_guards_by_default
    @object.seatbelt_on = false
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan

    assert_equal %i[ignite shift_up], plan.events
  end

  def test_should_report_unevaluated_guards_as_pending
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan

    assert_equal [{ event: :ignite, if: [:seatbelt_on?] }], plan.pending_guards
    refute_predicate plan, :verified?
  end

  def test_should_evaluate_whitelisted_guards_that_pass
    @object.seatbelt_on = true
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear, evaluate_guards: [:seatbelt_on?]).plan

    assert_equal %i[ignite shift_up], plan.events
    assert_empty plan.pending_guards
    assert_predicate plan, :verified?
  end

  def test_should_skip_branches_whose_whitelisted_guards_fail
    @object.seatbelt_on = false
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear, evaluate_guards: [:seatbelt_on?]).plan

    assert_nil plan
  end

  def test_should_fall_through_to_later_branches_when_whitelisted_guard_fails
    @machine.event :restart do
      transition parked: :idling, if: :seatbelt_on?
      transition parked: :idling
    end
    @object.seatbelt_on = false
    plan = StateMachines::Planner.new(@object, @machine, from: :parked, to: :idling, evaluate_guards: [:seatbelt_on?]).plan

    assert_equal %i[restart], plan.events
    assert_predicate plan, :verified?
  end

  def test_should_still_recheck_guards_when_event_is_fired
    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan
    assert_equal %i[ignite shift_up], plan.events

    @object.seatbelt_on = false
    refute @object.ignite
    assert_equal 'parked', @object.state
  end
end

class PlannerWithUnlessGuardsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :alarm_on

      def alarm_on?
        !!alarm_on
      end
    end
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition parked: :idling, unless: :alarm_on?
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_report_unevaluated_unless_guards_as_pending
    plan = StateMachines::Planner.new(@object, @machine, to: :idling).plan

    assert_equal [{ event: :ignite, unless: [:alarm_on?] }], plan.pending_guards
  end

  def test_should_skip_branch_when_whitelisted_unless_guard_holds
    @object.alarm_on = true
    plan = StateMachines::Planner.new(@object, @machine, to: :idling, evaluate_guards: [:alarm_on?]).plan

    assert_nil plan
  end

  def test_should_use_branch_when_whitelisted_unless_guard_does_not_hold
    @object.alarm_on = false
    plan = StateMachines::Planner.new(@object, @machine, to: :idling, evaluate_guards: [:alarm_on?]).plan

    assert_equal %i[ignite], plan.events
    assert_predicate plan, :verified?
  end
end

class PlannerWithProcGuardsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      def ready?
        true
      end
    end
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling
    @guard = ->(object) { object.ready? }
    guard = @guard
    @machine.event :ignite do
      transition parked: :idling, if: guard
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_report_proc_guards_as_pending_by_default
    plan = StateMachines::Planner.new(@object, @machine, to: :idling).plan

    assert_equal [{ event: :ignite, if: [@guard] }], plan.pending_guards
  end

  def test_should_evaluate_whitelisted_proc_guards
    plan = StateMachines::Planner.new(@object, @machine, to: :idling, evaluate_guards: [@guard]).plan

    assert_predicate plan, :verified?
  end
end

class PlannerWithStateGuardsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      state_machine :alarm_state, initial: :active do
        event :disable do
          transition active: :off
        end
      end
    end
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling
    @machine.event :ignite do
      transition parked: :idling, if_state: { alarm_state: :off }
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_report_state_guards_as_pending
    plan = StateMachines::Planner.new(@object, @machine, to: :idling).plan

    assert_equal [{ event: :ignite, state_guards: { if_state: { alarm_state: :off } } }], plan.pending_guards
    refute_predicate plan, :verified?
  end
end
