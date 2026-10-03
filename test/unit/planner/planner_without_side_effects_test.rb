# frozen_string_literal: true

require 'test_helper'

class PlannerWithoutSideEffectsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :action_ran, :callback_ran, :guard_ran

      def run_action
        self.action_ran = true
      end

      def tracked_guard
        self.guard_ran = true
        true
      end
    end
    @machine = StateMachines::Machine.new(@klass, action: :run_action)
    @machine.state :parked, :idling
    @machine.before_transition { |object| object.callback_ran = true }
    @machine.event :ignite do
      transition parked: :idling, if: :tracked_guard
    end
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_not_change_the_object_state
    StateMachines::Planner.new(@object, @machine, to: :idling).plan

    assert_equal 'parked', @object.state
  end

  def test_should_not_run_actions
    StateMachines::Planner.new(@object, @machine, to: :idling).plan

    refute @object.action_ran
  end

  def test_should_not_run_callbacks
    StateMachines::Planner.new(@object, @machine, to: :idling).plan

    refute @object.callback_ran
  end

  def test_should_not_evaluate_guards
    StateMachines::Planner.new(@object, @machine, to: :idling).plan

    refute @object.guard_ran
  end

  def test_should_only_evaluate_whitelisted_guards
    StateMachines::Planner.new(@object, @machine, to: :idling, evaluate_guards: [:tracked_guard]).plan

    assert @object.guard_ran
    refute @object.action_ran
    assert_equal 'parked', @object.state
  end
end
