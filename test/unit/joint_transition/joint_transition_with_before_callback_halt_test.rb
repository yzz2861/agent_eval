# frozen_string_literal: true

require 'test_helper'

class JointTransitionWithBeforeCallbackHaltTest < StateMachinesTest
  def setup
    @task_class = Class.new do
      state_machine :state, initial: :open do
        event(:hand_off) { transition open: :assigned }
      end
    end
    @person_class = Class.new do
      state_machine :state, initial: :busy do
        event(:assign) { transition busy: :working }
      end
    end

    @task_after_count = 0
    @task_class.state_machines[:state].after_transition { @task_after_count += 1 }
    @person_class.state_machines[:state].before_transition { throw :halt }

    @task = @task_class.new
    @person = @person_class.new

    @result = StateMachines::JointTransition.new([
                                                  { object: @task, machine: :state, event: :hand_off },
                                                  { object: @person, machine: :state, event: :assign }
                                                ]).perform
  end

  def test_should_not_succeed
    assert_equal false, @result
  end

  def test_should_restore_all_participant_states
    assert_equal 'open', @task.state
    assert_equal 'busy', @person.state
  end

  def test_should_not_run_after_callbacks
    assert_equal 0, @task_after_count
  end
end
