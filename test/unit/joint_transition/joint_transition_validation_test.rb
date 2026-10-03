# frozen_string_literal: true

require 'test_helper'

class JointTransitionValidationTest < StateMachinesTest
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

    @task_before_count = 0
    @person_before_count = 0
    @task_class.state_machines[:state].before_transition { @task_before_count += 1 }
    @person_class.state_machines[:state].before_transition { @person_before_count += 1 }

    @task = @task_class.new
    @person = @person_class.new
    @person.assign

    @result = StateMachines::JointTransition.new([
                                                  { object: @task, machine: :state, event: :hand_off },
                                                  { object: @person, machine: :state, event: :assign }
                                                ]).perform
  end

  def test_should_not_succeed
    assert_equal false, @result
  end

  def test_should_not_change_any_participant_state
    assert_equal 'open', @task.state
    assert_equal 'working', @person.state
  end

  def test_should_not_run_any_callbacks
    assert_equal 0, @task_before_count
    assert_equal 1, @person_before_count # ran once by the direct #assign call in setup
  end
end
