# frozen_string_literal: true

require 'test_helper'

class JointTransitionWithCallbacksTest < StateMachinesTest
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

    @before_callbacks = []
    @after_callbacks = []
    @task_class.state_machines[:state].before_transition { @before_callbacks << :task_before }
    @task_class.state_machines[:state].after_transition { @after_callbacks << :task_after }
    @person_class.state_machines[:state].before_transition { @before_callbacks << :person_before }
    @person_class.state_machines[:state].after_transition { @after_callbacks << :person_after }

    @task = @task_class.new
    @person = @person_class.new

    @participants = [
      { object: @task, machine: :state, event: :hand_off },
      { object: @person, machine: :state, event: :assign }
    ]
  end

  def test_should_run_before_callbacks_in_order
    StateMachines::JointTransition.new(@participants).perform

    assert_equal %i[task_before person_before], @before_callbacks
  end

  def test_should_run_after_callbacks_in_reverse_order
    StateMachines::JointTransition.new(@participants).perform

    assert_equal %i[person_after task_after], @after_callbacks
  end

  def test_should_run_all_before_callbacks_before_persisting_any_state
    task = @task
    @person_class.state_machines[:state].before_transition do
      @before_callbacks << task.state
    end

    StateMachines::JointTransition.new(@participants).perform

    assert_equal 'open', @before_callbacks.last
  end
end
