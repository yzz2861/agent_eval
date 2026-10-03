# frozen_string_literal: true

require 'test_helper'

class JointTransitionByDefaultTest < StateMachinesTest
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

    @task = @task_class.new
    @person = @person_class.new

    @result = StateMachines::JointTransition.new([
                                                  { object: @task, machine: :state, event: :hand_off },
                                                  { object: @person, machine: :state, event: :assign }
                                                ]).perform
  end

  def test_should_succeed
    assert_equal true, @result
  end

  def test_should_transition_all_participants
    assert_equal 'assigned', @task.state
    assert_equal 'working', @person.state
  end

  def test_should_expose_module_level_shortcut
    task = @task_class.new
    person = @person_class.new

    result = StateMachines.joint_transition([
                                              { object: task, machine: :state, event: :hand_off },
                                              { object: person, machine: :state, event: :assign }
                                            ])

    assert_equal true, result
    assert_equal 'assigned', task.state
    assert_equal 'working', person.state
  end
end
