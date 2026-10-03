# frozen_string_literal: true

require 'test_helper'

class JointTransitionWithActionErrorTest < StateMachinesTest
  def setup
    @task_class = Class.new do
      state_machine :state, initial: :open do
        event(:hand_off) { transition open: :assigned }
      end
    end
    @person_class = Class.new do
      def save
        raise 'save failed'
      end

      state_machine :state, initial: :busy, action: :save do
        event(:assign) { transition busy: :working }
      end
    end

    @task = @task_class.new
    @person = @person_class.new

    @exception = assert_raises(RuntimeError) do
      StateMachines::JointTransition.new([
                                           { object: @task, machine: :state, event: :hand_off },
                                           { object: @person, machine: :state, event: :assign }
                                         ]).perform
    end
  end

  def test_should_reraise_the_exception
    assert_equal 'save failed', @exception.message
  end

  def test_should_restore_all_participant_states
    assert_equal 'open', @task.state
    assert_equal 'busy', @person.state
  end
end
