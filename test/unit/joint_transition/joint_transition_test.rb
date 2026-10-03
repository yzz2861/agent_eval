# frozen_string_literal: true

require 'test_helper'

class JointTransitionTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_reader :saved
      attr_accessor :save_result

      def save
        @saved = true
        @save_result != false
      end
    end

    @machine = StateMachines::Machine.new(@klass, :state, initial: :parked, action: :save)
    @machine.event :ignite do
      transition parked: :idling
    end
    @machine.event :park do
      transition idling: :parked
    end

    @first = @klass.new
    @second = @klass.new
  end

  def test_should_transition_all_participants
    result = StateMachines::JointTransition.perform([
                                                       { object: @first, machine: :state, event: :ignite },
                                                       { object: @second, machine: :state, event: :ignite }
                                                     ])

    assert result
    assert_equal 'idling', @first.state
    assert_equal 'idling', @second.state
    assert @first.saved
    assert @second.saved
  end

  def test_should_accept_array_participants_and_machine_instances
    result = StateMachines::JointTransition.perform([
                                                       [@first, @machine, :ignite],
                                                       [@second, :state, :ignite]
                                                     ])

    assert result
    assert_equal 'idling', @first.state
    assert_equal 'idling', @second.state
  end

  def test_should_run_callbacks_for_all_participants
    before_count = after_count = 0
    @machine.before_transition { before_count += 1 }
    @machine.after_transition { after_count += 1 }

    StateMachines::JointTransition.perform([
                                             { object: @first, machine: :state, event: :ignite },
                                             { object: @second, machine: :state, event: :ignite }
                                           ])

    assert_equal 2, before_count
    assert_equal 2, after_count
  end

  def test_should_not_transition_anything_if_any_participant_cannot_transition
    @second.state = 'idling'

    result = StateMachines::JointTransition.perform([
                                                       { object: @first, machine: :state, event: :ignite },
                                                       { object: @second, machine: :state, event: :ignite }
                                                     ])

    refute result
    assert_equal 'parked', @first.state
    assert_equal 'idling', @second.state
    refute @first.saved
    refute @second.saved
  end

  def test_should_run_failure_callbacks_only_for_failed_participants
    failures = []
    @machine.after_failure { |object| failures << object }
    @second.state = 'idling'

    StateMachines::JointTransition.perform([
                                             { object: @first, machine: :state, event: :ignite },
                                             { object: @second, machine: :state, event: :ignite }
                                           ])

    assert_equal [@second], failures
  end

  def test_should_not_run_transition_callbacks_if_validation_fails
    before_count = 0
    @machine.before_transition { before_count += 1 }
    @second.state = 'idling'

    StateMachines::JointTransition.perform([
                                             { object: @first, machine: :state, event: :ignite },
                                             { object: @second, machine: :state, event: :ignite }
                                           ])

    assert_equal 0, before_count
  end

  def test_should_restore_all_states_if_an_action_fails
    @second.save_result = false

    result = StateMachines::JointTransition.perform([
                                                       { object: @first, machine: :state, event: :ignite },
                                                       { object: @second, machine: :state, event: :ignite }
                                                     ])

    refute result
    assert_equal 'parked', @first.state
    assert_equal 'parked', @second.state
  end

  def test_should_restore_all_states_and_reraise_if_an_action_raises
    @second.define_singleton_method(:save) { raise 'save failed' }

    assert_raises(RuntimeError) do
      StateMachines::JointTransition.perform([
                                               { object: @first, machine: :state, event: :ignite },
                                               { object: @second, machine: :state, event: :ignite }
                                             ])
    end

    assert_equal 'parked', @first.state
    assert_equal 'parked', @second.state
  end

  def test_should_reject_duplicate_objects_before_execution
    callback_run = false
    @machine.before_transition { callback_run = true }

    exception = assert_raises(ArgumentError) do
      StateMachines::JointTransition.perform([
                                               { object: @first, machine: :state, event: :ignite },
                                               { object: @first, machine: :state, event: :park }
                                             ])
    end
    assert_match(/same object listed more than once/, exception.message)

    assert_equal 'parked', @first.state
    refute callback_run
    refute @first.saved
  end

  def test_should_raise_exception_if_invalid_event_specified
    exception = assert_raises(StateMachines::InvalidEvent) do
      StateMachines::JointTransition.perform([
                                               { object: @first, machine: :state, event: :invalid },
                                               { object: @second, machine: :state, event: :ignite }
                                             ])
    end
    assert_equal :invalid, exception.event
    assert_equal 'parked', @second.state
  end

  def test_should_raise_exception_if_unknown_machine_specified
    assert_raises(ArgumentError) do
      StateMachines::JointTransition.perform([
                                               { object: @first, machine: :unknown, event: :ignite }
                                             ])
    end
  end

  def test_should_raise_exception_if_no_participants_given
    assert_raises(ArgumentError) { StateMachines::JointTransition.perform([]) }
  end

  def test_should_raise_exception_for_malformed_participants
    assert_raises(ArgumentError) { StateMachines::JointTransition.perform([[@first, :state]]) }
    assert_raises(ArgumentError) { StateMachines::JointTransition.perform([{ object: @first, machine: :state }]) }
    assert_raises(ArgumentError) { StateMachines::JointTransition.perform([@first]) }
  end

  def test_should_allow_participants_with_the_same_attribute_name
    other_class = Class.new
    other_machine = StateMachines::Machine.new(other_class, :state, initial: :off)
    other_machine.event(:flip) { transition off: :on }
    other = other_class.new

    result = StateMachines::JointTransition.perform([
                                                       { object: @first, machine: :state, event: :ignite },
                                                       { object: other, machine: :state, event: :flip }
                                                     ])

    assert result
    assert_equal 'idling', @first.state
    assert_equal 'on', other.state
  end

  def test_concurrent_groups_with_reversed_order_do_not_deadlock
    first = @klass.new
    second = @klass.new
    errors = []

    threads = [
      Thread.new do
        30.times do
          StateMachines::JointTransition.perform([[first, :state, :ignite], [second, :state, :ignite]])
          StateMachines::JointTransition.perform([[first, :state, :park], [second, :state, :park]])
        end
      rescue StandardError => e
        errors << e
      end,
      Thread.new do
        30.times do
          StateMachines::JointTransition.perform([[second, :state, :ignite], [first, :state, :ignite]])
          StateMachines::JointTransition.perform([[second, :state, :park], [first, :state, :park]])
        end
      rescue StandardError => e
        errors << e
      end
    ]

    completed = threads.map { |thread| thread.join(10) }
    assert(completed.all?, 'concurrent joint transitions deadlocked')
    assert_empty errors
    assert_equal first.state, second.state
  end
end
