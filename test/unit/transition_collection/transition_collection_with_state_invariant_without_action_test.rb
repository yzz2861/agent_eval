# frozen_string_literal: true

require 'test_helper'

class TransitionCollectionWithStateInvariantWithoutActionTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :tracking_number
    end

    @machine = StateMachines::Machine.new(@klass, initial: :pending)
    @machine.state :shipped
    @machine.event :ship do
      transition pending: :shipped
    end
    @machine.state :shipped, invariant: ->(object) { !object.tracking_number.nil? }

    @object = @klass.new
  end

  def test_should_not_check_invariants_when_actions_are_skipped
    transition = StateMachines::Transition.new(@object, @machine, :ship, :pending, :shipped)
    collection = StateMachines::TransitionCollection.new([transition], actions: false)

    assert collection.perform
    assert_equal 'shipped', @object.state
  end

  def test_should_check_invariants_when_an_explicit_action_block_runs
    transition = StateMachines::Transition.new(@object, @machine, :ship, :pending, :shipped)
    collection = StateMachines::TransitionCollection.new([transition], actions: false)

    refute collection.perform { true }
    assert_equal 'pending', @object.state
  end

  def test_should_succeed_when_explicit_block_action_satisfies_invariant
    transition = StateMachines::Transition.new(@object, @machine, :ship, :pending, :shipped)
    collection = StateMachines::TransitionCollection.new([transition], actions: false)

    result = collection.perform do
      @object.tracking_number = 'T1'
      true
    end

    assert result
    assert_equal 'shipped', @object.state
    assert_equal 'T1', @object.tracking_number
  end
end
