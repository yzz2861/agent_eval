# frozen_string_literal: true

require 'test_helper'

class JointTransitionConcurrencyTest < StateMachinesTest
  def setup
    @klass = Class.new do
      state_machine :state, initial: :open do
        event(:hand_off) { transition open: :assigned }
        event(:release) { transition assigned: :open }
      end
    end
    @objects = Array.new(4) { @klass.new }
  end

  def test_should_not_deadlock_when_groups_list_same_objects_in_opposite_orders
    forward = @objects.map { |object| { object: object, machine: :state, event: :hand_off } }
    backward = @objects.reverse.map { |object| { object: object, machine: :state, event: :release } }

    errors = []
    threads = [
      Thread.new do
        25.times do
          StateMachines.joint_transition(forward)
          StateMachines.joint_transition(backward)
        end
      rescue StandardError => e
        errors << e
      end,
      Thread.new do
        25.times do
          StateMachines.joint_transition(backward)
          StateMachines.joint_transition(forward)
        end
      rescue StandardError => e
        errors << e
      end
    ]

    threads.each { |thread| thread.join(30) }

    assert threads.none?(&:alive?), 'joint transitions deadlocked'
    assert_empty errors
  end

  def test_should_keep_states_consistent_under_concurrent_groups
    forward = @objects.map { |object| { object: object, machine: :state, event: :hand_off } }
    backward = @objects.reverse.map { |object| { object: object, machine: :state, event: :release } }

    threads = [
      Thread.new { 25.times { StateMachines.joint_transition(forward) && StateMachines.joint_transition(backward) } },
      Thread.new { 25.times { StateMachines.joint_transition(backward.reverse) && StateMachines.joint_transition(forward.reverse) } }
    ]
    threads.each { |thread| thread.join(30) }

    assert threads.none?(&:alive?), 'joint transitions deadlocked'
    @objects.each do |object|
      assert_includes %w[open assigned], object.state
    end
  end
end
