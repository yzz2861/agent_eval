# frozen_string_literal: true

require 'test_helper'

class TransitionCollectionWithStateInvariantsAcrossMachinesTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :state, :label_state, :tracking_number, :label, :checked, :save_count

      def save
        @save_count ||= 0
        @save_count += 1
        true
      end
    end

    @state_machine = StateMachines::Machine.new(@klass, :state, initial: :pending, action: :save)
    @state_machine.state :shipped
    @state_machine.event :ship do
      transition pending: :shipped
    end

    @label_machine = StateMachines::Machine.new(@klass, :label_state, initial: :unlabeled, action: :save)
    @label_machine.state :labeled
    @label_machine.event :label do
      transition unlabeled: :labeled
    end

    @object = @klass.new
  end

  def transitions
    StateMachines::TransitionCollection.new([
                                            StateMachines::Transition.new(@object, @state_machine, :ship, :pending, :shipped),
                                            StateMachines::Transition.new(@object, @label_machine, :label, :unlabeled, :labeled)
                                          ])
  end

  def test_should_succeed_when_all_target_state_invariants_hold
    @state_machine.state :shipped, invariant: ->(object) { !object.tracking_number.nil? }
    @label_machine.state :labeled, invariant: ->(object) { !object.label.nil? }
    @object.tracking_number = 'T1'
    @object.label = 'L1'

    assert transitions.perform
    assert_equal 'shipped', @object.state
    assert_equal 'labeled', @object.label_state
  end

  def test_should_check_every_target_state_before_reporting_failure
    checked = []
    @state_machine.state :shipped, invariant: ->(_object) { checked << :state; false }
    @label_machine.state :labeled, invariant: ->(_object) { checked << :label; false }

    refute transitions.perform
    assert_equal %i[state label], checked
  end

  def test_should_roll_back_every_managed_state_when_one_invariant_fails
    @state_machine.state :shipped, invariant: ->(_object) { false }
    @label_machine.state :labeled, invariant: ->(_object) { true }

    refute transitions.perform
    assert_equal 'pending', @object.state
    assert_equal 'unlabeled', @object.label_state
  end

  def test_should_roll_back_every_managed_state_when_an_invariant_raises
    @state_machine.state :shipped, invariant: ->(_object) { true }
    @label_machine.state :labeled, invariant: ->(_object) { raise ArgumentError, 'label boom' }

    exception = assert_raises(ArgumentError) { transitions.perform }
    assert_equal 'label boom', exception.message
    assert_equal 'pending', @object.state
    assert_equal 'unlabeled', @object.label_state
  end

  def test_should_run_the_shared_action_only_once
    @state_machine.state :shipped, invariant: ->(_object) { true }
    @label_machine.state :labeled, invariant: ->(_object) { true }

    transitions.perform

    assert_equal 1, @object.save_count
  end

  def test_should_reraise_and_roll_back_when_false_and_exception_both_occur
    @state_machine.state :shipped, invariant: ->(_object) { false }
    @label_machine.state :labeled, invariant: ->(_object) { raise ArgumentError, 'label boom' }

    exception = assert_raises(ArgumentError) { transitions.perform }
    assert_equal 'label boom', exception.message
    assert_equal 'pending', @object.state
    assert_equal 'unlabeled', @object.label_state
  end
end
