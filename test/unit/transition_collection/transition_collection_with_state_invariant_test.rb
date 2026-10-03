# frozen_string_literal: true

require 'test_helper'

class TransitionCollectionWithStateInvariantTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :tracking_number, :saved

      def save
        @saved = true
        self.tracking_number ||= 'T123' if state == 'shipped'
        true
      end
    end

    @machine = StateMachines::Machine.new(@klass, initial: :pending, action: :save)
    @machine.state :shipped
    @machine.event :ship do
      transition pending: :shipped
    end
    @machine.state :shipped, invariant: ->(object) { !object.tracking_number.nil? }

    @object = @klass.new
    @transition = StateMachines::Transition.new(@object, @machine, :ship, :pending, :shipped)
    @transitions = StateMachines::TransitionCollection.new([@transition])
    @result = @transitions.perform
  end

  def test_should_succeed
    assert @result
  end

  def test_should_persist_state
    assert_equal 'shipped', @object.state
  end

  def test_should_observe_values_written_by_the_action
    assert_equal 'T123', @object.tracking_number
  end
end

class TransitionCollectionWithFailingStateInvariantTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :tracking_number, :saved, :after_callbacks, :failure_callbacks

      def save
        @saved = true
        true
      end
    end

    @machine = StateMachines::Machine.new(@klass, initial: :pending, action: :save)
    @machine.state :shipped
    @machine.event :ship do
      transition pending: :shipped
    end
    @machine.state :shipped, invariant: ->(object) { !object.tracking_number.nil? }
    @machine.after_transition { |object| (object.after_callbacks ||= []) << :after }
    @machine.after_failure { |object| (object.failure_callbacks ||= []) << :failure }

    @object = @klass.new
    @transition = StateMachines::Transition.new(@object, @machine, :ship, :pending, :shipped)
    @transitions = StateMachines::TransitionCollection.new([@transition])
    @result = @transitions.perform
  end

  def test_should_not_succeed
    refute @result
  end

  def test_should_have_run_the_action
    assert @object.saved
  end

  def test_should_roll_back_the_managed_state_attribute
    assert_equal 'pending', @object.state
  end

  def test_should_not_run_after_transition_callbacks
    assert_nil @object.after_callbacks
  end

  def test_should_run_failure_callbacks
    assert_equal [:failure], @object.failure_callbacks
  end

  def test_should_not_touch_non_state_attributes_when_rolling_back
    assert @object.saved
    assert_nil @object.tracking_number
  end
end

class TransitionCollectionWithStateInvariantRaisingErrorTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :saved, :failure_callbacks

      def save
        @saved = true
        true
      end
    end

    @machine = StateMachines::Machine.new(@klass, initial: :pending, action: :save)
    @machine.state :shipped
    @machine.event :ship do
      transition pending: :shipped
    end
    @machine.state :shipped, invariant: ->(_object) { raise ArgumentError, 'invariant boom' }
    @machine.after_failure { |object| (object.failure_callbacks ||= []) << :failure }

    @object = @klass.new
    @transition = StateMachines::Transition.new(@object, @machine, :ship, :pending, :shipped)
    @transitions = StateMachines::TransitionCollection.new([@transition])

    @raised = false
    begin
      @transitions.perform
    rescue ArgumentError => e
      @error = e
      @raised = true
    end
  end

  def test_should_propagate_the_exception
    assert @raised
    assert_equal 'invariant boom', @error.message
  end

  def test_should_roll_back_the_managed_state_attribute
    assert_equal 'pending', @object.state
  end

  def test_should_not_run_failure_callbacks_for_hard_exceptions
    assert_nil @object.failure_callbacks
  end

  def test_should_be_distinguishable_from_false_result
    assert_instance_of ArgumentError, @error
  end
end
