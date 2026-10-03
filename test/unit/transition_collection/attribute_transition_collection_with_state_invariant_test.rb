# frozen_string_literal: true

require 'test_helper'

class AttributeTransitionCollectionWithStateInvariantTest < StateMachinesTest
  def setup
    @superclass = Class.new do
      def save
        true
      end
    end

    @klass = Class.new(@superclass) do
      attr_accessor :tracking_number

      def save
        self.tracking_number ||= 'T123'
        super
      end
    end

    @machine = StateMachines::Machine.new(@klass, initial: :pending, action: :save)
    @machine.state :shipped
    @machine.event :ship do
      transition pending: :shipped
    end
    @machine.state :shipped, invariant: ->(object) { !object.tracking_number.nil? }

    @object = @klass.new
    @object.state_event = 'ship'
    @result = @object.save
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

class AttributeTransitionCollectionWithFailingStateInvariantTest < StateMachinesTest
  def setup
    @superclass = Class.new do
      def save
        true
      end
    end

    @klass = Class.new(@superclass) do
      attr_accessor :tracking_number, :failure_callbacks, :after_callbacks
    end

    @machine = StateMachines::Machine.new(@klass, initial: :pending, action: :save)
    @machine.state :shipped
    @machine.event :ship do
      transition pending: :shipped
    end
    @machine.state :shipped, invariant: ->(object) { !object.tracking_number.nil? }
    @machine.after_failure { |object| (object.failure_callbacks ||= []) << :failure }
    @machine.after_transition { |object| (object.after_callbacks ||= []) << :after }

    @object = @klass.new
    @object.state_event = 'ship'
    @result = @object.save
  end

  def test_should_return_the_failed_action_result
    refute @result
  end

  def test_should_roll_back_state
    assert_equal 'pending', @object.state
  end

  def test_should_restore_the_event_on_rollback
    assert_equal :ship, @object.state_event
  end

  def test_should_run_failure_callbacks
    assert_equal [:failure], @object.failure_callbacks
  end

  def test_should_not_run_after_callbacks
    assert_nil @object.after_callbacks
  end
end
