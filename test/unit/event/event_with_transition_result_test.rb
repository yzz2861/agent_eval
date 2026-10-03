# frozen_string_literal: true

require 'test_helper'

class EventWithTransitionResultTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :state, :allow_transition

      def initialize
        @state = 'parked'
        @allow_transition = true
      end

      def save
        @allow_transition
      end
    end

    @machine = StateMachines::Machine.new(@klass, initial: :parked, action: :save)
    @machine.state :idling
    @machine.event :ignite do
      transition parked: :idling
    end
  end

  def test_returns_succeeded_result
    object = @klass.new

    result = @machine.event(:ignite).fire_with_result(object)

    assert_equal :succeeded, result.status
    assert result.succeeded?
    assert_equal 'idling', object.state
  end

  def test_returns_guard_rejected_result
    object = @klass.new
    object.state = 'idling'

    result = @machine.event(:ignite).fire_with_result(object)

    assert_equal :guard_rejected, result.status
    assert result.guard_rejected?
    assert_equal 'idling', object.state
  end

  def test_returns_action_failed_result
    object = @klass.new
    object.allow_transition = false

    result = @machine.event(:ignite).fire_with_result(object)

    assert_equal :action_failed, result.status
    assert result.action_failed?
    assert_equal 'parked', object.state
  end
end
