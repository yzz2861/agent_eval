# frozen_string_literal: true

require 'test_helper'
require 'unit/state_timeout/fake_timeout_scheduler'

class StateTimeoutRaceTest < StateMachinesTest
  def setup
    @scheduler = FakeTimeoutScheduler.new
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass, initial: :pending, timeout_scheduler: @scheduler)
    @machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    @machine.event :pay do
      transition awaiting_payment: :paid
    end
    @machine.event :timeout do
      transition awaiting_payment: :expired
    end
    @machine.state :awaiting_payment, timeout: 300

    @object = @klass.new
    @object.start_payment
  end

  def test_should_ignore_timeout_arriving_after_manual_transition
    entry = @scheduler.entries.first

    assert @object.pay
    assert_equal 'paid', @object.state

    # The timer callback was already in flight when the manual event won
    @scheduler.trigger(entry)

    assert_equal 'paid', @object.state
  end

  def test_should_ignore_manual_event_arriving_after_timeout
    entry = @scheduler.entries.first

    @scheduler.trigger(entry)
    assert_equal 'expired', @object.state

    refute @object.pay
    assert_equal 'expired', @object.state
  end

  def test_should_invalidate_previous_timer_when_state_is_reentered
    @machine.event :retry_payment do
      transition awaiting_payment: :awaiting_payment
    end

    stale = @scheduler.entries.first
    @object.retry_payment
    current = @scheduler.entries.last

    # The callback armed by the previous entry into the state is dead
    @scheduler.trigger(stale)
    assert_equal 'awaiting_payment', @object.state

    # The callback armed by the current entry is still live
    @scheduler.trigger(current)
    assert_equal 'expired', @object.state
  end

  def test_should_invalidate_timer_when_state_is_left_and_reentered
    stale = @scheduler.entries.first
    @object.pay

    @machine.event :refund do
      transition paid: :awaiting_payment
    end
    @object.refund
    current = @scheduler.entries.last

    @scheduler.trigger(stale)
    assert_equal 'awaiting_payment', @object.state

    @scheduler.trigger(current)
    assert_equal 'expired', @object.state
  end
end
