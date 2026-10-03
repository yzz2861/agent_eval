# frozen_string_literal: true

require 'test_helper'
require 'unit/state_timeout/fake_timeout_scheduler'

class StateTimeoutCallbackTimingTest < StateMachinesTest
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
    @entry = @scheduler.entries.first
  end

  def test_should_fire_timeout_when_callback_arrives_early
    # The scheduler is trusted for timing: a callback that arrives before the
    # full delay has elapsed still fires the timeout
    @scheduler.trigger(@entry)

    assert_equal 'expired', @object.state
  end

  def test_should_fire_timeout_when_callback_arrives_on_time
    @scheduler.advance(300)

    assert_equal 'expired', @object.state
  end

  def test_should_not_fire_timeout_before_it_is_due
    @scheduler.advance(299)

    assert_equal 'awaiting_payment', @object.state
  end

  def test_should_discard_callback_arriving_late_after_state_was_left
    @object.pay

    # The scheduler fires the (already cancelled) timer anyway
    @scheduler.trigger(@entry)

    assert_equal 'paid', @object.state
  end

  def test_should_not_fire_cancelled_entries_when_clock_advances
    @object.pay
    @scheduler.advance(600)

    assert_equal 'paid', @object.state
  end
end
