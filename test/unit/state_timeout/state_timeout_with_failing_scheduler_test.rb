# frozen_string_literal: true

require 'test_helper'
require 'unit/state_timeout/fake_timeout_scheduler'

class StateTimeoutWithFailingSchedulerTest < StateMachinesTest
  class ExplodingScheduler
    def schedule(_delay, &_block)
      raise 'scheduler backend unavailable'
    end
  end

  def setup
    @scheduler = ExplodingScheduler.new
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass, initial: :pending, timeout_scheduler: @scheduler)
    @machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    @machine.event :timeout do
      transition awaiting_payment: :expired
    end
    @machine.state :awaiting_payment, timeout: 300

    @object = @klass.new
  end

  def test_should_let_the_caller_know_scheduling_failed
    error = assert_raises(RuntimeError) { @object.start_payment }
    assert_equal 'scheduler backend unavailable', error.message
  end

  def test_should_not_leave_timeout_looking_scheduled_after_failure
    assert_raises(RuntimeError) { @object.start_payment }

    refute @machine.state_timeout_pending?(@object)
  end

  def test_should_not_report_pending_timeout_on_fresh_object
    refute @machine.state_timeout_pending?(@object)
  end

  def test_should_cancel_previous_timer_even_when_rescheduling_fails
    working = FakeTimeoutScheduler.new
    machine = StateMachines::Machine.new(Class.new, initial: :pending, timeout_scheduler: working)
    machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    machine.event :retry_payment do
      transition awaiting_payment: :awaiting_payment
    end
    machine.event :timeout do
      transition awaiting_payment: :expired
    end
    machine.state :awaiting_payment, timeout: 300
    object = machine.owner_class.new

    object.start_payment
    first = working.entries.first
    assert machine.state_timeout_pending?(object)

    machine.timeout_scheduler = @scheduler
    assert_raises(RuntimeError) { object.retry_payment }

    assert first.cancelled
    refute machine.state_timeout_pending?(object)
  end
end
