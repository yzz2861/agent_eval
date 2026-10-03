# frozen_string_literal: true

require 'test_helper'
require 'unit/state_timeout/fake_timeout_scheduler'

class StateTimeoutTest < StateMachinesTest
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
  end

  def test_should_store_timeout_on_state
    assert_equal 300, @machine.states[:awaiting_payment].timeout
  end

  def test_should_not_schedule_anything_before_entering_state
    assert_empty @scheduler.entries
    refute @machine.state_timeout_pending?(@object)
  end

  def test_should_schedule_timeout_when_state_entered
    @object.start_payment

    assert_equal 1, @scheduler.entries.length
    assert_equal 300, @scheduler.entries.first.delay
    assert @machine.state_timeout_pending?(@object)
  end

  def test_should_fire_timeout_event_when_timer_elapses
    @object.start_payment
    @scheduler.advance(300)

    assert_equal 'expired', @object.state
  end

  def test_should_cancel_timeout_when_state_is_left
    @object.start_payment
    entry = @scheduler.entries.first

    @object.pay

    assert entry.cancelled
    refute @machine.state_timeout_pending?(@object)
    assert_equal 'paid', @object.state
  end

  def test_should_not_schedule_timeout_for_states_without_timeout
    @object.start_payment
    @object.pay

    assert_equal 1, @scheduler.entries.length
    refute @machine.state_timeout_pending?(@object)
  end

  def test_should_rearm_timeout_when_same_state_is_reentered
    @machine.event :retry_payment do
      transition awaiting_payment: :awaiting_payment
    end

    @object.start_payment
    first = @scheduler.entries.first

    @object.retry_payment

    assert first.cancelled
    assert_equal 2, @scheduler.entries.length
    refute @scheduler.entries.last.cancelled
    assert @machine.state_timeout_pending?(@object)
  end

  def test_should_raise_when_no_scheduler_configured
    machine = StateMachines::Machine.new(Class.new, initial: :pending)
    machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    machine.event :timeout do
      transition awaiting_payment: :expired
    end
    machine.state :awaiting_payment, timeout: 300
    object = machine.owner_class.new

    error = assert_raises(StateMachines::Error) { object.start_payment }
    assert_match(/no timeout_scheduler configured/, error.message)
    refute machine.state_timeout_pending?(object)
  end

  def test_should_raise_when_timeout_event_is_not_defined
    machine = StateMachines::Machine.new(Class.new, initial: :pending, timeout_scheduler: @scheduler)
    machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    machine.state :awaiting_payment, timeout: 300
    object = machine.owner_class.new

    assert_raises(StateMachines::InvalidEvent) { object.start_payment }
    refute machine.state_timeout_pending?(object)
  end

  def test_should_allow_custom_timeout_event
    machine = StateMachines::Machine.new(Class.new, initial: :pending, timeout_scheduler: @scheduler)
    machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    machine.event :expire do
      transition awaiting_payment: :expired
    end
    machine.state :awaiting_payment, timeout: 60, timeout_event: :expire
    object = machine.owner_class.new

    object.start_payment
    @scheduler.advance(60)

    assert_equal 'expired', object.state
  end

  def test_should_allow_scheduler_to_be_assigned_after_definition
    machine = StateMachines::Machine.new(Class.new, initial: :pending)
    machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    machine.event :timeout do
      transition awaiting_payment: :expired
    end
    machine.state :awaiting_payment, timeout: 300
    machine.timeout_scheduler = @scheduler
    object = machine.owner_class.new

    object.start_payment

    assert_equal 1, @scheduler.entries.length
  end

  def test_should_support_handles_that_cancel_themselves
    handle_class = Struct.new(:cancelled) do
      def cancel
        self.cancelled = true
      end
    end
    scheduler = Object.new
    handles = []
    scheduler.define_singleton_method(:schedule) do |_delay, &_block|
      handle_class.new(false).tap { |handle| handles << handle }
    end

    machine = StateMachines::Machine.new(Class.new, initial: :pending, timeout_scheduler: scheduler)
    machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    machine.event :pay do
      transition awaiting_payment: :paid
    end
    machine.event :timeout do
      transition awaiting_payment: :expired
    end
    machine.state :awaiting_payment, timeout: 300
    object = machine.owner_class.new

    object.start_payment
    object.pay

    assert handles.first.cancelled
    refute machine.state_timeout_pending?(object)
  end
end
