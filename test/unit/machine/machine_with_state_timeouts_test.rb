# frozen_string_literal: true

require 'test_helper'

class MachineWithStateTimeoutsTest < StateMachinesTest
  # A test scheduler that records scheduled callbacks instead of running them
  # on a background thread, letting tests fire them manually at any point.
  class FakeScheduler
    class Entry
      attr_reader :delay

      def initialize(delay, callback)
        @delay = delay
        @callback = callback
        @cancelled = false
      end

      def cancel
        @cancelled = true
      end

      def cancelled?
        @cancelled
      end

      def fire
        @callback.call
      end
    end

    attr_reader :entries

    def initialize
      @entries = []
    end

    def schedule(delay, &callback)
      Entry.new(delay, callback).tap { |entry| @entries << entry }
    end

    def latest
      @entries.last
    end
  end

  # A scheduler whose #schedule always fails
  class FailingScheduler
    def schedule(_delay, &)
      raise 'scheduler backend unavailable'
    end
  end

  def setup
    @fake_now = Time.at(1_000_000)
    @scheduler = FakeScheduler.new
    @klass = Class.new { attr_accessor :state }
    @machine = StateMachines::Machine.new(@klass, :state, initial: :pending, scheduler: @scheduler, clock: -> { @fake_now })
    @machine.event(:start_checkout) { transition pending: :awaiting_payment }
    @machine.event(:pay) { transition awaiting_payment: :paid }
    @machine.event(:void) { transition awaiting_payment: :pending }
    @machine.event(:timeout) { transition awaiting_payment: :expired }
    @machine.state :awaiting_payment, timeout: 10
    @object = @klass.new
  end

  def advance_time(seconds)
    @fake_now += seconds
  end

  def test_should_not_arm_timer_for_initial_state
    assert_equal 0, @scheduler.entries.length
  end

  def test_should_schedule_timeout_when_entering_timed_state
    @object.start_checkout

    assert_equal 1, @scheduler.entries.length
    assert_equal 10, @scheduler.latest.delay
  end

  def test_should_fire_timeout_event_when_callback_runs_on_time
    @object.start_checkout
    advance_time(10)
    @scheduler.latest.fire

    assert_equal 'expired', @object.state
  end

  def test_should_cancel_timer_when_leaving_state
    @object.start_checkout
    entry = @scheduler.latest
    @object.pay

    assert_predicate entry, :cancelled?
  end

  def test_should_ignore_late_callback_after_leaving_state
    @object.start_checkout
    entry = @scheduler.latest
    @object.pay
    advance_time(10)
    entry.fire

    assert_equal 'paid', @object.state
  end

  def test_should_not_arm_timer_when_entering_untimed_state
    @object.start_checkout
    @object.pay

    assert_equal 1, @scheduler.entries.length
  end

  def test_should_invalidate_previous_callback_when_reentering_same_state
    @object.start_checkout
    stale_entry = @scheduler.latest
    @object.void
    @object.start_checkout
    fresh_entry = @scheduler.latest

    refute_same stale_entry, fresh_entry
    assert_predicate stale_entry, :cancelled?

    advance_time(10)
    stale_entry.fire
    assert_equal 'awaiting_payment', @object.state

    fresh_entry.fire
    assert_equal 'expired', @object.state
  end

  def test_should_invalidate_previous_callback_on_loopback_reentry
    @machine.event(:retry) { transition awaiting_payment: :awaiting_payment }
    @object.start_checkout
    stale_entry = @scheduler.latest
    @object.retry

    assert_predicate stale_entry, :cancelled?
    assert_equal 2, @scheduler.entries.length

    advance_time(10)
    stale_entry.fire
    assert_equal 'awaiting_payment', @object.state

    @scheduler.latest.fire
    assert_equal 'expired', @object.state
  end

  def test_should_let_only_manual_transition_succeed_when_it_wins_the_race
    @object.start_checkout
    entry = @scheduler.latest
    @object.pay
    advance_time(10)
    entry.fire

    assert_equal 'paid', @object.state
  end

  def test_should_let_only_timeout_transition_succeed_when_it_wins_the_race
    @object.start_checkout
    advance_time(10)
    @scheduler.latest.fire

    assert_equal 'expired', @object.state
    refute @object.pay
    assert_equal 'expired', @object.state
  end

  def test_should_evaluate_dynamic_timeout_once_per_entry
    evaluations = 0
    scheduler = FakeScheduler.new
    klass = Class.new { attr_accessor :status }
    machine = StateMachines::Machine.new(klass, :status, initial: :pending, scheduler: scheduler, clock: -> { @fake_now })
    machine.event(:begin) { transition pending: :waiting }
    machine.event(:timeout) { transition waiting: :expired }
    machine.state :waiting, timeout: ->(_object) { evaluations += 1; 5 }

    object = klass.new
    object.begin

    assert_equal 1, evaluations
    assert_equal 5, scheduler.latest.delay

    advance_time(5)
    scheduler.latest.fire
    assert_equal 1, evaluations
    assert_equal 'expired', object.status
  end

  def test_should_raise_when_entering_timed_state_without_scheduler
    klass = Class.new { attr_accessor :status }
    machine = StateMachines::Machine.new(klass, :status, initial: :pending)
    machine.event(:begin) { transition pending: :waiting }
    machine.state :waiting, timeout: 10

    object = klass.new
    exception = assert_raises(StateMachines::SchedulingError) { object.begin }
    assert_match(/no scheduler configured/, exception.message)
    assert_nil object.instance_variable_get(:@_state_machine_state_timeouts)&.dig(:status)
  end

  def test_should_propagate_scheduling_failure_to_caller
    klass = Class.new { attr_accessor :status }
    machine = StateMachines::Machine.new(klass, :status, initial: :pending, scheduler: FailingScheduler.new)
    machine.event(:begin) { transition pending: :waiting }
    machine.state :waiting, timeout: 10

    object = klass.new
    exception = assert_raises(StateMachines::SchedulingError) { object.begin }
    assert_match(/scheduler backend unavailable/, exception.message)
    assert_nil object.instance_variable_get(:@_state_machine_state_timeouts)&.dig(:status)
  end

  def test_should_reschedule_remaining_delay_when_callback_fires_early
    @object.start_checkout

    advance_time(4)
    @scheduler.latest.fire

    assert_equal 'awaiting_payment', @object.state
    assert_equal 2, @scheduler.entries.length
    assert_in_delta 6, @scheduler.latest.delay, 0.001

    advance_time(6)
    @scheduler.latest.fire
    assert_equal 'expired', @object.state
  end

  def test_should_use_custom_timeout_event
    scheduler = FakeScheduler.new
    klass = Class.new { attr_accessor :status }
    machine = StateMachines::Machine.new(klass, :status, initial: :pending, scheduler: scheduler, clock: -> { @fake_now })
    machine.event(:begin) { transition pending: :waiting }
    machine.event(:payment_expired) { transition waiting: :expired }
    machine.state :waiting, timeout: 10, timeout_event: :payment_expired

    object = klass.new
    object.begin
    advance_time(10)
    scheduler.latest.fire

    assert_equal 'expired', object.status
  end

  def test_should_raise_on_invalid_timeout_value
    assert_raises(ArgumentError) { @machine.state :broken, timeout: 'ten seconds' }
  end
end
