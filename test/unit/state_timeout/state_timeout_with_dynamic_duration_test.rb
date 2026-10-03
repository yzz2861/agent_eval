# frozen_string_literal: true

require 'test_helper'
require 'unit/state_timeout/fake_timeout_scheduler'

class StateTimeoutWithDynamicDurationTest < StateMachinesTest
  def setup
    @scheduler = FakeTimeoutScheduler.new
    @klass = Class.new do
      attr_accessor :payment_window
    end
    @machine = StateMachines::Machine.new(@klass, initial: :pending, timeout_scheduler: @scheduler)
    @machine.event :start_payment do
      transition pending: :awaiting_payment
    end
    @machine.event :timeout do
      transition awaiting_payment: :expired
    end

    @object = @klass.new
    @object.payment_window = 120
  end

  def test_should_evaluate_lambda_exactly_once_per_entry
    evaluations = 0
    @machine.state :awaiting_payment, timeout: ->(_object) { evaluations += 1; 120 }

    @object.start_payment

    assert_equal 1, evaluations
    assert_equal 120, @scheduler.entries.first.delay
  end

  def test_should_use_value_computed_at_entry_time
    @machine.state :awaiting_payment, timeout: ->(object) { object.payment_window }

    @object.payment_window = 45
    @object.start_payment

    assert_equal 45, @scheduler.entries.first.delay

    # Changing the source value after entry must not affect the armed timer
    @object.payment_window = 999
    @scheduler.advance(45)

    assert_equal 'expired', @object.state
  end

  def test_should_reevaluate_duration_on_reentry
    @machine.event :retry_payment do
      transition awaiting_payment: :awaiting_payment
    end
    @machine.state :awaiting_payment, timeout: ->(object) { object.payment_window }

    @object.payment_window = 30
    @object.start_payment

    @object.payment_window = 90
    @object.retry_payment

    assert_equal [30, 90], @scheduler.entries.map(&:delay)
  end

  def test_should_support_method_names_for_duration
    @machine.state :awaiting_payment, timeout: :payment_window

    @object.start_payment

    assert_equal 120, @scheduler.entries.first.delay
  end

  def test_should_raise_when_duration_is_not_a_number
    @machine.state :awaiting_payment, timeout: ->(_object) { nil }

    error = assert_raises(StateMachines::Error) { @object.start_payment }
    assert_match(/non-negative number/, error.message)
    refute @machine.state_timeout_pending?(@object)
  end
end
