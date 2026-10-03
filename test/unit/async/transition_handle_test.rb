# frozen_string_literal: true

require File.expand_path('../../test_helper', __dir__)

class TransitionHandleTest < Minitest::Test
  def setup
    skip "Async tests not supported on #{RUBY_ENGINE}" if RUBY_ENGINE == 'jruby' || RUBY_ENGINE == 'truffleruby'

    @klass = Class.new do
      attr_accessor :log

      def initialize
        @log = []
        super
      end

      state_machine :state, async: true, initial: :parked, action: :save do
        before_transition { |vehicle, _transition| vehicle.log << :before }
        after_transition { |vehicle, _transition| vehicle.log << :after }

        event :ignite do
          transition parked: :idling, if: :guard_check
        end
      end

      def guard_check
        log << :guard
        guard_passes?
      end

      def guard_passes?
        true
      end

      def save
        log << :action
        save_succeeds?
      end

      def save_succeeds?
        true
      end
    end

    @vehicle = @klass.new
    @machine = @klass.state_machines[:state]
  end

  def test_async_interfaces_return_handles
    handle = @vehicle.ignite_async

    assert_kind_of StateMachines::AsyncMode::TransitionHandle, handle
    assert_respond_to handle, :cancel
    assert_respond_to handle, :wait
    assert_respond_to handle, :status
    handle.wait
  end

  def test_handle_is_queryable
    handle = StateMachines::AsyncMode::TransitionHandle.new(@vehicle, @machine, :ignite, [])

    assert_predicate handle, :pending?
    refute_predicate handle, :claimed?
    refute_predicate handle, :cancelled?
    refute_predicate handle, :completed?
    assert_equal :pending, handle.status

    handle.start
    handle.wait

    assert_predicate handle, :completed?
    assert_equal :completed, handle.status
  end

  def test_successful_transition_result
    result = @vehicle.ignite_async.wait

    assert_equal :success, result.outcome
    assert_predicate result, :success?
    refute_predicate result, :cancelled?
    refute_predicate result, :guard_rejected?
    refute_predicate result, :action_failed?
    assert result == true
    assert_equal 'idling', @vehicle.state
    assert_equal %i[guard before action after], @vehicle.log
  end

  def test_guard_rejection_result
    def @vehicle.guard_passes?
      false
    end

    result = @vehicle.ignite_async.wait

    assert_equal :guard_rejected, result.outcome
    assert_predicate result, :guard_rejected?
    refute_predicate result, :success?
    assert result == false
    assert_equal 'parked', @vehicle.state
    assert_includes @vehicle.log, :guard
    refute_includes @vehicle.log, :action
  end

  def test_action_failure_result
    def @vehicle.save_succeeds?
      false
    end

    result = @vehicle.ignite_async.wait

    assert_equal :action_failed, result.outcome
    assert_predicate result, :action_failed?
    refute_predicate result, :success?
    assert result == false
    assert_equal %i[guard before action], @vehicle.log
  end

  def test_cancel_before_claim_prevents_transition
    handle = StateMachines::AsyncMode::TransitionHandle.new(@vehicle, @machine, :ignite, [])

    assert handle.cancel, 'cancel should succeed while pending'
    assert_predicate handle, :cancelled?

    handle.start
    result = handle.wait

    assert_equal :cancelled, result.outcome
    assert_predicate result, :cancelled?
    # Guard, action, and transition callbacks never ran
    assert_empty @vehicle.log
    assert_equal 'parked', @vehicle.state
  end

  def test_cancel_returns_false_once_claimed
    claimed = Queue.new
    release = Queue.new
    @machine.before_transition do |_vehicle, _transition|
      claimed.push(true)
      release.pop
    end

    handle = @vehicle.ignite_async
    claimed.pop # Wait until the executor is inside the transition

    refute handle.cancel, 'cancel should fail once the executor claimed the handle'
    refute_predicate handle, :cancelled?

    release.push(true)
    result = handle.wait

    assert_equal :success, result.outcome
    assert_equal 'idling', @vehicle.state
  end

  def test_cancel_returns_false_after_completion
    handle = @vehicle.ignite_async
    handle.wait

    refute handle.cancel
  end

  def test_cancel_inside_async_context
    require 'async'

    Async do
      handle = @vehicle.ignite_async

      assert handle.cancel, 'cancel should win before the Async executor claims the handle'

      result = handle.wait

      assert_equal :cancelled, result.outcome
      assert_empty @vehicle.log
      assert_equal 'parked', @vehicle.state
    end
  end

  def test_success_inside_async_context
    require 'async'

    Async do
      result = @vehicle.ignite_async.wait

      assert_equal :success, result.outcome
      assert_equal 'idling', @vehicle.state
    end
  end

  def test_cancel_after_claim_inside_async_context
    require 'async'

    @machine.before_transition { |_vehicle, _transition| sleep(0.05) }

    Async do
      handle = @vehicle.ignite_async
      sleep(0.01) until handle.claimed?

      refute handle.cancel
      assert_equal :success, handle.wait.outcome
    end
  end

  def test_bang_handle_raises_on_guard_rejection
    def @vehicle.guard_passes?
      false
    end

    error = assert_raises(StateMachines::InvalidTransition) do
      @vehicle.ignite_async!.wait
    end

    assert_match(/ignite/, error.message)
  end

  def test_bang_handle_succeeds_on_valid_transition
    result = @vehicle.ignite_async!.wait

    assert_equal :success, result.outcome
    assert_equal 'idling', @vehicle.state
  end

  def test_bang_handle_returns_cancelled_result_instead_of_raising
    handle = StateMachines::AsyncMode::TransitionHandle.new(@vehicle, @machine, :ignite, [], raise_on_failure: true)
    handle.cancel
    handle.start

    assert_equal :cancelled, handle.wait.outcome
  end

  def test_wait_reraises_transition_errors
    def @vehicle.save
      raise 'boom'
    end

    error = assert_raises(RuntimeError) { @vehicle.ignite_async.wait }

    assert_equal 'boom', error.message
  end

  def test_fire_event_async_returns_result
    result = @vehicle.fire_event_async(:ignite)

    assert_kind_of StateMachines::AsyncMode::TransitionResult, result
    assert_equal :success, result.outcome
  end

  def test_async_fire_event_works_outside_async_context
    handle = @vehicle.async_fire_event(:ignite)

    assert_kind_of StateMachines::AsyncMode::TransitionHandle, handle
    assert_equal :success, handle.wait.outcome
  end

  def test_fire_events_async_returns_results_in_order
    results = @vehicle.fire_events_async(:ignite)

    assert_equal [:success], results.map(&:outcome)
  end
end
