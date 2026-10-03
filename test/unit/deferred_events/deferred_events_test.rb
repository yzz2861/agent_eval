# frozen_string_literal: true

require 'test_helper'

class DeferredEventsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_reader :calls

      def initialize
        @calls = []
        super
      end
    end

    @machine = StateMachines::Machine.new(@klass, initial: :idle)
    @machine.state :uploading, defer: :publish
    @machine.state :ready
    @machine.state :published
    @machine.event :start_upload do
      transition idle: :uploading
    end
    @machine.event :upload_complete do
      transition uploading: :ready
    end
    @machine.event :publish do
      transition ready: :published
    end

    @object = @klass.new
  end

  def test_should_report_configured_deferred_events_per_state
    uploading = @machine.states[:uploading]
    ready = @machine.states[:ready]

    assert uploading.defers_event?(:publish)
    refute uploading.defers_event?(:upload_complete)
    refute ready.defers_event?(:publish)
    assert_equal [:publish], uploading.deferred_events
  end

  def test_should_queue_deferred_event_instead_of_transitioning
    @object.start_upload
    result = @object.publish

    assert_equal 'uploading', @object.state
    assert result
    assert_equal [:publish], @machine.deferred_events(@object).map(&:name)
  end

  def test_should_process_deferred_event_after_state_allows_it
    @object.start_upload
    @object.publish
    @object.upload_complete

    assert_equal 'published', @object.state
    assert_empty @machine.deferred_events(@object)
  end

  def test_should_preserve_positional_arguments_when_replayed
    recorded = nil
    @machine.after_transition on: :publish do |_object, transition|
      recorded = transition.args
    end

    @object.start_upload
    @object.publish(:urgent, retry_count: 2)
    @object.upload_complete

    assert_equal [:urgent, { retry_count: 2 }], recorded
  end

  def test_should_only_recheck_after_a_state_change
    # publish has no transition from :uploading; while still uploading it is
    # deferred.  A loopback-style unrelated event must not make it spin.
    @machine.event :ping do
      transition uploading: :uploading
    end

    @object.start_upload
    @object.publish
    @object.ping

    assert_equal 'uploading', @object.state
    assert_equal [:publish], @machine.deferred_events(@object).map(&:name)
  end

  def test_should_keep_still_impossible_event_without_retrying_in_place
    # :publish only fires from :ready; after leaving :uploading for a state
    # where it still cannot fire, the single recheck must leave it queued.
    @machine.state :aborted
    @machine.event :cancel do
      transition uploading: :aborted
    end

    @object.start_upload
    @object.publish
    @object.cancel

    assert_equal 'aborted', @object.state
    assert_equal [:publish], @machine.deferred_events(@object).map(&:name)
  end

  def test_should_retry_kept_event_after_later_state_change
    @machine.state :aborted
    @machine.event :cancel do
      transition uploading: :aborted
    end
    @machine.event :requeue do
      transition aborted: :ready
    end

    @object.start_upload
    @object.publish
    @object.cancel
    @object.requeue

    assert_equal 'published', @object.state
    assert_empty @machine.deferred_events(@object)
  end

  def test_should_return_false_for_non_bang_event_that_cannot_fire_when_drained
    # A queued event whose destination never becomes reachable stays queued
    # and does not raise when fired without !
    @machine.state :aborted
    @machine.event :cancel do
      transition uploading: :aborted
    end

    @object.start_upload
    assert @object.publish
    assert @object.cancel
    assert_equal [:publish], @machine.deferred_events(@object).map(&:name)
  end

  def test_should_raise_invalid_transition_for_bang_event_that_cannot_fire_when_drained
    @machine.state :aborted
    @machine.event :cancel do
      transition uploading: :aborted
    end
    @machine.event :never do
      transition ready: :published
    end
    @machine.states[:uploading].configure_deferred_events(:never)

    @object.start_upload
    @object.never!
    exception = assert_raises(StateMachines::InvalidTransition) { @object.cancel }
    assert_equal :never, exception.event
    # The attempted bang entry was consumed from the queue
    assert_empty @machine.deferred_events(@object)
  end

  def test_should_finish_current_callbacks_before_consuming_events_fired_inside_them
    trace = []
    @machine.after_transition on: :start_upload do |_object, _transition|
      trace << :start_upload_after_begin
      @object.upload_complete
      trace << :start_upload_after_end
    end
    @machine.after_transition on: :upload_complete do |_object, _transition|
      trace << :upload_complete_after
    end

    @object.start_upload

    assert_equal [:start_upload_after_begin, :start_upload_after_end, :upload_complete_after], trace
    assert_equal 'ready', @object.state
  end

  def test_should_restore_unprocessed_entries_when_a_drained_callback_raises
    boom = Class.new(StandardError)
    @machine.after_transition on: :upload_complete do
      raise boom, 'callback failed'
    end

    @object.start_upload
    @object.publish

    assert_raises(boom) { @object.upload_complete }
    # publish was never attempted and remains queued for a later retry
    assert_equal [:publish], @machine.deferred_events(@object).map(&:name)
  end

  def test_should_not_raise_for_a_non_bang_event_that_fails_when_drained
    @machine.state :aborted
    @machine.event :cancel do
      transition uploading: :aborted
    end
    @machine.states[:uploading].configure_deferred_events(:never)
    @machine.event :never do
      transition ready: :published
    end

    @object.start_upload
    @object.never
    result = @object.cancel

    assert result
    assert_equal 'aborted', @object.state
    # Non-bang failure keeps the entry for a later retry
    assert_equal [:never], @machine.deferred_events(@object).map(&:name)
  end
end
