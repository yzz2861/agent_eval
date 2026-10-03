# frozen_string_literal: true

require 'test_helper'

class DeferredEventsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_reader :calls, :published
      attr_accessor :allow_publish

      def initialize
        @calls = []
        @allow_publish = true
        super
      end

      def write_publication(version = 1)
        @published = version
      end
    end

    @machine = StateMachines::Machine.new(
      @klass,
      initial: :idle,
      deferred_event_queue_size: 2
    )

    @machine.event :start_upload do
      transition idle: :uploading
    end

    @machine.event :finish_upload do
      transition uploading: :ready
    end

    @machine.event :publish do
      transition(ready: :published, if: :allow_publish)
    end

    @machine.event :reject do
      transition ready: :rejected
    end

    @machine.state :uploading, defer: :publish
    @machine.after_transition on: :publish do |object, transition|
      object.write_publication(*transition.args)
    end

    @object = @klass.new
  end

  def test_queues_declared_event_until_upload_finishes_and_preserves_arguments
    @object.start_upload

    assert_equal true, @object.publish(7)
    assert_equal 'uploading', @object.state
    refute @object.published

    assert_equal true, @object.finish_upload

    assert_equal 'published', @object.state
    assert_equal 7, @object.published
  end

  def test_queues_events_triggered_from_callbacks_until_current_transition_finishes
    @machine.after_transition on: :start_upload do |object|
      object.publish(9)
      object.calls << :nested_during_uploading
    end

    @object.start_upload
    @object.finish_upload

    assert_equal 'published', @object.state
    assert_equal 9, @object.published
  end

  def test_processes_one_transition_completely_before_consuming_next_event
    @machine.after_transition on: :finish_upload do |object|
      object.calls << [:finish_after, object.state]
    end
    @machine.after_transition on: :publish do |object|
      object.calls << [:publish_after, object.state]
    end

    @object.start_upload
    @object.publish
    @object.finish_upload

    assert_equal [[:finish_after, 'ready'], [:publish_after, 'published']], @object.calls
  end

  def test_returns_false_when_non_bang_event_cannot_fit_in_queue
    @object.start_upload

    assert_equal true, @object.publish
    assert_equal true, @object.publish
    assert_equal false, @object.publish
  end

  def test_direct_event_fire_returns_false_when_queue_is_full
    @object.start_upload
    @object.publish
    @object.publish

    assert_equal false, @machine.event(:publish).fire(@object)
  end

  def test_raises_when_bang_event_cannot_fit_in_queue
    @object.start_upload
    @object.publish
    @object.publish

    error = assert_raises(StateMachines::DeferredEventQueueFull) { @object.publish! }
    assert_equal @object, error.object
    assert_equal :publish, error.event
  end

  def test_keeps_event_deferred_when_state_does_not_become_executable
    @machine.event :cancel do
      transition uploading: :idle
    end

    @object.start_upload
    @object.publish
    @object.cancel

    assert_equal 'idle', @object.state
    refute @object.published
  end

  def test_requeues_failed_entry_without_retrying_it_in_same_drain
    @machine.event :cancel do
      transition uploading: :idle
    end

    @object.start_upload
    @object.publish
    @object.allow_publish = false
    @object.cancel
    @object.start_upload
    assert_equal false, @object.finish_upload

    assert_equal 'ready', @object.state
    queue = @machine.event(:publish).send(:deferred_event_queue, @object)
    assert_equal [:publish], queue.items.map(&:event_name)
    refute @object.published
  end

  def test_does_not_requeue_entries_that_already_succeeded
    @klass.attr_accessor :allow_archive
    @machine.event :archive do
      transition(ready: :archived, if: :allow_archive)
    end
    @machine.state :uploading, defer: [:publish, :archive]

    @object.start_upload
    @object.publish
    @object.archive
    @object.allow_archive = false

    assert_equal false, @object.finish_upload

    assert_equal 'published', @object.state
    queue = @machine.event(:archive).send(:deferred_event_queue, @object)
    assert_equal [:archive], queue.items.map(&:event_name)
  end

  def test_keeps_failed_entry_and_arguments_when_callback_raises
    @machine.after_transition on: :publish do
      raise RuntimeError, 'publisher unavailable'
    end

    @object.start_upload
    @object.publish(13)

    error = assert_raises(RuntimeError) { @object.finish_upload }
    assert_equal 'publisher unavailable', error.message
    assert_equal 'published', @object.state

    queue = @machine.event(:publish).send(:deferred_event_queue, @object)
    assert_equal [[:publish, [13], false]], queue.items.map { |item| [item.event_name, item.args, item.bang] }
  end

  def test_duplicates_object_queue_without_sharing_entries
    @object.start_upload
    @object.publish(11)
    copy = @object.dup
    copy.finish_upload

    assert_equal 'published', copy.state
    assert_equal 11, copy.published
    assert_equal 'uploading', @object.state
    refute @object.published
  end

  def test_keeps_deferred_event_queues_separate_between_objects
    second_object = @klass.new
    @object.start_upload
    second_object.start_upload
    @object.publish(1)

    second_object.finish_upload

    assert_equal 'ready', second_object.state
    refute second_object.published
    assert_equal 'uploading', @object.state
  end
end
