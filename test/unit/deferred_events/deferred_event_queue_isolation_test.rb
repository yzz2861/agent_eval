# frozen_string_literal: true

require 'test_helper'

class DeferredEventQueueIsolationTest < StateMachinesTest
  def setup
    @klass = Class.new do
      def initialize
        super
      end
    end

    @phase = StateMachines::Machine.new(@klass, :phase, initial: :idle)
    @phase.state :uploading, defer: :publish
    @phase.state :ready
    @phase.event :start do
      transition idle: :uploading
    end
    @phase.event :upload_complete do
      transition uploading: :ready
    end
    @phase.event :publish do
      transition ready: :done
    end
    @phase.state :done

    @stage = StateMachines::Machine.new(@klass, :stage, initial: :new)
    @stage.state :pending, defer: :approve
    @stage.state :approved
    @stage.event :submit do
      transition new: :pending
    end
    @stage.event :accept do
      transition pending: :approved
    end
    @stage.event :approve do
      transition pending: :approved, approved: :approved
    end

    @first = @klass.new
    @second = @klass.new
  end

  def test_should_not_share_queues_between_objects
    @first.start
    @first.publish

    assert_equal [:publish], @phase.deferred_events(@first).map(&:name)
    assert_empty @phase.deferred_events(@second)
  end

  def test_should_not_share_queues_between_machines_on_one_object
    @first.start
    @first.publish
    @first.submit
    @first.approve

    assert_equal [:publish], @phase.deferred_events(@first).map(&:name)
    assert_equal [:approve], @stage.deferred_events(@first).map(&:name)
  end

  def test_should_drain_only_the_machine_that_changed_state
    @first.start
    @first.publish
    @first.submit
    @first.approve

    @first.upload_complete

    assert_empty @phase.deferred_events(@first)
    assert_equal [:approve], @stage.deferred_events(@first).map(&:name)

    @first.accept
    assert_empty @stage.deferred_events(@first)
  end

  def test_should_duplicate_the_queue_with_the_object
    @first.start
    @first.publish

    copy = @first.dup

    assert_equal [:publish], @phase.deferred_events(@first).map(&:name)
    assert_equal [:publish], @phase.deferred_events(copy).map(&:name)
    refute_same @phase.deferred_event_queue(@first), @phase.deferred_event_queue(copy)

    # Completing one object's upload must not touch the copy
    @first.upload_complete
    assert_empty @phase.deferred_events(@first)
    assert_equal [:publish], @phase.deferred_events(copy).map(&:name)
  end
end
