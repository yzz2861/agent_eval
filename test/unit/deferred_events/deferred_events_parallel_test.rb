# frozen_string_literal: true

require 'test_helper'

class DeferredEventsParallelTest < StateMachinesTest
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
    @phase.event :complete do
      transition uploading: :ready
    end
    @phase.event :publish do
      transition ready: :ready
    end

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

    @object = @klass.new
  end

  def test_should_drain_after_parallel_fire_events
    @object.start
    @object.publish
    @object.submit
    @object.approve

    assert @object.fire_events(:complete, :accept)

    assert_equal 'ready', @object.phase
    assert_equal 'approved', @object.stage
    assert_empty @phase.deferred_events(@object)
    assert_empty @stage.deferred_events(@object)
  end

  def test_should_queue_events_fired_inside_parallel_callbacks_until_batch_finishes
    trace = []
    @phase.after_transition on: :start do |object, _transition|
      trace << :start_after_begin
      object.complete
      trace << :start_after_end
    end
    @phase.after_transition on: :complete do |_object, _transition|
      trace << :complete_after
    end
    @stage.after_transition on: :submit do |_object, _transition|
      trace << :submit_after
    end

    @object.fire_events(:start, :submit)

    assert_includes trace, :submit_after
    assert trace.index(:start_after_end) < trace.index(:complete_after)
    assert_equal 'ready', @object.phase
  end
end
