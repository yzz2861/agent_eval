# frozen_string_literal: true

require 'test_helper'

class DeferredEventQueueTest < StateMachinesTest
  def setup
    @queue = StateMachines::DeferredEventQueue.new(2)
    @first = StateMachines::DeferredEvent.new(name: :first, args: [], bang: false)
    @second = StateMachines::DeferredEvent.new(name: :second, args: [], bang: false)
    @third = StateMachines::DeferredEvent.new(name: :third, args: [], bang: false)
  end

  def test_should_start_empty
    assert_equal 0, @queue.length
    assert_predicate @queue, :empty?
  end

  def test_should_store_entries_in_fifo_order
    @queue.add(@first)
    @queue.add(@second)

    assert_equal [@first, @second], @queue.entries
    refute_predicate @queue, :empty?
  end

  def test_should_raise_queue_full_when_capacity_is_reached
    @queue.add(@first)
    @queue.add(@second)

    exception = assert_raises(StateMachines::DeferredEventQueue::QueueFull) do
      @queue.add(@third)
    end
    assert_equal :third, exception.event_name
    assert_equal 2, exception.size
    assert_equal [@first, @second], @queue.entries
  end

  def test_should_track_nested_transitions
    refute_predicate @queue, :busy?

    @queue.begin_transition!
    assert_predicate @queue, :busy?
    assert_predicate @queue, :transitioning?

    @queue.begin_transition!
    refute @queue.end_transition!
    assert_predicate @queue, :busy?

    assert @queue.end_transition!
    refute_predicate @queue, :busy?
  end

  def test_should_drain_entries_added_during_a_transition
    @queue.begin_transition!
    @queue.add(@first)
    @queue.add(@second)
    @queue.end_transition!

    batch = @queue.begin_pass!
    assert_equal [@first, @second], batch
    assert_predicate @queue, :empty?

    # Events enqueued mid-drain accumulate separately and are not revisited
    # by the running pass.
    @queue.add(@third)
    assert_equal [@third], @queue.entries

    @queue.end_pass!
    assert_equal [@third], @queue.entries
  end

  def test_should_keep_unexecutable_entries_at_the_front_without_revisiting_them
    @queue.add(@first)
    @queue.begin_pass!

    # A new event arriving during the pass goes behind the retained entry
    @queue.add(@second)
    @queue.keep(@first)
    @queue.end_pass!

    assert_equal [@first, @second], @queue.entries
  end

  def test_should_support_nested_passes
    @queue.add(@first)
    @queue.begin_pass!
    @queue.begin_transition!
    @queue.add(@second)
    @queue.end_transition!

    inner = @queue.begin_pass!
    assert_equal [@second], inner
    @queue.end_pass!
    @queue.end_pass!

    assert_predicate @queue, :empty?
  end
end
