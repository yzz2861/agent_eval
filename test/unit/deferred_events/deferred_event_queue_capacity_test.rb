# frozen_string_literal: true

require 'test_helper'

class DeferredEventQueueCapacityTest < StateMachinesTest
  def test_should_use_default_capacity
    klass = build_machine_class(nil)
    machine = klass.state_machine

    assert_equal StateMachines::Machine::DeferredEvents::DEFAULT_DEFERRED_QUEUE_SIZE,
                 machine.deferred_queue_size
  end

  def test_should_allow_custom_capacity
    klass = build_machine_class(1)
    machine = klass.state_machine
    object = klass.new
    object.start
    object.finish

    exception = assert_raises(StateMachines::DeferredEventQueue::QueueFull) do
      object.finish
    end
    assert_equal :finish, exception.event_name
    assert_equal 1, exception.size
    assert_equal 1, machine.deferred_events(object).length
  end

  def test_should_reject_invalid_capacity
    assert_raises(ArgumentError) do
      build_machine_class(0)
    end
    assert_raises(ArgumentError) do
      build_machine_class(:lots)
    end
  end

  private

  def build_machine_class(size)
    options = { initial: :idle }
    options[:deferred_queue_size] = size unless size.nil?

    Class.new do
      def initialize
        super
      end

      state_machine options do
        state :uploading, defer: :finish
        state :done
        event :start do
          transition idle: :uploading
        end
        event :finish do
          transition uploading: :done
        end
      end
    end
  end
end
