# frozen_string_literal: true

require 'test_helper'

class DeferredEventConfigurationTest < StateMachinesTest
  def test_should_allow_events_to_be_declared_after_the_deferring_state
    klass = Class.new do
      def initialize
        super
      end
    end

    machine = StateMachines::Machine.new(klass, initial: :idle) do
      state :uploading, defer: :publish
      event :publish do
        transition uploading: :uploading
      end
    end

    assert machine.states[:uploading].defers_event?(:publish)
  end

  def test_should_accept_an_array_of_deferred_events
    klass = Class.new
    machine = StateMachines::Machine.new(klass, initial: :idle)
    machine.state :uploading, defer: %i[publish cancel]
    machine.event :publish do
      transition uploading: :uploading
    end
    machine.event :cancel do
      transition uploading: :uploading
    end

    assert_equal %i[publish cancel], machine.states[:uploading].deferred_events
  end

  def test_should_raise_when_deferring_an_unknown_event
    klass = Class.new
    machine = StateMachines::Machine.new(klass, initial: :idle)
    machine.state :uploading
    machine.event :publish do
      transition uploading: :uploading
    end
    machine.states[:uploading].configure_deferred_events(:missing)

    exception = assert_raises(ArgumentError) do
      machine.send(:validate_deferred_event_names!)
    end
    assert_includes exception.message, ':missing'
  end

  def test_should_merge_deferred_events_across_state_declarations
    klass = Class.new
    machine = StateMachines::Machine.new(klass, initial: :idle)
    machine.state :uploading, defer: :publish
    machine.state :uploading, defer: :cancel
    machine.event :publish do
      transition uploading: :uploading
    end
    machine.event :cancel do
      transition uploading: :uploading
    end

    assert_equal %i[publish cancel], machine.states[:uploading].deferred_events
  end
end
