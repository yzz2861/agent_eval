# frozen_string_literal: true

require 'test_helper'

class StateWithInvariantsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :tracking_number

      def tracking_number?
        !tracking_number.nil?
      end
    end
    @machine = StateMachines::Machine.new(@klass)
  end

  def test_should_accept_invariant_option
    invariant = ->(object) { object.tracking_number }
    state = @machine.state :shipped, invariant: invariant

    assert_equal [invariant], state.invariants
  end

  def test_should_accept_invariants_option
    invariant = ->(object) { object.tracking_number }
    state = @machine.state :shipped, invariants: [invariant]

    assert_equal [invariant], state.invariants
  end

  def test_should_accept_invariant_declared_in_state_context
    state = nil
    @machine.state :shipped do
      state = invariant { |object| !object.tracking_number.nil? }
    end

    assert_equal 1, @machine.states[:shipped].invariants.length
    assert_same @machine.states[:shipped], state
  end

  def test_should_verify_all_invariants
    state = @machine.state :shipped do
      invariant { |object| object.tracking_number }
      invariant { |_object, _transition| false }
    end
    object = @klass.new
    object.tracking_number = 'T-1'
    transition = Struct.new(:event).new(:ship)

    refute state.verify_invariants(object, transition)
  end

  def test_should_verify_symbol_invariant
    state = @machine.state :shipped, invariant: :tracking_number?
    object = @klass.new
    transition = Struct.new(:event).new(:ship)

    refute state.verify_invariants(object, transition)

    object.tracking_number = 'T-1'
    assert state.verify_invariants(object, transition)
  end

  def test_should_raise_for_non_callable_invariant
    error = assert_raises(ArgumentError) { @machine.state :shipped, invariant: 'tracking_number?' }
    assert_equal 'State invariant must be a Symbol or callable', error.message
  end
end
