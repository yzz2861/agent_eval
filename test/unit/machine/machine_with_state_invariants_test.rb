# frozen_string_literal: true

require 'test_helper'

class MachineWithStateInvariantsTest < StateMachinesTest
  def setup
    @machine = StateMachines::Machine.new(Class.new, initial: :pending)
    @machine.state :pending, :shipped
  end

  def test_should_register_invariant_via_state_option
    @machine.state :shipped, invariant: ->(object) { object }

    assert_equal 1, @machine.states[:shipped].invariants.length
  end

  def test_should_register_invariant_via_invariant_dsl
    check = ->(object) { object }
    @machine.invariant :shipped, check

    assert_equal [check], @machine.states[:shipped].invariants
  end

  def test_should_register_invariant_with_block
    @machine.invariant :shipped do |object|
      object
    end

    assert_equal 1, @machine.states[:shipped].invariants.length
  end

  def test_should_register_invariant_with_do_option
    @machine.invariant :shipped, do: :valid?

    assert_equal [:valid?], @machine.states[:shipped].invariants
  end

  def test_should_register_for_multiple_states
    @machine.state :cancelled
    @machine.invariant :shipped, :cancelled, :valid?

    assert_equal [:valid?], @machine.states[:shipped].invariants
    assert_equal [:valid?], @machine.states[:cancelled].invariants
  end

  def test_should_register_for_matcher_states
    @machine.invariant @machine.all - :pending, :valid?

    assert_equal [:valid?], @machine.states[:shipped].invariants
    assert_empty @machine.states[:pending].invariants
  end

  def test_should_accumulate_invariants
    @machine.invariant :shipped, :valid?
    @machine.invariant :shipped, :complete?

    assert_equal [:valid?, :complete?], @machine.states[:shipped].invariants
  end

  def test_should_register_invariant_inside_state_block
    @machine.state :shipped do
      invariant { |object| object }
    end

    assert_equal 1, @machine.states[:shipped].invariants.length
  end

  def test_should_raise_without_a_check
    exception = assert_raises(ArgumentError) { @machine.invariant :shipped }
    assert_equal 'Invariant must be specified', exception.message
  end

  def test_should_raise_without_states
    exception = assert_raises(ArgumentError) { @machine.invariant { |object| object } }
    assert_equal 'Must specify at least one state for the invariant', exception.message
  end

  def test_should_reject_unknown_options
    exception = assert_raises(ArgumentError) { @machine.invariant :shipped, invalid: true }
    assert_equal 'Unknown key: :invalid. Valid keys are: :do', exception.message
  end
end
