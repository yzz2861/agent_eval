# frozen_string_literal: true

require 'test_helper'

class StateWithInvariantsTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :tracking_number

      def tracking_number?
        !tracking_number.nil? && !tracking_number.empty?
      end
    end

    @machine = StateMachines::Machine.new(@klass, initial: :shipped)
    @state = StateMachines::State.new(@machine, :shipped)
  end

  def test_should_accept_invariant_option
    state = StateMachines::State.new(@machine, :shipped, invariant: :tracking_number?)

    assert_equal 1, state.invariants.length
  end

  def test_should_accept_multiple_invariants_as_array
    check = ->(object) { !object.tracking_number.nil? }
    state = StateMachines::State.new(@machine, :shipped, invariant: [:tracking_number?, check])

    assert_equal 2, state.invariants.length
  end

  def test_should_register_invariants
    check = ->(object) { object.tracking_number }
    @state.add_invariant(:tracking_number?, check)

    assert_equal [:tracking_number?, check], @state.invariants
  end

  def test_should_raise_for_invalid_invariant
    exception = assert_raises(ArgumentError) { @state.add_invariant(1) }
    assert_equal 'Invariant must be a method name, Proc, or callable', exception.message
  end

  def test_should_pass_when_all_invariants_hold
    @state.add_invariant(:tracking_number?)
    object = @klass.new
    object.tracking_number = 'T123'

    assert @state.check_invariants(object)
  end

  def test_should_fail_when_an_invariant_returns_false
    @state.add_invariant(:tracking_number?)

    refute @state.check_invariants(@klass.new)
  end

  def test_should_fail_when_an_invariant_returns_nil
    @state.add_invariant(->(object) { object.tracking_number })

    refute @state.check_invariants(@klass.new)
  end

  def test_should_stop_at_the_first_failing_invariant
    ran = false
    @state.add_invariant(->(_object) { false }, ->(_object) { ran = true })
    @state.check_invariants(@klass.new)

    refute ran
  end

  def test_should_propagate_exceptions
    @state.add_invariant(->(_object) { raise ArgumentError, 'boom' })

    exception = assert_raises(ArgumentError) { @state.check_invariants(@klass.new) }
    assert_equal 'boom', exception.message
  end

  def test_should_pass_the_transition_when_the_check_accepts_it
    seen = nil
    transition = Object.new
    @state.add_invariant(->(object, given_transition) { seen = given_transition; true })
    @state.check_invariants(@klass.new, transition)

    assert_equal transition, seen
  end

  def test_should_duplicate_invariants_when_copied
    check = ->(object) { object.tracking_number }
    @state.add_invariant(check)
    copy = @state.dup
    copy.add_invariant(:tracking_number?)

    assert_equal [check], @state.invariants
    assert_equal [check, :tracking_number?], copy.invariants
  end
end
