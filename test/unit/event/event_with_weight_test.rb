# frozen_string_literal: true

require 'test_helper'

class EventWithWeightTest < StateMachinesTest
  def setup
    @machine = StateMachines::Machine.new(Class.new)
  end

  def test_should_default_to_a_weight_of_one
    event = StateMachines::Event.new(@machine, :ignite)

    assert_equal 1, event.weight
  end

  def test_should_allow_weight_via_keyword
    event = StateMachines::Event.new(@machine, :ignite, weight: 3)

    assert_equal 3, event.weight
  end

  def test_should_allow_weight_via_options_hash
    event = StateMachines::Event.new(@machine, :ignite, { weight: 2 })

    assert_equal 2, event.weight
  end

  def test_should_allow_weight_via_machine_dsl
    event = @machine.event(:ignite, weight: 4) do
      transition parked: :idling
    end

    assert_equal 4, event.weight
  end

  def test_should_allow_zero_weight
    event = StateMachines::Event.new(@machine, :ignite, weight: 0)

    assert_equal 0, event.weight
  end

  def test_should_allow_changing_weight
    event = StateMachines::Event.new(@machine, :ignite)
    event.weight = 2.5

    assert_equal 2.5, event.weight
  end

  def test_should_raise_exception_for_negative_weight
    exception = assert_raises(ArgumentError) { StateMachines::Event.new(@machine, :ignite, weight: -1) }

    assert_equal 'weight must be a non-negative number, got -1', exception.message
  end

  def test_should_raise_exception_for_non_numeric_weight
    assert_raises(ArgumentError) { StateMachines::Event.new(@machine, :ignite, weight: 'cheap') }
  end

  def test_should_raise_exception_for_invalid_option
    assert_raises(ArgumentError) { StateMachines::Event.new(@machine, :ignite, { invalid: true }) }
  end
end
