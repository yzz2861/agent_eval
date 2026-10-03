# frozen_string_literal: true

require 'test_helper'

class PlanTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @object = @klass.new
    @object.state = 'parked'

    @steps = [
      StateMachines::Plan::Step.new(event: :ignite, from_name: :parked, to_name: :idling, weight: 1, guards: { if: [:seatbelt_on?] }),
      StateMachines::Plan::Step.new(event: :shift_up, from_name: :idling, to_name: :first_gear, weight: 3, guards: {})
    ]
    @plan = StateMachines::Plan.new(@object, @machine, from_name: :parked, to_name: :first_gear, steps: @steps)
  end

  def test_should_have_an_object
    assert_equal @object, @plan.object
  end

  def test_should_have_a_machine
    assert_equal @machine, @plan.machine
  end

  def test_should_have_a_from_name
    assert_equal :parked, @plan.from_name
  end

  def test_should_have_a_to_name
    assert_equal :first_gear, @plan.to_name
  end

  def test_should_list_events_in_order
    assert_equal %i[ignite shift_up], @plan.events
  end

  def test_should_sum_step_weights_as_total_cost
    assert_equal 4, @plan.total_cost
  end

  def test_should_not_be_empty
    refute_predicate @plan, :empty?
  end

  def test_should_list_pending_guards_per_step
    assert_equal [{ event: :ignite, if: [:seatbelt_on?] }], @plan.pending_guards
  end

  def test_should_not_be_verified_with_pending_guards
    refute_predicate @plan, :verified?
  end

  def test_should_be_verified_without_pending_guards
    plan = StateMachines::Plan.new(@object, @machine, from_name: :parked, to_name: :first_gear, steps: [@steps.last])

    assert_predicate plan, :verified?
  end

  def test_should_use_pretty_inspect
    assert_equal '#<StateMachines::Plan :parked => :first_gear events=[:ignite, :shift_up] total_cost=4>', @plan.inspect
  end
end

class PlanWithoutStepsTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked
    @object = @klass.new
    @object.state = 'parked'

    @plan = StateMachines::Plan.new(@object, @machine, from_name: :parked, to_name: :parked)
  end

  def test_should_be_empty
    assert_predicate @plan, :empty?
  end

  def test_should_have_no_events
    assert_empty @plan.events
  end

  def test_should_have_zero_total_cost
    assert_equal 0, @plan.total_cost
  end

  def test_should_be_verified
    assert_predicate @plan, :verified?
  end
end
