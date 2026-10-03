# frozen_string_literal: true

require 'test_helper'

class PlannerWithTiesTest < StateMachinesTest
  def setup
    @klass = Class.new
    @machine = StateMachines::Machine.new(@klass)
    @machine.state :parked, :idling, :first_gear
    @object = @klass.new
    @object.state = 'parked'
  end

  def test_should_prefer_fewer_events_when_costs_are_equal
    @machine.event :ignite, weight: 1 do
      transition parked: :idling
    end
    @machine.event :shift_up, weight: 1 do
      transition idling: :first_gear
    end
    @machine.event :tow, weight: 2 do
      transition parked: :first_gear
    end

    plan = StateMachines::Planner.new(@object, @machine, to: :first_gear).plan

    assert_equal %i[tow], plan.events
    assert_equal 2, plan.total_cost
  end

  def test_should_prefer_lexicographically_smaller_event_sequence_when_costs_and_lengths_are_equal
    @machine.event :zap do
      transition parked: :idling
    end
    @machine.event :accelerate do
      transition parked: :idling
    end

    plan = StateMachines::Planner.new(@object, @machine, to: :idling).plan

    assert_equal %i[accelerate], plan.events
  end

  def test_should_resolve_ties_deterministically_regardless_of_definition_order
    @machine.event :zap do
      transition parked: :idling
    end
    @machine.event :accelerate do
      transition parked: :idling
    end

    plans = 5.times.map { StateMachines::Planner.new(@object, @machine, to: :idling).plan.events }

    assert_equal [%i[accelerate]] * 5, plans
  end
end
