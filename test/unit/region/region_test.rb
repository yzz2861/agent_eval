# frozen_string_literal: true

require 'test_helper'

class RegionTest < StateMachinesTest
  def setup
    @machine = StateMachines::Machine.new(Class.new)
    @state = StateMachines::State.new(@machine, :processing)
    @region = StateMachines::Region.new(@machine, @state, :payment)
  end

  def test_should_have_a_name
    assert_equal :payment, @region.name
  end

  def test_should_normalize_name_to_symbol
    region = StateMachines::Region.new(@machine, @state, 'payment')

    assert_equal :payment, region.name
  end

  def test_should_have_a_machine_and_parent_state
    assert_equal @machine, @region.machine
    assert_equal @state, @region.state
  end

  def test_should_have_no_states_by_default
    assert_empty @region.state_names
    assert_empty @region.states
  end

  def test_should_track_added_states_in_order
    @region.add_state(:awaiting_payment)
    @region.add_state(:paid)

    assert_equal %i[awaiting_payment paid], @region.state_names
  end

  def test_should_not_add_duplicate_states
    @region.add_state(:paid)
    @region.add_state(:paid)

    assert_equal %i[paid], @region.state_names
  end

  def test_should_use_first_state_as_initial_by_default
    @region.add_state(:awaiting_payment)
    @region.add_state(:paid)

    assert_equal :awaiting_payment, @region.initial_state_name
  end

  def test_should_allow_explicit_initial_state
    @region.add_state(:awaiting_payment)
    @region.add_state(:paid, initial: true)

    assert_equal :paid, @region.initial_state_name
  end

  def test_should_resolve_states_from_machine
    @machine.state(:awaiting_payment)
    @machine.state(:paid)
    @region.add_state(:awaiting_payment)
    @region.add_state(:paid)

    assert_equal %i[awaiting_payment paid], @region.states.map(&:name)
    assert_equal :awaiting_payment, @region.initial_state.name
  end

  def test_should_check_state_membership
    @region.add_state(:paid)

    assert @region.include?(:paid)
    refute @region.include?(:awaiting_payment)
  end

  def test_should_rebind_to_copied_state
    @region.add_state(:paid)
    new_machine = StateMachines::Machine.new(Class.new)
    new_state = StateMachines::State.new(new_machine, :processing)

    copy = @region.copy_for(new_state)

    assert_equal new_machine, copy.machine
    assert_equal new_state, copy.state
    assert_equal %i[paid], copy.state_names
  end

  def test_should_use_pretty_inspect
    @region.add_state(:awaiting_payment)
    @region.add_state(:paid)

    assert_equal '#<StateMachines::Region name=:payment states=[:awaiting_payment, :paid] initial=:awaiting_payment>',
                 @region.inspect
  end
end
