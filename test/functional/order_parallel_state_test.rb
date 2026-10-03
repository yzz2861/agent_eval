# frozen_string_literal: true

require 'test_helper'
require 'files/models/order'

class OrderParallelStateTest < StateMachinesTest
  def setup
    @order = Order.new
    @machine = Order.state_machine
  end

  def test_should_start_in_cart
    assert_equal 'cart', @order.state
    assert_equal :cart, @order.state_name
    refute @machine.parallel_state_for(@order)
  end

  def test_should_enter_every_region_at_its_initial_substate_on_checkout
    assert @order.checkout

    assert_equal 'processing(payment:awaiting_payment,fulfillment:awaiting_stock)', @order.state
    assert_equal :processing, @order.state_name
    assert @order.processing?
    assert_equal %i[awaiting_payment awaiting_stock], @order.current_states.map(&:name)
    assert_equal :awaiting_payment, @order.region_state(:payment).name
    assert_equal :awaiting_stock, @order.region_state(:fulfillment).name
  end

  def test_should_keep_single_attribute_interface_compatible
    @order.checkout

    # The attribute still holds a single string value and predicates for both
    # the parallel state and the region substates keep working
    assert_kind_of String, @order.state
    assert @order.processing?
    assert @order.awaiting_payment?
    refute @order.paid?

    # Writing the bare state value resets every region to its initial substate
    @order.state = 'processing'
    assert @order.processing?
    assert_equal :awaiting_payment, @order.region_state(:payment).name
    assert_equal :awaiting_stock, @order.region_state(:fulfillment).name
  end

  def test_should_advance_only_the_receiving_region
    @order.checkout
    assert @order.pay

    assert_equal 'processing(payment:paid,fulfillment:awaiting_stock)', @order.state
    assert_equal :paid, @order.region_state(:payment).name
    assert_equal :awaiting_stock, @order.region_state(:fulfillment).name
    assert @order.paid?
    assert @order.awaiting_stock?
  end

  def test_should_allow_event_to_be_received_by_multiple_regions
    @order.checkout
    assert @order.expedite

    assert_equal :paid, @order.region_state(:payment).name
    assert_equal :stocked, @order.region_state(:fulfillment).name
  end

  def test_should_determine_transition_set_before_running_callbacks
    @order.checkout
    @order.callbacks.clear
    @order.expedite

    before_callbacks = @order.callbacks.select { |type, *| type == :before }
    # Both regions' before callbacks observe the same starting configuration,
    # proving the whole transition set was determined up front
    assert_equal 2, before_callbacks.length
    before_callbacks.each do |_, _, _, state_at_callback|
      assert_equal 'processing(payment:awaiting_payment,fulfillment:awaiting_stock)', state_at_callback
    end
  end

  def test_should_run_before_callbacks_in_region_definition_order
    @order.checkout
    @order.callbacks.clear
    @order.expedite

    before_callbacks = @order.callbacks.select { |type, *| type == :before }
    assert_equal [[:before, :awaiting_payment, :paid], [:before, :awaiting_stock, :stocked]],
                 before_callbacks.map { |callback| callback.first(3) }
  end

  def test_should_fire_completion_event_only_when_all_regions_reach_final
    @order.checkout
    @order.pay
    @order.stock

    # Fulfillment is not final yet
    assert_equal :processing, @order.state_name

    @order.ship

    # Both regions reached a final state: the completion event fired
    assert_equal 'completed', @order.state
    assert_equal :completed, @order.state_name
  end

  def test_should_not_fire_completion_event_while_any_region_is_not_final
    @order.checkout
    @order.pay
    @order.ship

    # Payment is final but fulfillment is still stocked (not final)
    assert_equal :processing, @order.state_name
    assert_equal 'processing(payment:paid,fulfillment:awaiting_stock)', @order.state
  end

  def test_should_exit_every_active_region_when_parent_state_exits
    @order.checkout
    @order.pay
    @order.callbacks.clear

    assert @order.cancel
    assert_equal 'cancelled', @order.state

    before_callbacks = @order.callbacks.select { |type, *| type == :before }
    # Each active region is exited (via its active substate) in region order,
    # before the parent state's own transition
    assert_equal [
      [:before, :paid, :paid],
      [:before, :awaiting_stock, :awaiting_stock],
      [:before, :processing, :cancelled]
    ], before_callbacks.map { |callback| callback.first(3) }
  end

  def test_should_exit_regions_when_region_transition_leaves_parallel_state
    @order.checkout

    # A region-local transition targeting a state outside the region exits
    # the whole parallel state
    assert @order.cancel
    assert_equal 'cancelled', @order.state
    refute @machine.parallel_state_for(@order)
  end

  def test_should_fail_event_that_no_region_or_parent_can_handle
    @order.checkout
    @order.pay

    refute @order.pay
    assert_equal 'processing(payment:paid,fulfillment:awaiting_stock)', @order.state
  end

  def test_should_raise_on_bang_event_that_cannot_transition
    @order.checkout
    @order.pay

    assert_raises(StateMachines::InvalidTransition) { @order.pay! }
  end

  def test_should_report_events_available_to_regions
    @order.checkout

    events = @order.state_events
    assert_includes events, :pay
    assert_includes events, :stock
    assert_includes events, :cancel
    refute_includes events, :ship
    assert @order.can_pay?
    refute @order.can_ship?
  end

  def test_should_rollback_all_regions_when_action_fails
    @order.checkout
    @order.fail_save = true

    refute @order.expedite
    assert_equal 'processing(payment:awaiting_payment,fulfillment:awaiting_stock)', @order.state
    assert_equal :awaiting_payment, @order.region_state(:payment).name
    assert_equal :awaiting_stock, @order.region_state(:fulfillment).name
  end

  def test_should_skip_action_when_run_action_is_false
    @order.checkout
    assert @order.pay(false)
    assert_equal :paid, @order.region_state(:payment).name
  end

  def test_should_expose_parallel_structure_on_machine
    assert @machine.parallel?
    assert_equal %i[processing], @machine.parallel_states.map(&:name)
    assert_equal %i[payment fulfillment], @machine.regions.map(&:name)

    processing = @machine.states[:processing]
    assert processing.parallel?
    assert_equal :complete_processing, processing.completion_event
    assert_equal %i[awaiting_payment paid], processing.region(:payment).state_names
  end
end
