# frozen_string_literal: true

require_relative '../test_helper'

class OrthogonalRegionsTest < StateMachinesTest
  def setup
    super
    @class = Class.new do
      attr_accessor :state, :callback_log

      def initialize
        @callback_log = []
        super
      end
    end

    @machine = StateMachines::Machine.new(@class, initial: :processing)
    @machine.state :processing, composite: true do
      region :payment, initial: :unpaid do
        event :pay do
          transition unpaid: :paid
        end
      end

      region :fulfillment, initial: :waiting do
        event :stock do
          transition waiting: :ready
        end
      end

      event :complete do
        transition processing: :done
      end
    end
    @object = @class.new
  end

  def test_initializes_each_orthogonal_region
    assert_equal({ processing: { payment: :unpaid, fulfillment: :waiting } }, @object.state)
    assert_equal %i[unpaid waiting], @machine.active_states(@object).map(&:name)
  end

  def test_single_event_can_transition_multiple_regions
    assert @object.pay
    assert_equal :paid, @object.state[:processing][:payment]
    assert_equal :waiting, @object.state[:processing][:fulfillment]

    assert @object.stock
    assert_equal :ready, @object.state[:processing][:fulfillment]
  end

  def test_completion_only_fires_when_all_regions_are_final
    @machine.state :paid, final: true
    @machine.state :ready, final: true

    @object.pay
    assert_equal :processing, @object.state.keys.first

    @object.stock
    assert_equal 'done', @object.state
  end

  def test_region_order_controls_selection_and_callbacks
    calls = []
    @machine.before_transition(on: :shared) { calls << :before }
    @machine.after_transition(on: :shared) { calls << :after }

    payment_context = RegionEventContextStub.new(@machine, :shared, region: @machine.regions.first)
    payment_context.transition(unpaid: :paid)
    fulfillment_context = RegionEventContextStub.new(@machine, :shared, region: @machine.regions.last)
    fulfillment_context.transition(waiting: :ready)

    assert @object.shared
    assert_equal %i[paid ready], @machine.active_states(@object).map(&:name)
    assert_equal %i[before before after after], calls
  end

  def test_transition_set_is_selected_before_region_callbacks_persist
    observed = []
    payment_context = RegionEventContextStub.new(@machine, :sync, region: @machine.regions.first)
    payment_context.transition(unpaid: :paid)
    fulfillment_context = RegionEventContextStub.new(@machine, :sync, region: @machine.regions.last)
    fulfillment_context.transition(waiting: :ready)

    @machine.before_transition(on: :sync) do |object|
      observed << @machine.active_states(object).map(&:name)
    end

    assert @object.sync
    assert_equal [%i[unpaid waiting], %i[unpaid waiting]], observed
    assert_equal %i[paid ready], @machine.active_states(@object).map(&:name)
  end

  def test_parent_transition_takes_priority_over_active_children
    @machine.event :cancel do
      transition processing: :cancelled
    end

    payment_context = RegionEventContextStub.new(@machine, :cancel, region: @machine.regions.first)
    payment_context.transition(unpaid: :paid)
    fulfillment_context = RegionEventContextStub.new(@machine, :cancel, region: @machine.regions.last)
    fulfillment_context.transition(waiting: :ready)

    assert @object.cancel
    assert_equal 'cancelled', @object.state
    refute @object.processing?
    assert_equal %i[cancelled], @machine.active_states(@object).map(&:name)
  end

  def test_plain_single_state_machine_interface_remains_compatible
    klass = Class.new do
      attr_accessor :state
    end
    machine = StateMachines::Machine.new(klass, initial: :parked)
    machine.event :ignite do
      transition parked: :idling
    end
    object = klass.new

    assert_equal 'parked', object.state
    assert object.parked?
    assert object.ignite
    assert_equal 'idling', object.state
    assert_equal :idling, machine.states.match!(object).name
  end
end

class RegionEventContextStub
  def initialize(machine, event_name, region:)
    @context = StateMachines::RegionEventContext.new(machine, event_name, region: region, parent_state: region.parent_state)
  end

  def transition(options)
    @context.transition(options)
  end
end
