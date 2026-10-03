# frozen_string_literal: true

require 'test_helper'

class StateInvariantTest < Minitest::Test
  # Models the requirement: a shipped order must carry a tracking number.
  # The tracking number is only written while +save+ runs, so a pre-transition
  # guard could never validate it - the state invariant is checked after the
  # action completes.
  class Order
    attr_accessor :state, :tracking_number, :failures

    state_machine initial: :pending, action: :save do
      state :pending, :shipped

      event :ship do
        transition pending: :shipped
      end

      state :shipped do
        invariant { |order| !order.tracking_number.nil? && !order.tracking_number.empty? }
      end

      after_failure { |order| (order.failures ||= []) << :ship_failed }
    end

    def initialize
      @failures = []
      super
    end

    def save
      self.tracking_number ||= 'T-1234' if state == 'shipped'
      true
    end
  end

  def test_should_transition_when_the_action_writes_the_required_value
    order = Order.new

    assert order.ship
    assert_equal 'shipped', order.state
    assert_equal 'T-1234', order.tracking_number
    assert_empty order.failures
  end

  def test_should_roll_back_and_run_failure_flow_when_invariant_returns_false
    klass = Class.new do
      attr_accessor :state, :failures

      state_machine initial: :pending, action: :save do
        state :pending, :shipped
        event :ship do
          transition pending: :shipped
        end
        invariant :shipped, :do => ->(order) { false }
        after_failure { |order| (order.failures ||= []) << :failed }
      end

      def initialize
        @failures = []
        super
      end

      def save
        true
      end
    end

    order = klass.new

    refute order.ship
    assert_equal 'pending', order.state
    assert_equal [:failed], order.failures
  end

  def test_should_roll_back_and_reraise_when_invariant_raises
    klass = Class.new do
      attr_accessor :state

      state_machine initial: :pending, action: :save do
        state :pending, :shipped
        event :ship do
          transition pending: :shipped
        end
        state :shipped, invariant: ->(_order) { raise ArgumentError, 'missing tracking number' }
      end

      def save
        true
      end
    end

    order = klass.new

    error = assert_raises(ArgumentError) { order.ship }
    assert_equal 'missing tracking number', error.message
    assert_equal 'pending', order.state
  end
end
