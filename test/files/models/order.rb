# frozen_string_literal: true

require_relative 'model_base'

# An order that goes through payment and fulfillment (stocking) at the same
# time.  Both tracks of progress live in a single state machine: the
# +processing+ state is a parallel state composed of two orthogonal regions,
# each with its own active substate.
class Order < ModelBase
  attr_accessor :callbacks, :fail_save

  def initialize(attributes = {})
    attributes = {
      callbacks: [],
      fail_save: false
    }.merge(attributes)

    attributes.each { |attr, value| send("#{attr}=", value) }
    super()
  end

  def save
    return false if fail_save

    super
  end

  # rubocop:disable Metrics/BlockLength
  state_machine initial: :cart, action: :save do
    # Record every callback along with the attribute value visible at that
    # moment, so tests can verify dispatch ordering and that the transition
    # set is fully determined before any callback runs
    before_transition do |order, transition|
      order.callbacks << [:before, transition.from_name, transition.to_name, order.state]
    end
    after_transition do |order, transition|
      order.callbacks << [:after, transition.from_name, transition.to_name, order.state]
    end

    parallel_state :processing do
      region :payment do
        state :awaiting_payment, initial: true
        state :paid
      end

      region :fulfillment do
        state :awaiting_stock, initial: true
        state :stocked
        state :shipped
      end

      on_complete :complete_processing
    end

    event :checkout do
      transition cart: :processing
    end

    event :pay do
      transition awaiting_payment: :paid
    end

    event :stock do
      transition awaiting_stock: :stocked
    end

    event :ship do
      transition stocked: :shipped
    end

    # Received by multiple regions at once
    event :expedite do
      transition awaiting_payment: :paid
      transition awaiting_stock: :stocked
    end

    # Only handled by the parent parallel state
    event :cancel do
      transition processing: :cancelled
    end

    event :complete_processing do
      transition processing: :completed
    end
  end
  # rubocop:enable Metrics/BlockLength
end
