require 'state_machines'

class Order
  attr_accessor :state

  state_machine initial: :cart do
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
    event :complete_processing do
      transition processing: :completed
    end
  end
end

order = Order.new
order.checkout
order.pay
order.stock
machine = Order.state_machine
event = machine.events[:ship]
ts = machine.parallel_transitions_for(event, order)
puts "transitions: #{ts.inspect}"
puts "can_ship? #{order.can_ship?}"
result = order.ship
puts "ship result: #{result.inspect} state=#{order.state.inspect}"
