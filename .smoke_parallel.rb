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
    event :cancel do
      transition processing: :cancelled
    end
    event :complete_processing do
      transition processing: :completed
    end
  end
end

order = Order.new
puts "initial: #{order.state.inspect} name=#{order.state_name.inspect}"
order.checkout
puts "after checkout: #{order.state.inspect} name=#{order.state_name.inspect} processing?=#{order.processing?}"
puts "current_states: #{order.current_states.map(&:name).inspect}"
puts "region payment: #{order.region_state(:payment).name.inspect}"
order.pay
puts "after pay: #{order.state.inspect} paid?=#{order.paid?} awaiting_stock?=#{order.awaiting_stock?}"
order.stock
puts "after stock: #{order.state.inspect}"
order.ship
puts "after ship: #{order.state.inspect} name=#{order.state_name.inspect}"
puts '---'
order2 = Order.new
order2.checkout
order2.cancel
puts "after cancel: #{order2.state.inspect}"
puts '---'
order3 = Order.new
order3.checkout
order3.pay
order3.ship
puts "pay+ship only: #{order3.state.inspect}"
