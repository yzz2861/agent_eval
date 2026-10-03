# frozen_string_literal: true

RSpec.describe "State: inventory reservation" do
  include Dry::Monads[:state, :result]

  state = Dry::Monads::State

  # The state is a plain hash of SKU => available stock.
  # Each reservation reads the stock left by the previous one,
  # so reservations must be sequenced with bind.
  def reserve(sku, quantity)
    Dry::Monads::State.get.bind_result { |stock|
      available = stock.fetch(sku, 0)

      if available >= quantity
        Success(quantity)
      else
        Failure({sku: sku, requested: quantity, available: available})
      end
    }.bind { |reserved|
      Dry::Monads::State.modify { |stock| stock.merge(sku => stock[sku] - reserved) }
        .fmap { reserved }
    }
  end

  let(:order) do
    reserve("ruby-book", 2).bind { |first|
      reserve("ruby-book", 2).bind { |second|
        state.pure([first, second])
      }
    }
  end

  it "does not touch the inventory while the order is being composed" do
    stock = {"ruby-book" => 5}
    order
    expect(stock).to eql("ruby-book" => 5)
  end

  it "reserves sequentially when the stock suffices" do
    value, stock = order.run({"ruby-book" => 5})

    expect(value).to eql([2, 2])
    expect(stock).to eql("ruby-book" => 1)
  end

  it "threads the state so the second reservation sees the first one's effect" do
    # 3 items: the first reservation of 2 succeeds, the second one
    # observes the remaining 1 and fails
    value, stock = order.run({"ruby-book" => 3})

    expect(value).to eql(Failure(sku: "ruby-book", requested: 2, available: 1))
    # the state at the point of failure is kept: the first reservation
    # is still in effect, there is no rollback to the initial 3
    expect(stock).to eql("ruby-book" => 1)
  end

  it "keeps repeated runs independent" do
    initial = {"ruby-book" => 5}

    expect(order.run(initial)).to eql(order.run(initial))
    expect(initial).to eql("ruby-book" => 5)
  end

  it "exposes the final value and the final state separately" do
    expect(order.eval_state({"ruby-book" => 5})).to eql([2, 2])
    expect(order.exec_state({"ruby-book" => 5})).to eql("ruby-book" => 1)
  end
end
