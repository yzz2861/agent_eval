# frozen_string_literal: true

RSpec.describe "Parallel branches" do
  include Dry::Monads[:result]

  before do
    module Test
      class ShippingCalculator
        include Dry::Transaction

        step :compute

        def compute(input)
          Success(input[:distance] * 2)
        end
      end

      class TaxCalculator
        include Dry::Transaction

        step :compute

        def compute(input)
          Success(input[:amount] * 0.1)
        end
      end

      class DiscountCalculator
        include Dry::Transaction

        step :compute

        def compute(input)
          input[:vip] ? Success(input[:amount] * 0.2) : Failure(:not_eligible)
        end
      end

      class ProcessOrder
        include Dry::Transaction

        map :prepare
        parallel :calculate, max_concurrency: 2
        map :summarize

        def prepare(input)
          input
        end

        def calculate(_input)
          {
            shipping: ShippingCalculator.new,
            tax: TaxCalculator.new,
            discount: DiscountCalculator.new
          }
        end

        def summarize(results)
          results.merge(total: results[:shipping] + results[:tax] - results[:discount])
        end
      end
    end
  end

  it "runs every branch and hands the named results to the next step" do
    result = Test::ProcessOrder.new.call(distance: 5, amount: 100.0, vip: true)

    expect(result).to eql(Success(shipping: 10, tax: 10.0, discount: 20.0, total: 0.0))
  end

  it "fails with a result locating the failing branch" do
    result = Test::ProcessOrder.new.call(distance: 5, amount: 100.0, vip: false)

    expect(result).to eql(Failure(discount: :not_eligible))
  end
end
