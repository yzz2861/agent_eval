# frozen_string_literal: true

RSpec.describe "Fold step" do
  let(:transaction) {
    Class.new do
      include Dry::Transaction

      fold :import, initial: 0

      def import(total, bill, index)
        bill > 0 ? Success(total + bill) : Failure("invalid bill at #{index}")
      end
    end.new
  }

  it "folds a lazy input stream into a single result" do
    expect(transaction.call([10, 20, 30].each)).to eql(Success(60))
  end

  it "returns the initial value for an empty stream" do
    expect(transaction.call([].each)).to eql(Success(0))
  end

  it "stops at the first failure and exposes the fold state" do
    result = transaction.call([10, -1, 30].each)

    expect(result).to be_failure
    expect(result.failure.accumulator).to eql(10)
    expect(result.failure.index).to eql(1)
  end
end
