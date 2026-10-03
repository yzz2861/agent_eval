# frozen_string_literal: true

RSpec.describe "fold steps" do
  include Dry::Monads[:result]

  let(:transaction_class) do
    Class.new do
      include Dry::Transaction

      fold :process, initial: 0
    end
  end

  it "processes each element with accumulator, element, and index" do
    seen = []
    operation = -> (accumulator, element, index) {
      seen << [accumulator, element, index]
      Success(accumulator + element + index)
    }

    result = transaction_class.new(process: operation).call([10, 20].to_enum)

    expect(result).to eql(Success(31))
    expect(seen).to eql([[0, 10, 0], [10, 20, 1]])
  end

  it "uses the initial value for an empty stream" do
    operation = -> (accumulator, _element, _index) { Success(accumulator) }

    result = transaction_class.new(process: operation).call([].to_enum)

    expect(result).to eql(Success(0))
  end

  it "stops after the first failure" do
    source = Class.new do
      attr_reader :read_count

      def initialize
        @read_count = 0
      end

      def each
        [1, 2, 3].each do |value|
          @read_count += 1
          raise "read past failure" if @read_count > 2

          yield value
        end
      end
    end.new

    operation = -> (accumulator, element, index) {
      element == 2 ? Failure([accumulator, index]) : Success(accumulator + element)
    }

    result = transaction_class.new(process: operation).call(source)

    expect(result).to eql(Failure([1, 1]))
    expect(source.read_count).to be(2)
  end
end
