# frozen_string_literal: true

RSpec.describe Dry::Transaction::StepAdapters::Fold, :adapter do
  subject { described_class.new }

  let(:options) { {initial: 0, step_name: "unit"} }

  before do
    module Test
      class TrackingSource
        include Enumerable

        attr_reader :read_count, :closed

        def initialize(values)
          @values = values
          @read_count = 0
          @closed = false
        end

        def each
          @values.each do |value|
            @read_count += 1
            yield value
          end
        end

        def close
          @closed = true
        end
      end

      class StrictSource < TrackingSource
        def initialize(values, allowed_reads)
          super(values)
          @allowed_reads = allowed_reads
        end

        def each
          @values.each do |value|
            @read_count += 1
            raise StandardError, "read past failure" if @read_count > @allowed_reads

            yield value
          end
        end
      end

      class ClosableEnumerator < Enumerator
        attr_reader :closed

        def initialize(source)
          @closed = false
          super() { |yielder| source.each { |value| yielder << value } }
        end

        def close
          @closed = true
        end
      end
    end
  end

  let(:operation) {
    -> (accumulator, element, index) {
      if element == :bad
        Failure("failure at #{index}")
      else
        Success(accumulator + element)
      end
    }
  }

  describe "#call" do
    it "folds an enumerator with the accumulator, element, and index" do
      seen = []
      operation = -> (accumulator, element, index) {
        seen << [accumulator, element, index]
        Success(accumulator + element)
      }

      result = subject.(operation, options, [[1, 2, 3].to_enum])

      expect(result).to eql(Success(6))
      expect(seen).to eql([[0, 1, 0], [1, 2, 1], [3, 3, 2]])
    end

    it "uses the initial value for an empty stream" do
      result = subject.(operation, options, [[].to_enum])

      expect(result).to eql(Success(0))
    end

    it "uses an initial value passed as an argument when no option is present" do
      result = subject.(operation, {step_name: "unit"}, [[2, 3], 10])

      expect(result).to eql(Success(15))
    end

    it "stops at the first failure and preserves accumulator and index" do
      source = Test::StrictSource.new([1, :bad, 3], 2)

      result = subject.(operation, options, [source])

      expect(result).to eql(Failure([1, 1]))
      expect(source.read_count).to be(2)
    end

    it "does not convert the source to an array" do
      source = Object.new

      def source.each
        yield 1
        yield 2
      end

      def source.to_a
        raise "the source must be consumed lazily"
      end

      result = subject.(operation, options, [source])

      expect(result).to eql(Success(3))
    end

    it "closes a source the adapter owns" do
      source = Test::TrackingSource.new([1, 2])

      subject.(operation, options, [source])

      expect(source.closed).to be(true)
    end

    it "closes an owned source after a failure" do
      source = Test::StrictSource.new([1, :bad, 3], 2)

      subject.(operation, options, [source])

      expect(source.closed).to be(true)
    end

    it "does not close an enumerator supplied by the caller" do
      source = Test::TrackingSource.new([1, 2])
      enumerator = Test::ClosableEnumerator.new(source)

      subject.(operation, options, [enumerator])

      expect(enumerator.closed).to be(false)
      expect(source.closed).to be(false)
    end

    context "when the operation returns a non-Result value" do
      let(:operation) { -> (_accumulator, _element, _index) { "plain" } }

      it "raises an InvalidResultError" do
        expect {
          subject.(operation, options, [[1].to_enum])
        }.to raise_error(
          Dry::Transaction::InvalidResultError,
          "step +unit+ must return a Result object"
        )
      end
    end
  end

  describe "#input_arity" do
    it "reports that the transaction supplies one input" do
      expect(subject.input_arity).to be(1)
    end
  end
end
