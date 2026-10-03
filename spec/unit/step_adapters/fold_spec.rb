# frozen_string_literal: true

RSpec.describe Dry::Transaction::StepAdapters::Fold, :adapter do
  subject { described_class.new }

  let(:options) { {initial: 0} }

  let(:operation) {
    -> (accumulator, element, _index) { Success(accumulator + element) }
  }

  # Test source that raises when pulled more than +max_pulls+ times, proving
  # the adapter consumes the input lazily and stops reading after a failure
  def guarded_source(elements, max_pulls:)
    pulls = 0

    Enumerator.new do |yielder|
      elements.each do |element|
        pulls += 1
        raise "source pulled more than #{max_pulls} times" if pulls > max_pulls

        yielder << element
      end
    end
  end

  # Test source that records whether it was closed
  def closable_source(elements)
    Class.new {
      def initialize(elements)
        @elements = elements
        @closed = false
      end

      def each(&block)
        @elements.each(&block)
      end

      def close
        @closed = true
      end

      def closed?
        @closed
      end
    }.new(elements)
  end

  describe "#call" do
    it "folds every element into the accumulated value" do
      result = subject.(operation, options, [guarded_source([1, 2, 3], max_pulls: 3)])

      expect(result).to eql(Success(6))
    end

    it "passes the accumulator, element and index to the operation" do
      calls = []
      recording = -> (accumulator, element, index) {
        calls << [accumulator, element, index]
        Success(accumulator + element)
      }

      subject.(recording, options, [guarded_source([10, 20], max_pulls: 2)])

      expect(calls).to eql([[0, 10, 0], [10, 20, 1]])
    end

    it "forwards additional step arguments to the operation" do
      calls = []
      recording = -> (accumulator, element, index, scale) {
        calls << [accumulator, element, index, scale]
        Success(accumulator + element * scale)
      }

      result = subject.(recording, options, [guarded_source([1, 2], max_pulls: 2), 10])

      expect(result).to eql(Success(30))
      expect(calls).to eql([[0, 1, 0, 10], [10, 2, 1, 10]])
    end

    context "when the input is empty" do
      it "returns the initial value without calling the operation" do
        result = subject.(operation, options, [guarded_source([], max_pulls: 0)])

        expect(result).to eql(Success(0))
      end
    end

    context "when the operation fails" do
      let(:operation) {
        -> (accumulator, element, index) {
          index == 1 ? Failure("nope") : Success(accumulator + element)
        }
      }

      it "returns a Failure with the accumulated value and the failing index" do
        result = subject.(operation, options, [guarded_source([1, 2, 3], max_pulls: 2)])

        expect(result).to eql(Failure(described_class::FailureState.new(1, 1)))
      end

      it "stops pulling the source after the failure" do
        source = guarded_source([1, 2, 3], max_pulls: 2)

        expect { subject.(operation, options, [source]) }.not_to raise_error
      end
    end

    context "when the source supports close" do
      context "when the adapter owns the source" do
        let(:options) { {initial: 0, owns_source: true} }

        it "closes the source after folding" do
          source = closable_source([1, 2])

          subject.(operation, options, [source])

          expect(source).to be_closed
        end

        context "and the operation fails" do
          let(:operation) { -> (_accumulator, _element, _index) { Failure("nope") } }

          it "closes the source" do
            source = closable_source([1, 2])

            subject.(operation, options, [source])

            expect(source).to be_closed
          end
        end
      end

      context "when the adapter does not own the source" do
        it "leaves the source open" do
          source = closable_source([1, 2])

          subject.(operation, options, [source])

          expect(source).not_to be_closed
        end
      end
    end
  end
end
