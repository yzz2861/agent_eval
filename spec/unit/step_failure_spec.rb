# frozen_string_literal: true

RSpec.describe Dry::Transaction::StepFailure do
  let(:step_class) do
    Class.new do
      attr_reader :name

      def initialize(name)
        @name = name
      end
    end
  end

  let(:inner_step) { step_class.new(:validate) }
  let(:outer_step) { step_class.new(:process) }

  describe ".call" do
    context "with a plain failure value" do
      it "wraps the value and starts a single-entry path" do
        failure = described_class.call(inner_step, "error") {}

        expect(failure.step).to be inner_step
        expect(failure.value).to eq "error"
        expect(failure.path).to eq [:validate]
      end

      it "yields before wrapping" do
        yielded = false
        described_class.call(inner_step, "error") { yielded = true }

        expect(yielded).to be true
      end
    end

    context "with an existing StepFailure" do
      subject!(:inner) { described_class.call(inner_step, "error") {} }

      it "returns a new failure with the step prepended to the path" do
        failure = described_class.call(outer_step, inner) {}

        expect(failure).not_to be inner
        expect(failure.path).to eq [:process, :validate]
      end

      it "preserves the original step and failure value" do
        failure = described_class.call(outer_step, inner) {}

        expect(failure.step).to be inner_step
        expect(failure.value).to eq "error"
      end

      it "does not mutate the original failure" do
        described_class.call(outer_step, inner) {}

        expect(inner.path).to eq [:validate]
      end

      it "does not yield" do
        expect { |block|
          described_class.call(outer_step, inner, &block)
        }.not_to yield_control
      end
    end
  end

  describe "#path" do
    it "is structured data, not a joined string" do
      failure = described_class.call(inner_step, "error") {}

      expect(failure.path).to be_an Array
      expect(failure.path).to all be_a Symbol
    end
  end
end
