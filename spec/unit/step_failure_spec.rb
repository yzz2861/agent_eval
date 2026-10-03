# frozen_string_literal: true

RSpec.describe Dry::Transaction::StepFailure do
  def build_step(name)
    instance_double(Dry::Transaction::Step, name: name)
  end

  describe ".call" do
    context "with a plain value" do
      it "wraps the value with a single-step path" do
        step = build_step(:validate)
        failure = described_class.call(step, "error") {}

        expect(failure.step).to be step
        expect(failure.value).to eq "error"
        expect(failure.path).to eq [:validate]
        expect(failure).not_to be_nested
      end

      it "yields" do
        expect { |block|
          described_class.call(build_step(:validate), "error", &block)
        }.to yield_control
      end
    end

    context "with a non-nested step failure" do
      it "returns it unchanged without yielding" do
        failure = described_class.call(build_step(:validate), "error") {}

        expect { |block|
          described_class.call(build_step(:process), failure, &block)
        }.not_to yield_control

        expect(described_class.call(build_step(:process), failure) {}).to be failure
      end
    end

    context "with a nested step failure" do
      it "prepends the enclosing step to the path and preserves the source" do
        nested = described_class.call(build_step(:validate), "error") {}.nested

        yielded = false
        failure = described_class.call(build_step(:process), nested) { yielded = true }

        expect(yielded).to be true
        expect(failure.step).to be nested.step
        expect(failure.value).to eq "error"
        expect(failure.path).to eq [:process, :validate]
        expect(failure).not_to be_nested
      end
    end
  end

  describe "#nested" do
    it "returns a nested copy preserving the step, value and path" do
      step = build_step(:validate)
      failure = described_class.new(step, "error")

      nested = failure.nested

      expect(nested).to be_nested
      expect(nested.step).to be step
      expect(nested.value).to eq "error"
      expect(nested.path).to eq [:validate]
    end
  end

  describe "#prepend" do
    it "grows the path while preserving the source step and value" do
      step = build_step(:validate)
      failure = described_class.new(step, "error")

      prepended = failure.prepend(build_step(:process)).prepend(build_step(:run))

      expect(prepended.step).to be step
      expect(prepended.value).to eq "error"
      expect(prepended.path).to eq [:run, :process, :validate]
    end
  end
end
