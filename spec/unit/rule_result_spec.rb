# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::RuleResult do
  it "builds a passed result" do
    result = described_class.new(name: :check, status: :passed)

    expect(result).to be_passed
    expect(result).not_to be_failed
    expect(result).not_to be_skipped
    expect(result.reason).to be_nil
    expect(result).to be_frozen
  end

  it "builds a failed result" do
    result = described_class.new(name: :check, status: :failed)

    expect(result).to be_failed
    expect(result.reason).to be_nil
  end

  it "builds a skipped result with unmet dependencies" do
    result = described_class.skipped(
      :check,
      unmet_dependencies: {prereq: :failed}
    )

    expect(result).to be_skipped
    expect(result.failed_dependencies).to eql([:prereq])
    expect(result).not_to be_schema_error
    expect(result.reason).to eql(
      "skipped because prerequisite :prereq was failed"
    )
  end

  it "builds a skipped result due to a schema error" do
    result = described_class.skipped(:check, schema_error: true)

    expect(result).to be_skipped
    expect(result).to be_schema_error
    expect(result.failed_dependencies).to eql([])
    expect(result.reason).to eql("skipped due to a schema error")
  end

  it "is equal by name, status and unmet dependencies" do
    a = described_class.skipped(:check, unmet_dependencies: {prereq: :failed})
    b = described_class.skipped(:check, unmet_dependencies: {prereq: :failed})

    expect(a).to eql(b)
  end

  it "has an informative inspect" do
    result = described_class.new(name: :check, status: :passed)

    expect(result.inspect).to eql("#<Dry::Validation::RuleResult name=:check status=:passed>")
  end
end
