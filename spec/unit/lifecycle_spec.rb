# frozen_string_literal: true

RSpec.describe Dry::System::Lifecycle do
  describe ".[]" do
    it "returns the lifecycle for a symbol" do
      expect(described_class[:singleton]).to be described_class::SINGLETON
      expect(described_class[:scoped]).to be described_class::SCOPED
      expect(described_class[:transient]).to be described_class::TRANSIENT
    end

    it "coerces strings" do
      expect(described_class["scoped"]).to be described_class::SCOPED
    end

    it "returns an existing lifecycle unchanged" do
      expect(described_class[described_class::SCOPED]).to be described_class::SCOPED
    end

    it "raises for an unknown lifecycle name" do
      expect { described_class[:weird] }.to raise_error(
        Dry::System::InvalidLifecycleError, /:weird/
      )
    end
  end

  describe "#can_depend_on?" do
    it "allows equal or longer-lived dependencies" do
      expect(described_class::SINGLETON.can_depend_on?(:singleton)).to be true
      expect(described_class::SCOPED.can_depend_on?(:singleton)).to be true
      expect(described_class::SCOPED.can_depend_on?(:scoped)).to be true
      expect(described_class::TRANSIENT.can_depend_on?(:singleton)).to be true
      expect(described_class::TRANSIENT.can_depend_on?(:scoped)).to be true
      expect(described_class::TRANSIENT.can_depend_on?(:transient)).to be true
    end

    it "rejects shorter-lived dependencies" do
      expect(described_class::SINGLETON.can_depend_on?(:scoped)).to be false
      expect(described_class::SINGLETON.can_depend_on?(:transient)).to be false
      expect(described_class::SCOPED.can_depend_on?(:transient)).to be false
    end
  end

  it "orders names from longest to shortest lived" do
    expect(described_class::NAMES).to eq %i[singleton scoped transient]
  end

  it "is equal to another lifecycle with the same name" do
    expect(described_class[:scoped]).to eq described_class["scoped"]
  end
end
