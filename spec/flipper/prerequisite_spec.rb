require 'flipper/prerequisite'

RSpec.describe Flipper::Prerequisite do
  it 'defaults to requiring the feature to be on' do
    prerequisite = described_class.new(:base_payments)
    expect(prerequisite.feature_name).to eq(:base_payments)
    expect(prerequisite.on?).to be(true)
    expect(prerequisite.off?).to be(false)
  end

  it 'can require the feature to be off' do
    prerequisite = described_class.new(:legacy_mode, on: false)
    expect(prerequisite.on?).to be(false)
    expect(prerequisite.off?).to be(true)
  end

  it 'symbolizes the feature name' do
    expect(described_class.new('base_payments').feature_name).to eq(:base_payments)
  end

  it 'is equal to another prerequisite with the same name and state' do
    expect(described_class.new(:a)).to eq(described_class.new('a', on: true))
    expect(described_class.new(:a)).not_to eq(described_class.new(:a, on: false))
    expect(described_class.new(:a)).not_to eq(described_class.new(:b))
  end
end
