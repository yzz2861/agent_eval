require 'flipper/layers'

RSpec.describe Flipper::Layers do
  describe '#initialize' do
    it 'finds the layer for a configured feature' do
      layers = described_class.new(
        experiments: { checkout: 0...400 },
        onboarding: { onboarding_a: 0...500 }
      )

      expect(layers.layer_for(:checkout).name).to eq(:experiments)
      expect(layers.layer_for(:onboarding_a).name).to eq(:onboarding)
      expect(layers.layer_for(:search)).to be_nil
    end

    it 'accepts layer instances' do
      layer = Flipper::Layer.new(:experiments, checkout: 0...400)
      layers = described_class.new(experiments: layer)

      expect(layers.layer_for(:checkout)).to equal(layer)
    end

    it 'rejects a feature allocated to more than one layer' do
      expect do
        described_class.new(
          experiments: { checkout: 0...400 },
          onboarding: { checkout: 400...800 }
        )
      end.to raise_error(Flipper::InvalidLayer, /cannot be in both layer/)
    end

    it 'rejects non-hash configuration' do
      expect { described_class.new(:experiments) }.to raise_error(Flipper::InvalidLayer, /must be a Hash/)
    end
  end
end
