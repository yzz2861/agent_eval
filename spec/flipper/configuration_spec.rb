require 'flipper/configuration'

RSpec.describe Flipper::Configuration do
  describe '#adapter' do
    it 'returns instance using Memory adapter' do
      expect(subject.adapter).to be_a(Flipper::Adapters::Memory)
    end

    it 'can be set' do
      instance = Flipper::Adapters::Memory.new
      expect(subject.adapter).not_to be(instance)
      subject.adapter { instance }
      expect(subject.adapter).to be(instance)
      # All adapters are wrapped in Memoizable
      expect(subject.default.adapter.adapter).to be(instance)
    end
  end

  describe '#default' do
    it 'returns instance using Memory adapter' do
      expect(subject.default).to be_a(Flipper::DSL)
      # All adapters are wrapped in Memoizable
      expect(subject.default.adapter.adapter).to be_a(Flipper::Adapters::Memory)
    end

    it 'can be set default' do
      instance = Flipper.new(Flipper::Adapters::Memory.new)
      expect(subject.default).not_to be(instance)
      subject.default { instance }
      expect(subject.default).to be(instance)
    end
  end

  describe '#layers' do
    it 'passes shared actor layers to the default Flipper instance' do
      configuration = described_class.new
      configuration.layers = { experiments: { search: 0...1000 } }
      flipper = configuration.default

      expect(flipper.layers.layer_for(:search).name).to eq(:experiments)
    end

    it 'defaults to empty layers' do
      configuration = described_class.new

      expect(configuration.layers).to equal(Flipper::Layers::EMPTY)
      expect(configuration.default.layers.layer_for(:search)).to be_nil
    end

    it 'restores empty layers when assigned nil' do
      configuration = described_class.new
      configuration.layers = { experiments: { search: 0...1000 } }
      configuration.layers = nil

      expect(configuration.layers).to equal(Flipper::Layers::EMPTY)
    end
  end

  describe '#statsd' do
    let(:statsd) { double(Statsd) }

    after do
      Flipper::Instrumentation::StatsdSubscriber.client = nil
    end

    it 'returns nil by default' do
      expect(subject.statsd).to be_nil
    end

    it 'can be set' do
      subject.statsd = statsd
      expect(subject.statsd).to be(statsd)
    end
  end
end
