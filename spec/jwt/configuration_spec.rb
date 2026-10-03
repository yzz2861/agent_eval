# frozen_string_literal: true

RSpec.describe JWT do
  describe 'JWT.configure' do
    it 'yields the configuration' do
      expect { |b| described_class.configure(&b) }.to yield_with_args(described_class.configuration)
    end

    it 'allows configuration to be changed via the block' do
      expect(described_class.configuration.decode.verify_expiration).to eq(true)

      described_class.configure do |config|
        config.decode.verify_expiration = false
      end

      expect(described_class.configuration.decode.verify_expiration).to eq(false)
    end
  end

  describe 'decode.strict_json' do
    it 'defaults to false for the backwards compatible JWT.decode entry point' do
      expect(described_class.configuration.decode.strict_json).to eq(false)
    end

    it 'is included in the decode configuration hash' do
      expect(described_class.configuration.decode.to_h[:strict_json]).to eq(false)
    end
  end
end
