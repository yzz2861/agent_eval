# frozen_string_literal: true

RSpec.describe Faraday::Adapter do
  let(:adapter) { Faraday::Adapter.new }
  let(:request) { {} }

  describe 'capability declaration' do
    let(:parent_adapter) do
      Class.new(Faraday::Adapter) do
        supports_capabilities Faraday::Adapter::STREAMING_RESPONSES
      end
    end
    let(:child_adapter) do
      Class.new(parent_adapter) do
        supports_capability Faraday::Adapter::PARALLEL
      end
    end

    it 'declares no capabilities by default' do
      expect(Faraday::Adapter.declared_capabilities).to eq([])
    end

    it 'records declared capabilities' do
      expect(parent_adapter.declared_capabilities)
        .to eq([Faraday::Adapter::STREAMING_RESPONSES])
    end

    it 'supports checking a single capability or a list' do
      expect(parent_adapter).to be_supports_capabilities(Faraday::Adapter::STREAMING_RESPONSES)
      expect(parent_adapter).not_to be_supports_capabilities(Faraday::Adapter::PARALLEL)
      expect(child_adapter.supports_capabilities?(Faraday::Adapter::STREAMING_RESPONSES,
                                                  Faraday::Adapter::PARALLEL)).to be(true)
    end

    it 'treats a missing declaration as unsupported' do
      legacy = Class.new(Faraday::Adapter)
      expect(legacy.supports_capabilities?(:anything_at_all)).to be(false)
      expect(legacy.missing_capabilities(:anything_at_all)).to eq([:anything_at_all])
    end

    it 'inherits capabilities and allows extending them without mutating the parent' do
      expect(child_adapter.declared_capabilities)
        .to eq([Faraday::Adapter::STREAMING_RESPONSES, Faraday::Adapter::PARALLEL])
      expect(parent_adapter.declared_capabilities)
        .to eq([Faraday::Adapter::STREAMING_RESPONSES])
    end

    it 'does not duplicate capabilities when declared twice' do
      adapter_class = Class.new(Faraday::Adapter) do
        supports_capabilities :feature_x
        supports_capabilities :feature_x
      end
      expect(adapter_class.declared_capabilities).to eq([:feature_x])
    end

    it 'exposes declared capabilities on adapter instances' do
      expect(parent_adapter.new(nil).declared_capabilities)
        .to eq([Faraday::Adapter::STREAMING_RESPONSES])
      expect(parent_adapter.new(nil).supports_capabilities?(
        Faraday::Adapter::STREAMING_RESPONSES
      )).to be(true)
    end

    it 'accepts capabilities as strings and normalizes them to symbols' do
      adapter_class = Class.new(Faraday::Adapter) do
        supports_capabilities 'feature_y'
      end
      expect(adapter_class.declared_capabilities).to eq([:feature_y])
      expect(adapter_class.supports_capabilities?(:feature_y)).to be(true)
    end
  end

  context '#request_timeout' do
    it 'gets :read timeout' do
      expect(timeout(:read)).to eq(nil)

      request[:timeout] = 5
      request[:write_timeout] = 1

      expect(timeout(:read)).to eq(5)

      request[:read_timeout] = 2

      expect(timeout(:read)).to eq(2)
    end

    it 'gets :open timeout' do
      expect(timeout(:open)).to eq(nil)

      request[:timeout] = 5
      request[:write_timeout] = 1

      expect(timeout(:open)).to eq(5)

      request[:open_timeout] = 2

      expect(timeout(:open)).to eq(2)
    end

    it 'gets :write timeout' do
      expect(timeout(:write)).to eq(nil)

      request[:timeout] = 5
      request[:read_timeout] = 1

      expect(timeout(:write)).to eq(5)

      request[:write_timeout] = 2

      expect(timeout(:write)).to eq(2)
    end

    it 'attempts unknown timeout type' do
      expect { timeout(:unknown) }.to raise_error(ArgumentError)
    end

    def timeout(type)
      adapter.send(:request_timeout, type, request)
    end
  end
end
