# frozen_string_literal: true

RSpec.describe 'Adapter capabilities' do
  let(:declaring_adapter) do
    Class.new(Faraday::Adapter) do
      declare_capability :streaming
      declare_capability :tls, false

      def call(env)
        super
        save_response(env, 200, 'ok')
      end
    end
  end

  describe Faraday::Adapter do
    it 'treats undeclared capabilities as unknown, not supported' do
      expect(Faraday::Adapter.capability_support(:streaming)).to be_nil
      expect(Faraday::Adapter.supports_capability?(:streaming)).to be(false)
    end

    it 'declares supported capabilities' do
      expect(declaring_adapter.supports_capability?(:streaming)).to be(true)
      expect(declaring_adapter.capability_support(:streaming)).to be(true)
    end

    it 'distinguishes explicitly unsupported capabilities from unknown ones' do
      expect(declaring_adapter.capability_support(:tls)).to be(false)
      expect(declaring_adapter.supports_capability?(:tls)).to be(false)
      expect(declaring_adapter.capability_support(:other)).to be_nil
    end

    it 'inherits declarations to subclasses without sharing state' do
      subclass = Class.new(declaring_adapter)
      expect(subclass.supports_capability?(:streaming)).to be(true)

      subclass.declare_capability :streaming, false
      expect(subclass.supports_capability?(:streaming)).to be(false)
      expect(declaring_adapter.supports_capability?(:streaming)).to be(true)
    end
  end

  describe 'connection-level requirements' do
    it 'raises at build time when the adapter does not declare a required capability' do
      expect do
        Faraday.new('http://example.com') do |faraday|
          faraday.require_capability :streaming
          faraday.adapter :test
        end
      end.to raise_error(Faraday::UnsupportedCapabilityError, /Faraday::Adapter::Test.*streaming/)
    end

    it 'exposes the adapter name and missing capabilities on the error' do
      error =
        begin
          Faraday.new('http://example.com') do |faraday|
            faraday.require_capability :streaming, :tls
            faraday.adapter :test
          end
          nil
        rescue Faraday::UnsupportedCapabilityError => e
          e
        end

      expect(error.adapter_name).to eq('Faraday::Adapter::Test')
      expect(error.missing_capabilities).to contain_exactly(:streaming, :tls)
    end

    it 'builds successfully when the adapter declares the required capability' do
      conn = Faraday.new('http://example.com') do |faraday|
        faraday.require_capability :streaming
        faraday.adapter declaring_adapter
      end

      expect(conn.required_capabilities).to include(:streaming)
    end

    it 'verifies requirements added after the connection is built' do
      conn = Faraday.new('http://example.com') do |faraday|
        faraday.adapter :test
      end

      expect { conn.require_capability :streaming }
        .to raise_error(Faraday::UnsupportedCapabilityError, /streaming/)
    end

    it 'does not require declarations when no capability is required (legacy adapters)' do
      conn = Faraday.new('http://example.com') do |faraday|
        faraday.adapter :test do |stubs|
          stubs.get('/ok') { [200, {}, 'ok'] }
        end
      end

      expect(conn.get('/ok').body).to eq('ok')
    end
  end

  describe 'request-level requirements' do
    let(:conn) do
      Faraday.new('http://example.com') do |faraday|
        faraday.adapter :test do |stubs|
          stubs.get('/ok') { [200, {}, 'ok'] }
        end
      end
    end

    it 'raises before entering the adapter when a required capability is not declared' do
      expect do
        conn.get('/ok') { |req| req.require_capability :streaming }
      end.to raise_error(Faraday::UnsupportedCapabilityError, /Faraday::Adapter::Test.*streaming/)
    end

    it 'lets requests without requirements through to legacy adapters' do
      expect(conn.get('/ok').body).to eq('ok')
    end

    it 'lets requests through when the adapter declares the required capability' do
      conn = Faraday.new('http://example.com') do |faraday|
        faraday.adapter declaring_adapter
      end

      response = conn.get('/') { |req| req.require_capability :streaming }
      expect(response.status).to eq(200)
    end
  end
end
