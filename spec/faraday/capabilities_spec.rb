# frozen_string_literal: true

RSpec.describe 'adapter capabilities' do
  # An adapter that does not declare anything, like pre-capabilities adapters.
  let(:legacy_adapter) do
    Class.new(Faraday::Adapter) do
      define_method(:call) do |env|
        super(env)
        save_response(env, 200, 'legacy', {})
      end
    end
  end

  # An adapter that explicitly declares streaming responses.
  let(:streaming_adapter) do
    klass = Class.new(legacy_adapter)
    klass.supports_capabilities(Faraday::Adapter::STREAMING_RESPONSES)
    klass
  end

  before do
    Faraday::Adapter.register_middleware(legacy_cap: legacy_adapter)
    Faraday::Adapter.register_middleware(streaming_cap: streaming_adapter)
  end

  after do
    Faraday::Adapter.registered_middleware.delete(:legacy_cap)
    Faraday::Adapter.registered_middleware.delete(:streaming_cap)
  end

  describe 'fixed connection requirements' do
    it 'keeps requests working when no capability is required' do
      conn = Faraday.new { |f| f.adapter :legacy_cap }
      expect(conn.get('/').body).to eq('legacy')
    end

    it 'accepts requirements declared on an adapter that supports them' do
      conn = Faraday.new do |f|
        f.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
        f.adapter :streaming_cap
      end
      expect(conn.get('/').body).to eq('legacy')
      expect(conn.required_capabilities)
        .to eq([Faraday::Adapter::STREAMING_RESPONSES])
    end

    it 'normalizes required capabilities to symbols' do
      conn = Faraday.new do |f|
        f.require_capabilities 'streaming_responses'
        f.adapter :streaming_cap
      end
      expect(conn.required_capabilities).to eq([:streaming_responses])
    end

    it 'reuses the provided builder and keeps its requirements' do
      builder = Faraday::RackBuilder.new do |b|
        b.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
        b.adapter :streaming_cap
      end
      conn = Faraday::Connection.new(nil, builder: builder)
      expect(conn.required_capabilities)
        .to eq([Faraday::Adapter::STREAMING_RESPONSES])
    end

    it 'raises when the adapter is set after the requirements' do
      expect do
        Faraday.new do |f|
          f.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
          f.adapter :legacy_cap
        end
      end.to raise_error(
        Faraday::MissingCapabilitiesError,
        /does not support.*for this connection.*streaming_responses/
      )
    end

    it 'raises when requirements are declared after the adapter' do
      expect do
        Faraday.new do |f|
          f.adapter :legacy_cap
          f.require_capabilities Faraday::Adapter::TLS_CIPHERS
        end
      end.to raise_error(Faraday::MissingCapabilitiesError, /tls_ciphers/)
    end

    it 'accepts requirements passed through the connection options hash' do
      expect do
        Faraday.new(nil, required_capabilities: [Faraday::Adapter::TLS_CIPHERS]) do |f|
          f.adapter :legacy_cap
        end
      end.to raise_error(Faraday::MissingCapabilitiesError, /tls_ciphers/)
    end

    it 'carries requirements over when the connection is duplicated' do
      conn = Faraday.new do |f|
        f.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
        f.adapter :streaming_cap
      end
      expect(conn.dup.required_capabilities)
        .to eq([Faraday::Adapter::STREAMING_RESPONSES])
    end

    it 're-checks fixed requirements when the stack is compiled' do
      builder = Faraday::RackBuilder.new do |b|
        b.adapter :legacy_cap
        b.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
      end

      expect { builder.app }
        .to raise_error(Faraday::MissingCapabilitiesError, /streaming_responses/)
    end

    it 'compiles the stack when the adapter declares the required capabilities' do
      conn = Faraday.new do |f|
        f.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
        f.adapter :streaming_cap
      end
      expect(conn.builder.app).to be_a(Faraday::Adapter)
    end
  end

  describe 'per-request requirements' do
    it 'raises before the adapter call if a capability is missing' do
      conn = Faraday.new { |f| f.adapter :legacy_cap }

      expect do
        conn.get('/') do |req|
          req.options.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
        end
      end.to raise_error(Faraday::MissingCapabilitiesError,
                         /for this request.*streaming_responses/)
    end

    it 'allows the request when every required capability is declared' do
      conn = Faraday.new { |f| f.adapter :streaming_cap }

      response = conn.get('/') do |req|
        req.options.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
      end
      expect(response.body).to eq('legacy')
    end

    it 'allows requests without per-request requirements through old adapters' do
      conn = Faraday.new { |f| f.adapter :legacy_cap }
      expect(conn.get('/').body).to eq('legacy')
    end

    it 'does not enter the adapter when requirements are missing' do
      called = false
      tracker = Class.new(legacy_adapter) do
        define_method(:call) do |env|
          called = true
          super(env)
        end
      end
      Faraday::Adapter.register_middleware(tracker_cap: tracker)

      conn = Faraday.new { |f| f.adapter :tracker_cap }
      expect do
        conn.get('/') do |req|
          req.options.require_capabilities Faraday::Adapter::TLS_VERIFY
        end
      end.to raise_error(Faraday::MissingCapabilitiesError, /tls_verify/)
      expect(called).to be(false)
    end

    it 'accepts requirements passed directly in the request options hash' do
      conn = Faraday.new { |f| f.adapter :legacy_cap }

      expect do
        conn.build_request(:get) do |req|
          req.options.update(required_capabilities: [Faraday::Adapter::PARALLEL])
        end
      end.not_to raise_error

      expect do
        conn.run_request(:get, '/', nil, nil) do |req|
          req.options.required_capabilities = [Faraday::Adapter::PARALLEL]
        end
      end.to raise_error(Faraday::MissingCapabilitiesError, /parallel/)
    end
  end
end
