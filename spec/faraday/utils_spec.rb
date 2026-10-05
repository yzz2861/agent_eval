# frozen_string_literal: true

RSpec.describe Faraday::Utils do
  describe 'headers parsing' do
    let(:multi_response_headers) do
      "HTTP/1.x 500 OK\r\nContent-Type: text/html; charset=UTF-8\r\n" \
        "HTTP/1.x 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
    end

    it 'parse headers for aggregated responses' do
      headers = Faraday::Utils::Headers.new
      headers.parse(multi_response_headers)

      result = headers.to_hash

      expect(result['Content-Type']).to eq('application/json; charset=UTF-8')
    end
  end

  describe 'URI parsing' do
    let(:url) { 'http://example.com/abc' }

    it 'escapes safe buffer' do
      str = FakeSafeBuffer.new('$32,000.00')
      expect(Faraday::Utils.escape(str)).to eq('%2432%2C000.00')
    end

    it 'parses with default parser' do
      with_default_uri_parser(nil) do
        uri = normalize(url)
        expect(uri.host).to eq('example.com')
      end
    end

    it 'parses with URI' do
      with_default_uri_parser(URI) do
        uri = normalize(url)
        expect(uri.host).to eq('example.com')
      end
    end

    it 'parses with block' do
      with_default_uri_parser(->(u) { "booya#{'!' * u.size}" }) do
        expect(normalize(url)).to eq('booya!!!!!!!!!!!!!!!!!!!!!!')
      end
    end

    it 'replaces headers hash' do
      headers = Faraday::Utils::Headers.new('authorization' => 't0ps3cr3t!')
      expect(headers).to have_key('authorization')

      headers.replace('content-type' => 'text/plain')
      expect(headers).not_to have_key('authorization')
    end
  end

  describe '.deep_merge!' do
    let(:connection_options) { Faraday::ConnectionOptions.new }
    let(:url) do
      {
        url: 'http://example.com/abc',
        headers: { 'Mime-Version' => '1.0' },
        request: { oauth: { consumer_key: 'anonymous' } },
        ssl: { version: '2' }
      }
    end

    it 'recursively merges the headers' do
      connection_options.headers = { user_agent: 'My Agent 1.0' }
      deep_merge = Faraday::Utils.deep_merge!(connection_options, url)

      expect(deep_merge.headers).to eq('Mime-Version' => '1.0', user_agent: 'My Agent 1.0')
    end

    context 'when a target hash has an Options Struct value' do
      let(:request) do
        {
          params_encoder: nil,
          proxy: nil,
          bind: nil,
          timeout: nil,
          open_timeout: nil,
          read_timeout: nil,
          write_timeout: nil,
          boundary: nil,
          oauth: { consumer_key: 'anonymous' },
          context: nil,
          on_data: nil
        }
      end
      let(:ssl) do
        {
          verify: nil,
          ca_file: nil,
          ca_path: nil,
          verify_mode: nil,
          cert_store: nil,
          client_cert: nil,
          client_key: nil,
          certificate: nil,
          private_key: nil,
          verify_depth: nil,
          version: '2',
          min_version: nil,
          max_version: nil,
          verify_hostname: nil,
          hostname: nil,
          ciphers: nil
        }
      end

      it 'does not overwrite an Options Struct value' do
        deep_merge = Faraday::Utils.deep_merge!(connection_options, url)

        expect(deep_merge.request.to_h).to eq(request)
        expect(deep_merge.ssl.to_h).to eq(ssl)
      end
    end
  end

  describe '.deep_dup' do
    it 'recursively copies hashes, arrays, strings and options' do
      options = Faraday::RequestOptions.from(
        timeout: 5,
        context: { 'auth' => { 'scopes' => %w[read] } }
      )
      source = {
        'headers' => Faraday::Utils::Headers.new('X-Team' => 'core'),
        'list' => ['a', %w[b c]],
        'options' => options
      }

      copy = Faraday::Utils.deep_dup(source)
      copy['headers']['X-Team'] = 'changed'
      copy['list'][0] = 'changed'
      copy['list'][1] << 'd'
      copy['options'].timeout = 9
      copy['options'].context['auth']['scopes'] << 'write'

      expect(source['headers']['X-Team']).to eq('core')
      expect(source['list']).to eq(['a', %w[b c]])
      expect(options.timeout).to eq(5)
      expect(options.context['auth']['scopes']).to eq(%w[read])
      expect(copy['options'].context['auth']['scopes']).to eq(%w[read write])
    end

    it 'preserves the class of hash subclasses' do
      headers = Faraday::Utils::Headers.new('X-Team' => 'core')
      copy = Faraday::Utils.deep_dup(headers)

      expect(copy).to be_a(Faraday::Utils::Headers)
      expect(copy['x-team']).to eq('core')
    end

    it 'shares IOs, locks, procs and service objects by reference' do
      service = Object.new
      callback = proc {}
      lock = Mutex.new
      source = { 'io' => $stdout, 'lock' => lock, 'callback' => callback, 'service' => service }

      copy = Faraday::Utils.deep_dup(source)

      expect(copy['io']).to equal($stdout)
      expect(copy['lock']).to equal(lock)
      expect(copy['callback']).to equal(callback)
      expect(copy['service']).to equal(service)
    end
  end
end
