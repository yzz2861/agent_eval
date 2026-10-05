# frozen_string_literal: true

RSpec.describe Faraday::Request::GrpcWeb do
  let(:message) { "\x0a\x05hello".b }
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }
  let(:options) { {} }
  let(:conn) do
    Faraday.new(url: 'http://grpc.example') do |builder|
      builder.request :grpc_web, **options
      builder.adapter :test, stubs
    end
  end

  def last_request_env
    env = nil
    stubs.post('/pkg.Service/Method') do |request_env|
      env = {
        body: request_env[:body]&.dup,
        request_headers: request_env[:request_headers].dup
      }
      [200, {}, '']
    end
    yield
    env
  end

  context 'in binary mode' do
    it 'frames the body as a single gRPC-Web data frame' do
      env = last_request_env { conn.post('/pkg.Service/Method', message) }
      expect(env[:body].bytes).to eq([0x00, 0, 0, 0, 7] + message.bytes)
    end

    it 'sets the gRPC-Web headers' do
      env = last_request_env { conn.post('/pkg.Service/Method', message) }
      headers = env[:request_headers]
      expect(headers['Content-Type']).to eq('application/grpc-web')
      expect(headers['Accept']).to eq('application/grpc-web')
      expect(headers['X-Grpc-Web']).to eq('1')
      expect(headers['TE']).to eq('trailers')
    end

    it 'does not override a user-provided content type' do
      env = last_request_env do
        conn.post('/pkg.Service/Method', message) do |req|
          req.headers['Content-Type'] = 'application/grpc-web+proto'
        end
      end
      expect(env[:request_headers]['Content-Type']).to eq('application/grpc-web+proto')
    end
  end

  context 'in text mode' do
    let(:options) { { mode: :text } }

    it 'base64-encodes the framed body' do
      env = last_request_env { conn.post('/pkg.Service/Method', message) }
      frame = Faraday::GrpcWeb.encode_frame(message)
      expect(env[:body]).to eq([frame].pack('m0'))
    end

    it 'uses the grpc-web-text content type' do
      env = last_request_env { conn.post('/pkg.Service/Method', message) }
      expect(env[:request_headers]['Content-Type']).to eq('application/grpc-web-text')
    end
  end

  it 'leaves a request without a body untouched' do
    env = last_request_env { conn.post('/pkg.Service/Method') }
    expect(env[:body]).to eq('')
    expect(env[:request_headers]['Content-Type']).to be_nil
    expect(env[:request_headers]['X-Grpc-Web']).to be_nil
  end

  it 'rejects non-string bodies' do
    expect { conn.post('/pkg.Service/Method', foo: 'bar') }
      .to raise_error(Faraday::GrpcWeb::Error, /encoded protobuf bytes/)
  end

  context 'with an invalid mode' do
    let(:options) { { mode: :json } }

    it 'raises a descriptive error' do
      expect { conn.post('/pkg.Service/Method', message) }
        .to raise_error(Faraday::GrpcWeb::Error, /invalid gRPC-Web mode/)
    end
  end
end
