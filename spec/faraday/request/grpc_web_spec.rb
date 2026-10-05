# frozen_string_literal: true

RSpec.describe Faraday::Request::GRPCWeb do
  def frame(payload, type: Faraday::GRPCWeb::DATA_FRAME_TYPE)
    type.chr + [payload.bytesize].pack('N') + payload
  end

  def trailer_frame(trailers)
    frame(trailers, type: Faraday::GRPCWeb::TRAILER_FRAME_TYPE)
  end

  def split_every(byte_string, size)
    byte_string.bytes.each_slice(size).map { |bytes| bytes.pack('C*') }
  end

  def base64(byte_string)
    [byte_string].pack('m0')
  end

  def connection(stubs, **options)
    Faraday.new do |builder|
      builder.request :grpc_web, **options
      builder.adapter :test, stubs
    end
  end

  def unary_response(message, trailers = { 'grpc-status' => '0' }, mode: :binary, chunks: 2)
    trailer_text = trailers.map { |key, value| "#{key}: #{value}" }.join("\r\n")
    body = frame(message) + trailer_frame(trailer_text + "\r\n")
    body = base64(body) if mode == :text
    [200, { 'Content-Type' => Faraday::GRPCWeb.content_type(mode) }, split_every(body, chunks)]
  end

  it 'sends a binary framed POST and returns unframed protobuf bytes' do
    received = nil
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do |env|
        received = env
        unary_response("\x08\x07".b)
      end
    end

    response = connection(stubs).post('/service/Unary', "\x0a\x03abc".b)

    expect(received.method).to eq(:post)
    expect(received.request_headers['Content-Type']).to eq('application/grpc-web+proto')
    expect(received.request_headers['Accept']).to eq('application/grpc-web+proto')
    expect(received.request_headers['x-grpc-web']).to eq('1')
    expect(received.request_body).to eq("\x00\x00\x00\x00\x05\x0a\x03abc".b)
    expect(response.body).to eq("\x08\x07".b)
    expect(response.headers['grpc-status']).to eq('0')
  end

  it 'supports base64 text requests and responses split across chunks' do
    received = nil
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do |env|
        received = env
        unary_response("\x08\x07".b, mode: :text, chunks: 3)
      end
    end

    response = connection(stubs, mode: :text).post('/service/Unary', "\x0a\x03abc".b)

    expect(received.request_headers['Content-Type']).to eq('application/grpc-web-text+proto')
    expect(received.request_body).to eq(base64("\x00\x00\x00\x00\x05\x0a\x03abc".b))
    expect(response.body).to eq("\x08\x07".b)
    expect(response.headers['grpc-status']).to eq('0')
    expect(response.env[:grpc_web_trailers]).to eq('grpc-status' => '0')
  end

  it 'encodes a nil body as an empty protobuf message' do
    received = nil
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do |env|
        received = env
        unary_response("".b)
      end
    end

    connection(stubs).post('/service/Unary')

    expect(received.request_body).to eq("\x00\x00\x00\x00\x00".b)
  end

  it 'rejects a request body that is not a String' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') { unary_response('x'.b) }
    end

    expect do
      connection(stubs).post('/service/Unary', { not: :protobuf })
    end.to raise_error(ArgumentError, /encoded protobuf String/)
  end

  it 'rejects an unsupported mode when the middleware is created' do
    expect do
      Faraday::Request::GRPCWeb.new(nil, mode: :unknown)
    end.to raise_error(ArgumentError, /unknown gRPC-Web mode/)
  end

  it 'rejects a response containing two unary data frames' do
    body = frame('a'.b) + frame('b'.b) + trailer_frame("grpc-status: 0\r\n")
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') { [200, { 'Content-Type' => 'application/grpc-web+proto' }, body] }
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /more than one data frame/)
  end

  it 'rejects a truncated final response' do
    body = frame('abc'.b).byteslice(0, 7)
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') { [200, { 'Content-Type' => 'application/grpc-web+proto' }, body] }
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /middle of a frame/)
  end

  it 'rejects a truncated final text response' do
    encoded = base64(frame('abc'.b))
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, { 'Content-Type' => 'application/grpc-web-text+proto' }, encoded.byteslice(0, 8)]
      end
    end

    expect do
      connection(stubs, mode: :text).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /middle of a frame/)
  end

  it 'enforces the configured response frame size' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        unary_response('abc', { 'grpc-status' => '0' }, chunks: 2)
      end
    end

    expect do
      connection(stubs, max_frame_size: 2).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /maximum size/)
  end

  it 'enforces the configured request frame size' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') { unary_response('x'.b) }
    end

    expect do
      connection(stubs, max_frame_size: 1).post('/service/Unary', 'abc'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /maximum size/)
  end

  it 'raises HTTP errors independently of grpc-status' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') { [500, {}, 'bad gateway'] }
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::HTTPError, /HTTP status 500/)
  end

  it 'raises gRPC errors independently of HTTP 200' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, { 'Content-Type' => 'application/grpc-web+proto' }, trailer_frame("grpc-status: 7\r\ngrpc-message: permission%20denied\r\n")]
      end
    end

    begin
      connection(stubs).post('/service/Unary', 'x'.b)
    rescue Faraday::GRPCWeb::StatusError => error
      expect(error.code).to eq(7)
      expect(error.trailers['grpc-message']).to eq('permission denied')
    else
      raise 'expected a gRPC status error'
    end
  end

  it 'decodes trailers-only errors split across chunks' do
    body = trailer_frame("grpc-status: 7\r\ngrpc-message: permission%20denied\r\n")
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, { 'Content-Type' => 'application/grpc-web+proto' }, split_every(body, 2)]
      end
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::StatusError, /gRPC error 7: permission denied/)
  end

  it 'rejects a successful status without trailer metadata' do
    body = frame('x'.b)
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, { 'Content-Type' => 'application/grpc-web+proto' }, body]
      end
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /missing its trailer/)
  end

  it 'rejects the wrong response content type' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') { [200, { 'Content-Type' => 'text/plain' }, 'ok'] }
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /unexpected gRPC-Web Content-Type/)
  end

  it 'accepts content type parameters and uppercase media types' do
    body = frame("x".b) + trailer_frame("grpc-status: 0\r\n")
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, { 'Content-Type' => 'Application/GRPC-Web+Proto; charset=binary' }, body]
      end
    end

    response = connection(stubs).post('/service/Unary', 'x'.b)

    expect(response.status).to eq(200)
    expect(response.body).to eq('x'.b)
  end

  it 'rejects a missing gRPC status' do
    body = frame('x'.b) + trailer_frame("other: value\r\n")
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, { 'Content-Type' => 'application/grpc-web+proto' }, body]
      end
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::ProtocolError, /invalid gRPC-Web grpc-status: nil/)
  end

  it 'accepts grpc-status from HTTP headers for trailers-only errors' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, { 'Content-Type' => 'application/grpc-web+proto', 'grpc-status' => '13' }, '']
      end
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::StatusError, /gRPC error 13/)
  end

  it 'decodes grpc-message supplied in HTTP response headers' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/service/Unary') do
        [200, {
          'Content-Type' => 'application/grpc-web+proto',
          'grpc-status' => '13',
          'grpc-message' => 'internal%20error'
        }, '']
      end
    end

    expect do
      connection(stubs).post('/service/Unary', 'x'.b)
    end.to raise_error(Faraday::GRPCWeb::StatusError, /gRPC error 13: internal error/)
  end
end
