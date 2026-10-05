# frozen_string_literal: true

RSpec.describe Faraday::Response::GrpcWeb do
  let(:message) { "\x0a\x05hello".b }
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }
  let(:options) { {} }
  let(:conn) do
    Faraday.new(url: 'http://grpc.example') do |builder|
      builder.response :grpc_web, **options
      builder.adapter :test, stubs
    end
  end

  def grpc_web_stream(payload, status: 0, grpc_message: nil)
    trailers = +"grpc-status: #{status}\r\n"
    trailers << "grpc-message: #{grpc_message}\r\n" if grpc_message
    Faraday::GrpcWeb.encode_frame(payload) +
      Faraday::GrpcWeb.encode_frame(trailers, trailer: true)
  end

  def stub_response(status:, body:, content_type: 'application/grpc-web')
    stubs.post('/pkg.Service/Method') do
      [status, { 'Content-Type' => content_type }, body]
    end
  end

  context 'with a binary response' do
    it 'returns the raw protobuf bytes and exposes the trailers' do
      stub_response(status: 200, body: grpc_web_stream(message))
      response = conn.post('/pkg.Service/Method')

      expect(response.body).to eq(message)
      result = response.env[:grpc_web]
      expect(result.grpc_status).to eq(0)
      expect(result.trailers['grpc-status']).to eq('0')
    end

    it 'parses frames split across the length prefix and payload' do
      stream = grpc_web_stream(message)
      stub_response(status: 200, body: stream)

      # Feed the exact stubbed bytes through the parser at every split
      # point to prove chunk boundaries do not matter.
      (0..stream.bytesize).each do |i|
        parser = Faraday::GrpcWeb::FrameParser.new
        parser << stream.byteslice(0, i)
        parser << stream.byteslice(i..)
        result = Faraday::GrpcWeb.build_unary_result(parser.finish)
        expect(result.message).to eq(message)
      end
    end
  end

  context 'with a base64 text response' do
    let(:text_body) { [grpc_web_stream(message)].pack('m0') }

    it 'decodes base64 frames' do
      stub_response(status: 200, body: text_body,
                    content_type: 'application/grpc-web-text')
      response = conn.post('/pkg.Service/Method')
      expect(response.body).to eq(message)
    end

    it 'decodes text frames split mid-quartet' do
      (0..text_body.bytesize).each do |i|
        parser = Faraday::GrpcWeb::FrameParser.new(text: true)
        parser << text_body.byteslice(0, i)
        parser << text_body.byteslice(i..)
        result = Faraday::GrpcWeb.build_unary_result(parser.finish)
        expect(result.message).to eq(message)
      end
    end
  end

  context 'when grpc-status is not OK' do
    it 'raises a StatusError with the status and decoded message' do
      stub_response(status: 200,
                    body: grpc_web_stream('', status: 3, grpc_message: 'bad%20request'))
      expect { conn.post('/pkg.Service/Method') }.to raise_error(
        Faraday::GrpcWeb::StatusError
      ) do |error|
        expect(error.grpc_status).to eq(3)
        expect(error.grpc_message).to eq('bad request')
        expect(error.message).to include('gRPC status 3')
      end
    end

    it 'raises a StatusError for trailers-only error responses' do
      body = Faraday::GrpcWeb.encode_frame("grpc-status: 14\r\n", trailer: true)
      stub_response(status: 200, body: body)
      expect { conn.post('/pkg.Service/Method') }.to raise_error(
        Faraday::GrpcWeb::StatusError
      ) { |error| expect(error.grpc_status).to eq(14) }
    end
  end

  context 'when the HTTP status is not 2xx' do
    it 'raises a ClientError for 4xx regardless of grpc-status' do
      stub_response(status: 400, body: grpc_web_stream(message))
      expect { conn.post('/pkg.Service/Method') }
        .to raise_error(Faraday::ClientError)
    end

    it 'raises a ServerError for 5xx regardless of grpc-status' do
      stub_response(status: 500, body: grpc_web_stream(message))
      expect { conn.post('/pkg.Service/Method') }
        .to raise_error(Faraday::ServerError)
    end
  end

  context 'with malformed responses' do
    it 'rejects more than one data frame' do
      body = Faraday::GrpcWeb.encode_frame(message) + grpc_web_stream(message)
      stub_response(status: 200, body: body)
      expect { conn.post('/pkg.Service/Method') }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /at most one data frame/)
    end

    it 'rejects a response without a trailers frame' do
      stub_response(status: 200, body: Faraday::GrpcWeb.encode_frame(message))
      expect { conn.post('/pkg.Service/Method') }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /missing a trailers/)
    end

    it 'rejects a truncated stream' do
      stub_response(status: 200, body: grpc_web_stream(message).byteslice(0, 8))
      expect { conn.post('/pkg.Service/Method') }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /truncated/)
    end

    it 'rejects frames exceeding max_frame_size' do
      conn = Faraday.new(url: 'http://grpc.example') do |builder|
        builder.response :grpc_web, max_frame_size: 4
        builder.adapter :test, stubs
      end
      stub_response(status: 200, body: grpc_web_stream(message))
      expect { conn.post('/pkg.Service/Method') }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /exceeds/)
    end
  end

 it 'rejects an empty body as a truncated response' do
    stub_response(status: 200, body: '')
    expect { conn.post('/pkg.Service/Method') }
      .to raise_error(Faraday::GrpcWeb::ProtocolError, /missing a trailers/)
  end

  it 'ignores responses with a non gRPC-Web content type' do
    stub_response(status: 200, body: 'plain text', content_type: 'text/plain')
    response = conn.post('/pkg.Service/Method')
    expect(response.body).to eq('plain text')
    expect(response.env[:grpc_web]).to be_nil
  end
end
