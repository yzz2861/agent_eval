# frozen_string_literal: true

RSpec.describe Faraday::Response::EventStream, type: :response do
  let(:received) { [] }
  let(:middleware) do
    described_class.new(lambda { |env|
      Faraday::Response.new(env)
    }) do |message, _env|
      received << message
    end
  end

  def encode_message(headers: [], payload: +'')
    headers_bytes = headers.map do |name, value|
      encoded = value.b
      [name.bytesize].pack('C') + name.b + [7].pack('C') + [encoded.bytesize].pack('n') + encoded
    end.join
    total_length = 12 + headers_bytes.bytesize + payload.bytesize + 4
    prelude = [total_length, headers_bytes.bytesize].pack('N2')
    prelude += [Zlib.crc32(prelude)].pack('N')
    frame = prelude + headers_bytes + payload
    frame + [Zlib.crc32(frame)].pack('N')
  end

  def process(body)
    env = Faraday::Env.from(
      body: body, request: {},
      request_headers: Faraday::Utils::Headers.new,
      response_headers: Faraday::Utils::Headers.new
    )
    middleware.call(env)
  end

  it 'requires a handler block' do
    expect { described_class.new }
      .to raise_error(Faraday::InitializationError, /requires a block/)
  end

  it 'is registered as :event_stream' do
    expect(Faraday::Response.lookup_middleware(:event_stream)).to eq(described_class)
  end

  context 'with a buffered body' do
    it 'delivers every validated message to the handler' do
      body = encode_message(headers: [[':message-type', 'event']], payload: 'one') +
             encode_message(payload: 'two')
      process(body)
      expect(received.map(&:payload)).to eq(%w[one two])
      expect(received[0].headers).to eq(':message-type' => 'event')
    end

    it 'leaves an empty body alone' do
      expect { process('') }.not_to raise_error
      expect(received).to be_empty
    end

    it 'raises when the body ends mid-message' do
      body = encode_message(payload: 'truncated').byteslice(0, 14)
      expect { process(body) }.to raise_error(Faraday::EventStream::TruncationError)
    end

    it 'raises when a message fails validation' do
      body = encode_message(payload: 'corrupt')
      body.setbyte(-1, body.getbyte(-1) ^ 0xFF)
      expect { process(body) }.to raise_error(Faraday::EventStream::MessageCrcError)
      expect(received).to be_empty
    end
  end

  context 'with a streamed response' do
    it 'decodes arbitrarily split chunks and finishes cleanly' do
      env = Faraday::Env.from(request: {})
      middleware.on_request(env)
      stream = env.request.on_data
      bytes = encode_message(payload: 'streamed')
      bytes.each_byte { |byte| stream.call(byte.chr, 0, env) }
      middleware.on_complete(env)
      expect(received.map(&:payload)).to eq(['streamed'])
    end

    it 'raises when the stream ends mid-message' do
      env = Faraday::Env.from(request: {})
      middleware.on_request(env)
      env.request.on_data.call('partial', 7, env)
      expect { middleware.on_complete(env) }
        .to raise_error(Faraday::EventStream::TruncationError)
    end
  end

  context 'with the test adapter' do
    it 'decodes the response through a full stack' do
      messages = []
      conn = Faraday.new do |f|
        f.response :event_stream do |message|
          messages << message
        end
        f.adapter :test do |stub|
          stub.get('/stream') do
            [200, { 'Content-Type' => 'application/vnd.amazon.eventstream' },
             encode_message(payload: 'via adapter')]
          end
        end
      end
      response = conn.get('/stream')
      expect(response.status).to eq(200)
      expect(messages.map(&:payload)).to eq(['via adapter'])
    end
  end
end
