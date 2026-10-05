# frozen_string_literal: true

RSpec.describe Faraday::GRPCWeb do
  def frame(payload, type: described_class::DATA_FRAME_TYPE)
    type.chr + [payload.bytesize].pack('N') + payload
  end

  def trailer_frame(trailers)
    frame(trailers, type: described_class::TRAILER_FRAME_TYPE)
  end

  def split_every(byte_string, size)
    byte_string.bytes.each_slice(size).map { |bytes| bytes.pack('C*') }
  end

  def base64(byte_string)
    [byte_string].pack('m0')
  end

  describe '.encode_request' do
    it 'encodes an uncompressed binary unary frame' do
      message = "\x0a\x05hello".b

      expect(described_class.encode_request(message)).to eq("\x00\x00\x00\x00\x07\x0a\x05hello".b)
    end

    it 'base64-encodes text mode frames' do
      message = "\x0a\x05hello".b

      expect(described_class.encode_request(message, mode: :text)).to eq(base64(frame(message)))
    end

    it 'rejects an oversized request frame' do
      expect do
        described_class.encode_request('x', max_frame_size: 0)
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /maximum size/)
    end
  end

  describe '.decode_response' do
    it 'decodes one binary data frame and a trailer frame' do
      body = frame("\x08\x01".b) + trailer_frame("grpc-status: 0\r\n")

      result = described_class.decode_response(body)

      expect(result.data).to eq("\x08\x01".b)
      expect(result.trailers).to eq('grpc-status' => '0')
    end

    it 'decodes chunks split inside the data length prefix' do
      body = frame("\x08\x01".b) + trailer_frame("grpc-status: 0\r\n")

      result = described_class.decode_response(split_every(body, 2), mode: :binary)

      expect(result.data).to eq("\x08\x01".b)
      expect(result.trailers).to eq('grpc-status' => '0')
    end

    it 'decodes text chunks split inside base64 quads' do
      body = frame("\x08\x01".b) + trailer_frame("grpc-status: 0\r\n")
    encoded = base64(body)

      result = described_class.decode_response(split_every(encoded, 3), mode: :text)

      expect(result.data).to eq("\x08\x01".b)
      expect(result.trailers).to eq('grpc-status' => '0')
    end

    it 'decodes a trailers-only gRPC error response' do
      result = described_class.decode_response(trailer_frame("grpc-status: 7\r\n"))

      expect(result.data?).to be(false)
      expect(result.trailers).to eq('grpc-status' => '7')
    end

    it 'preserves percent-encoded grpc-message trailers for the middleware to decode' do
      body = frame("\x08\x01".b) + trailer_frame("grpc-status: 0\r\ngrpc-message: hello%20world\r\n")

      result = described_class.decode_response(body)

      expect(result.trailers['grpc-message']).to eq('hello%20world')
    end

    describe '.decode_metadata' do
      it 'decodes RFC 3986 percent escapes without treating plus as a space' do
        expect(described_class.decode_metadata('hello%20world%21+gRPC')).to eq('hello world!+gRPC')
      end
    end

    it 'does not mutate the response chunks' do
      chunk = (frame("x".b) + trailer_frame("grpc-status: 0\r\n")).force_encoding(Encoding::UTF_8)
      original = chunk.dup

      described_class.decode_response([chunk])

      expect(chunk).to eq(original)
    end

    it 'rejects a second unary data frame' do
      body = frame('a'.b) + frame('b'.b) + trailer_frame("grpc-status: 0\r\n")

      expect do
        described_class.decode_response(body)
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /more than one data frame/)
    end

    it 'rejects a truncated data frame' do
      body = frame('abc'.b).byteslice(0, 6)

      expect do
        described_class.decode_response(body)
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /middle of a frame/)
    end

    it 'rejects a data frame larger than the configured limit' do
      body = frame('abc'.b) + trailer_frame("grpc-status: 0\r\n")

      expect do
        described_class.decode_response(body, max_frame_size: 2)
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /maximum size/)
    end

    it 'rejects a compressed frame' do
      body = "\x01\x00\x00\x00\x01x" + trailer_frame("grpc-status: 0\r\n")

      expect do
        described_class.decode_response(body)
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /unsupported.*frame type/)
    end

    it 'rejects a data response without a trailer frame' do
      expect do
        described_class.decode_response(frame('abc'.b))
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /missing its trailer/)
    end

    it 'rejects invalid base64' do
      expect do
        described_class.decode_response(['!!!!'], mode: :text)
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /invalid.*base64/)
    end

    it 'rejects duplicate trailer keys' do
      body = frame('x'.b) + trailer_frame("grpc-status: 0\r\ngrpc-status: 0\r\n")

      expect do
        described_class.decode_response(body)
      end.to raise_error(Faraday::GRPCWeb::ProtocolError, /duplicate.*grpc-status/)
    end
  end
end
