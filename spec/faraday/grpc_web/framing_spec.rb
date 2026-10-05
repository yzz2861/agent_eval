# frozen_string_literal: true

RSpec.describe Faraday::GrpcWeb do
  let(:message) { "\x0a\x05hello".b }

  describe '.encode_frame' do
    it 'encodes a data frame as flag + big-endian length + payload' do
      frame = described_class.encode_frame(message)
      expect(frame.bytes).to eq([0x00, 0, 0, 0, 7] + message.bytes)
    end

    it 'encodes a trailers frame with the MSB flag set' do
      frame = described_class.encode_frame('grpc-status: 0', trailer: true)
      expect(frame.bytes).to eq([0x80, 0, 0, 0, 14] + 'grpc-status: 0'.bytes)
    end

    it 'encodes an empty payload' do
      expect(described_class.encode_frame('').bytes).to eq([0, 0, 0, 0, 0])
    end
  end

  describe Faraday::GrpcWeb::FrameParser do
    let(:trailers_payload) { "grpc-status: 0\r\ngrpc-message: ok\r\n" }
    let(:stream) do
      Faraday::GrpcWeb.encode_frame(message) +
        Faraday::GrpcWeb.encode_frame(trailers_payload, trailer: true)
    end

    it 'parses a data frame and a trailers frame' do
      parser = described_class.new
      parser << stream
      frames = parser.finish

      expect(frames.map(&:type)).to eq(%i[data trailers])
      expect(frames[0].payload).to eq(message)
      expect(frames[1].payload).to eq(trailers_payload)
    end

    it 'handles chunks split anywhere, including inside the length prefix' do
      (0..stream.bytesize).each do |i|
        parser = described_class.new
        parser << stream.byteslice(0, i)
        parser << stream.byteslice(i..)
        frames = parser.finish

        expect(frames.map(&:type)).to eq(%i[data trailers])
        expect(frames[0].payload).to eq(message)
      end
    end

    it 'handles byte-by-byte delivery' do
      parser = described_class.new
      stream.each_byte { |byte| parser << byte.chr }
      expect(parser.finish.map(&:type)).to eq(%i[data trailers])
    end

    context 'in text mode' do
      let(:text_stream) { [stream].pack('m0') }

      it 'decodes base64 before framing' do
        parser = described_class.new(text: true)
        parser << text_stream
        frames = parser.finish

        expect(frames.map(&:type)).to eq(%i[data trailers])
        expect(frames[0].payload).to eq(message)
      end

      it 'handles chunks split inside base64 quartets and length prefixes' do
        (0..text_stream.bytesize).each do |i|
          parser = described_class.new(text: true)
          parser << text_stream.byteslice(0, i)
          parser << text_stream.byteslice(i..)
          frames = parser.finish

          expect(frames.map(&:type)).to eq(%i[data trailers])
          expect(frames[0].payload).to eq(message)
        end
      end

      it 'rejects invalid base64 data' do
        parser = described_class.new(text: true)
        expect { parser << '!!!!' }.to raise_error(Faraday::GrpcWeb::ProtocolError)
      end

      it 'rejects a stream ending mid-quartet' do
        parser = described_class.new(text: true)
        parser << text_stream.byteslice(0, text_stream.bytesize - 1)
        expect { parser.finish }.to raise_error(Faraday::GrpcWeb::ProtocolError, /base64/)
      end
    end

    it 'rejects frames larger than max_frame_size' do
      parser = described_class.new(max_frame_size: 4)
      expect { parser << stream }.to raise_error(Faraday::GrpcWeb::ProtocolError, /exceeds/)
    end

    it 'rejects a stream truncated inside the frame header' do
      parser = described_class.new
      parser << stream.byteslice(0, 3)
      expect { parser.finish }.to raise_error(Faraday::GrpcWeb::ProtocolError, /truncated/)
    end

    it 'rejects a stream truncated inside the frame payload' do
      parser = described_class.new
      parser << stream.byteslice(0, stream.bytesize - 2)
      expect { parser.finish }.to raise_error(Faraday::GrpcWeb::ProtocolError, /truncated/)
    end

    it 'rejects compressed frames' do
      parser = described_class.new
      compressed = [0x01, 0, 0, 0, 0].pack('C*')
      expect { parser << compressed }.to raise_error(Faraday::GrpcWeb::ProtocolError, /compressed/)
    end

    it 'rejects unknown frame flags' do
      parser = described_class.new
      unknown = [0x40, 0, 0, 0, 0].pack('C*')
      expect { parser << unknown }.to raise_error(Faraday::GrpcWeb::ProtocolError, /flag/)
    end

    it 'rejects appending after finish' do
      parser = described_class.new
      parser << stream
      parser.finish
      expect { parser << 'x' }.to raise_error(Faraday::GrpcWeb::ProtocolError)
    end
  end

  describe '.build_unary_result' do
    let(:data_frame) { Faraday::GrpcWeb::Frame.new(:data, message) }
    let(:trailers_frame) do
      Faraday::GrpcWeb::Frame.new(:trailers, "grpc-status: 0\r\n")
    end

    it 'returns the message and trailers of a well-formed response' do
      result = described_class.build_unary_result([data_frame, trailers_frame])
      expect(result.message).to eq(message)
      expect(result.grpc_status).to eq(0)
    end

    it 'accepts a trailers-only response' do
      result = described_class.build_unary_result([trailers_frame])
      expect(result.message).to be_nil
    end

    it 'rejects more than one data frame' do
      expect { described_class.build_unary_result([data_frame, data_frame, trailers_frame]) }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /at most one data frame/)
    end

    it 'rejects a response without a trailers frame' do
      expect { described_class.build_unary_result([data_frame]) }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /missing a trailers/)
    end

    it 'rejects frames after the trailers frame' do
      expect { described_class.build_unary_result([trailers_frame, data_frame]) }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /after the trailers/)
    end

    it 'rejects trailers without grpc-status' do
      bad = Faraday::GrpcWeb::Frame.new(:trailers, "grpc-message: hi\r\n")
      expect { described_class.build_unary_result([data_frame, bad]) }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /missing grpc-status/)
    end

    it 'rejects a non-numeric grpc-status' do
      bad = Faraday::GrpcWeb::Frame.new(:trailers, "grpc-status: ok\r\n")
      expect { described_class.build_unary_result([data_frame, bad]) }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /invalid grpc-status/)
    end
  end

  describe '.parse_trailers' do
    it 'parses HTTP/1 style trailer lines' do
      trailers = described_class.parse_trailers("grpc-status: 3\r\nGrpc-Message: oops\r\n")
      expect(trailers).to eq('grpc-status' => '3', 'grpc-message' => 'oops')
    end

    it 'percent-decodes grpc-message without treating + as space' do
      trailers = described_class.parse_trailers("grpc-status: 3\r\ngrpc-message: a%20b%2Bc+d\r\n")
      expect(trailers['grpc-message']).to eq('a b+c+d')
    end

    it 'rejects malformed lines' do
      expect { described_class.parse_trailers('no-colon-here') }
        .to raise_error(Faraday::GrpcWeb::ProtocolError, /malformed/)
    end
  end
end
