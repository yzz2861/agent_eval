# frozen_string_literal: true

RSpec.describe Faraday::EventStream::Decoder do
  subject(:decoder) { described_class.new }

  # Builds a wire-format message, computing both CRCs.
  def encode_message(headers: [], payload: +'')
    headers_bytes = headers.map { |name, type, value| encode_header(name, type, value) }.join
    total_length = 12 + headers_bytes.bytesize + payload.bytesize + 4
    prelude = [total_length, headers_bytes.bytesize].pack('N2')
    prelude += [Zlib.crc32(prelude)].pack('N')
    frame = prelude + headers_bytes + payload
    frame + [Zlib.crc32(frame)].pack('N')
  end

  def encode_header(name, type, value_bytes)
    [name.bytesize].pack('C') + name.b + [type].pack('C') + value_bytes
  end

  def string_header(name, value)
    [name, 7, [value.bytesize].pack('n') + value.b]
  end

  let(:message_bytes) do
    encode_message(headers: [string_header(':message-type', 'event')], payload: 'hello')
  end

  it 'decodes a message with headers and payload' do
    messages = decoder.feed(message_bytes)
    expect(messages.size).to eq(1)
    expect(messages[0].headers).to eq(':message-type' => 'event')
    expect(messages[0].payload).to eq('hello')
  end

  it 'yields messages to the block and returns them' do
    yielded = []
    returned = decoder.feed(message_bytes) { |message| yielded << message }
    expect(yielded).to eq(returned)
    expect(yielded.size).to eq(1)
  end

  it 'decodes every defined header value type' do
    timestamp_ms = 1_696_000_000_123
    uuid_bytes = ['00112233445566778899aabbccddeeff'].pack('H*')
    bytes = encode_message(headers: [
                             ['bool-true', 0, +''],
                             ['bool-false', 1, +''],
                             ['byte', 2, [0xFE].pack('C')],
                             ['short', 3, [-1234].pack('s>')],
                             ['integer', 4, [-123_456].pack('l>')],
                             ['long', 5, [-123_456_789_012].pack('q>')],
                             ['bytes', 6, [3].pack('n') + 'abc'],
                             string_header('string', 'héllo'),
                             ['timestamp', 8, [timestamp_ms].pack('q>')],
                             ['uuid', 9, uuid_bytes]
                           ])
    headers = decoder.feed(bytes)[0].headers
    expect(headers['bool-true']).to be(true)
    expect(headers['bool-false']).to be(false)
    expect(headers['byte']).to eq(-2)
    expect(headers['short']).to eq(-1234)
    expect(headers['integer']).to eq(-123_456)
    expect(headers['long']).to eq(-123_456_789_012)
    expect(headers['bytes']).to eq('abc')
    expect(headers['string']).to eq('héllo')
    expect(headers['string'].encoding).to eq(Encoding::UTF_8)
    expect(headers['timestamp']).to eq(Time.at(Rational(timestamp_ms, 1000)).utc)
    expect(headers['uuid']).to eq('00112233-4455-6677-8899-aabbccddeeff')
  end

  it 'preserves headers with names unknown to Faraday' do
    bytes = encode_message(headers: [string_header('x-custom-header', 'custom')])
    expect(decoder.feed(bytes)[0].headers).to eq('x-custom-header' => 'custom')
  end

  it 'decodes consecutive messages from a single chunk' do
    first = encode_message(payload: 'one')
    second = encode_message(payload: 'two')
    messages = decoder.feed(first + second)
    expect(messages.map(&:payload)).to eq(%w[one two])
    expect(decoder.message_index).to eq(2)
  end

  it 'decodes messages fed byte by byte' do
    bytes = encode_message(payload: 'split me')
    messages = []
    bytes.each_byte do |byte|
      decoder.feed(byte.chr) { |message| messages << message }
    end
    expect(messages.size).to eq(1)
    expect(messages[0].payload).to eq('split me')
  end

  it 'waits for a complete message before delivering' do
    head, tail = message_bytes.byteslice(0, 20), message_bytes.byteslice(20..-1)
    expect(decoder.feed(head)).to be_empty
    expect(decoder.feed(tail).size).to eq(1)
  end

  context 'with an invalid prelude CRC' do
    it 'raises before trusting the length fields' do
      # A huge total length with a bad prelude CRC must fail immediately
      # instead of making the decoder wait for gigabytes of data.
      prelude = [2**31, 0].pack('N2')
      prelude += [Zlib.crc32(prelude) ^ 0xFF].pack('N')
      expect { decoder.feed(prelude) }.to raise_error(Faraday::EventStream::PreludeCrcError) do |error|
        expect(error.message_index).to eq(0)
        expect(error.byte_offset).to eq(0)
      end
    end
  end

  context 'with invalid length fields' do
    def encode_with_lengths(total_length, headers_length)
      prelude = [total_length, headers_length].pack('N2')
      prelude + [Zlib.crc32(prelude)].pack('N')
    end

    it 'rejects a total length smaller than the minimum frame' do
      expect { decoder.feed(encode_with_lengths(15, 0)) }
        .to raise_error(Faraday::EventStream::ProtocolError, /total length/)
    end

    it 'rejects a headers length exceeding the total length' do
      expect { decoder.feed(encode_with_lengths(16, 1)) }
        .to raise_error(Faraday::EventStream::ProtocolError, /headers length/)
    end
  end

  context 'with an invalid message CRC' do
    it 'raises and does not deliver the message' do
      corrupt = message_bytes.dup
      corrupt.setbyte(-1, corrupt.getbyte(-1) ^ 0xFF)
      expect { decoder.feed(corrupt) }.to raise_error(Faraday::EventStream::MessageCrcError) do |error|
        expect(error.message_index).to eq(0)
        expect(error.byte_offset).to eq(message_bytes.bytesize - 4)
      end
    end

    it 'reports the index of the failing message' do
      good = encode_message(payload: 'good')
      bad = encode_message(payload: 'bad')
      bad.setbyte(-1, bad.getbyte(-1) ^ 0xFF)
      expect { decoder.feed(good + bad) }.to raise_error(Faraday::EventStream::MessageCrcError) do |error|
        expect(error.message_index).to eq(1)
        expect(error.byte_offset).to eq(good.bytesize + bad.bytesize - 4)
      end
    end

    it 'does not leak payload content into the error message' do
      corrupt = encode_message(payload: 'super-secret-payload')
      corrupt.setbyte(-1, corrupt.getbyte(-1) ^ 0xFF)
      expect { decoder.feed(corrupt) }.to raise_error(Faraday::EventStream::MessageCrcError) do |error|
        expect(error.message).not_to include('super-secret-payload')
      end
    end
  end

  context 'with an illegal header value type' do
    it 'raises InvalidHeaderTypeError with the byte offset of the type' do
      bytes = encode_message(headers: [['weird', 42, +'']])
      expect { decoder.feed(bytes) }.to raise_error(Faraday::EventStream::InvalidHeaderTypeError) do |error|
        expect(error.message_index).to eq(0)
        # prelude (12) + name length (1) + name (5)
        expect(error.byte_offset).to eq(18)
      end
    end

    it 'is distinguishable from other protocol errors' do
      bytes = encode_message(headers: [['weird', 42, +'']])
      expect { decoder.feed(bytes) }
        .to raise_error(Faraday::EventStream::InvalidHeaderTypeError)
      expect(Faraday::EventStream::InvalidHeaderTypeError.ancestors)
        .to include(Faraday::EventStream::ProtocolError)
    end
  end

  context 'with a malformed headers section' do
    it 'rejects a header name overrunning the headers section' do
      # headers_length says 2 bytes: a name length of 5 with only 1 byte left.
      headers_bytes = [5].pack('C') + 'x'
      bytes = encode_message_raw(headers_bytes)
      expect { decoder.feed(bytes) }
        .to raise_error(Faraday::EventStream::ProtocolError, /overruns/)
    end

    def encode_message_raw(headers_bytes)
      total_length = 12 + headers_bytes.bytesize + 4
      prelude = [total_length, headers_bytes.bytesize].pack('N2')
      prelude += [Zlib.crc32(prelude)].pack('N')
      frame = prelude + headers_bytes
      frame + [Zlib.crc32(frame)].pack('N')
    end
  end

  describe '#finish' do
    it 'returns nil when the stream ended on a message boundary' do
      decoder.feed(message_bytes)
      expect(decoder.finish).to be_nil
    end

    it 'raises when the stream ends mid-message' do
      decoder.feed(message_bytes.byteslice(0, 10))
      expect { decoder.finish }.to raise_error(Faraday::EventStream::TruncationError) do |error|
        expect(error.message_index).to eq(0)
        expect(error.byte_offset).to eq(10)
      end
    end

    it 'reports the absolute offset after complete messages' do
      decoder.feed(message_bytes)
      decoder.feed('junk')
      expect { decoder.finish }.to raise_error(Faraday::EventStream::TruncationError) do |error|
        expect(error.message_index).to eq(1)
        expect(error.byte_offset).to eq(message_bytes.bytesize + 4)
      end
    end
  end
end
