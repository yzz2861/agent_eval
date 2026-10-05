# frozen_string_literal: true

require 'zlib'

RSpec.describe Faraday::EventStream do
  def pack_header(name, value, type_code = nil)
    type_code ||= header_type_code(value)
    name = name.b
    [name.bytesize].pack('C') + name + [type_code].pack('C') + pack_header_value(value, type_code)
  end

  def header_type_code(value)
    case value
    when true then 0
    when false then 1
    when Integer
      value.abs <= 127 ? 2 : 3
    when String
      value.encoding == Encoding::UTF_8 ? 7 : 6
    when Time then 8
    end
  end

  def pack_header_value(value, type_code)
    case type_code
    when 0, 1 then +''
    when 2 then [value].pack('c')
    when 3 then [value].pack('s>')
    when 4 then [value].pack('l>')
    when 5 then [value].pack('q>')
    when 6 then [value.bytesize].pack('n') + value.b
    when 7
      bytes = value.encode(Encoding::UTF_8).b
      [bytes.bytesize].pack('n') + bytes
    when 8 then [(value.to_r * 1000).round].pack('q>')
    when 9 then [value.delete('-')].pack('H32')
    else
      +''
    end
  end

  def eventstream_frame(payload = +'', headers_bytes = +'')
    prelude = [16 + headers_bytes.bytesize + payload.bytesize,
               headers_bytes.bytesize].pack('NN')
    prelude_crc = [Zlib.crc32(prelude)].pack('N')
    body = prelude + prelude_crc + headers_bytes.b + payload.b
    body + [Zlib.crc32(body)].pack('N')
  end

  def feed_in_chunks(decoder, data, chunk_size)
    data.bytes.each_slice(chunk_size) do |bytes|
      decoder.call(bytes.pack('C*'), nil, :env)
    end
  end

  it 'delivers an empty message after validating the complete frame' do
    messages = []
    decoder = described_class::Decoder.new { |message| messages << message }
    frame = eventstream_frame

    decoder.call(frame.byteslice(0, frame.bytesize - 1), nil, :env)
    expect(messages).to be_empty

    decoder.call(frame.byteslice(-1), nil, :env)
    expect(messages.size).to eq(1)
    expect(messages.first.payload).to eq('')
    expect(messages.first.headers).to eq({})
  end

  it 'accepts arbitrary chunk boundaries and multiple messages' do
    first = eventstream_frame('first')
    second = eventstream_frame('second')
    data = first + second

    (1..data.bytesize).each do |chunk_size|
      messages = []
      decoder = described_class::Decoder.new { |message| messages << message }
      feed_in_chunks(decoder, data, chunk_size)
      decoder.finish

      expect(messages.map(&:payload)).to eq(%w[first second])
      expect(decoder.message_count).to eq(2)
      expect(decoder.received_bytes).to eq(data.bytesize)
    end
  end

  it 'parses all typed header values' do
    timestamp = Time.at(1_700_000_000_123 / 1000r)
    uuid = '01234567-89ab-cdef-0123-456789abcdef'
    headers = [
      ['bool_true', true],
      ['bool_false', false],
      ['byte', -5],
      ['short', -1234, 3],
      ['integer', -123_456, 4],
      ['long', -123_456_789, 5],
      ['bytes', +'binary', 6],
      ['string', 'héllo', 7],
      ['time', timestamp, 8],
      ['uuid', uuid, 9]
    ].map { |args| pack_header(*args) }.join
    frame = eventstream_frame('payload', headers)
    messages = []
    decoder = described_class::Decoder.new { |message| messages << message }

    feed_in_chunks(decoder, frame, 7)
    message = messages.first

    expect(message['bool_true']).to eq(true)
    expect(message['bool_false']).to eq(false)
    expect(message['byte']).to eq(-5)
    expect(message['short']).to eq(-1234)
    expect(message['integer']).to eq(-123_456)
    expect(message['long']).to eq(-123_456_789)
    expect(message['bytes']).to eq('binary')
    expect(message['string']).to eq('héllo')
    expect(message['time']).to eq(timestamp.utc)
    expect(message['time'].utc_offset).to eq(0)
    expect(message['uuid']).to eq(uuid)
    expect(message.payload).to eq('payload')
  end

  it 'accepts an empty header name without treating it as a malformed header' do
    frame = eventstream_frame('', [0, 0].pack('CC'))
    message = nil
    decoder = described_class::Decoder.new { |msg| message = msg }

    decoder.call(frame)
    decoder.finish

    expect(message['']).to eq(true)
  end

  it 'passes the response env to callbacks that request it' do
    received = nil
    decoder = described_class::Decoder.new do |message, env|
      received = [message, env]
    end

    decoder.call(eventstream_frame('ok'), 19, :response_env)

    expect(received.first.payload).to eq('ok')
    expect(received.last).to eq(:response_env)
  end

  it 'freezes payloads so later buffer reuse cannot mutate delivered messages' do
    message = nil
    decoder = described_class::Decoder.new { |msg| message = msg }
    decoder.call(eventstream_frame('secret'))

    expect(message.payload).to be_frozen
  end

  it 'raises truncation errors with the next message number and byte position' do
    first = eventstream_frame('first')
    decoder = described_class::Decoder.new {}
    decoder.call(first + eventstream_frame('second').byteslice(0, 20))

    expect { decoder.finish }.to raise_error do |error|
      expect(error).to be_a(described_class::TruncatedMessageError)
      expect(error.message_number).to eq(2)
      expect(error.byte_position).to eq(first.bytesize)
      expect(error.byte_offset).to eq(first.bytesize)
      expect(error.message).not_to include('second')
    end
  end

  it 'raises when the response ends before a prelude can be read' do
    decoder = described_class::Decoder.new {}
    decoder.call(eventstream_frame.byteslice(0, 4))

    expect { decoder.finish }.to raise_error(
      described_class::TruncatedMessageError
    ) do |error|
      expect(error.message_number).to eq(1)
      expect(error.byte_position).to eq(0)
    end
  end

  it 'validates the prelude CRC before trusting declared lengths' do
    frame = eventstream_frame.dup
    frame.setbyte(8, frame.getbyte(8) ^ 0xff)
    frame.setbyte(0, 255)
    decoder = described_class::Decoder.new {}

    expect { decoder.call(frame.byteslice(0, 12)) }.to raise_error(
      described_class::PreludeCrcError
    ) do |error|
      expect(error.message_number).to eq(1)
      expect(error.byte_position).to eq(0)
    end
  end

  it 'rejects invalid total and headers lengths with precise positions' do
    decoder = described_class::Decoder.new {}
    prelude = [15, 0].pack('NN')
    prelude << [Zlib.crc32(prelude)].pack('N')

    expect { decoder.call(prelude) }.to raise_error(
      described_class::InvalidTotalLengthError
    ) do |error|
      expect(error.byte_position).to eq(0)
    end

    prelude = [16, 1].pack('NN')
    prelude << [Zlib.crc32(prelude)].pack('N')
    decoder = described_class::Decoder.new {}
    expect { decoder.call(prelude) }.to raise_error(
      described_class::InvalidHeaderLengthError
    ) do |error|
      expect(error.message_number).to eq(1)
      expect(error.byte_position).to eq(4)
    end

    decoder = described_class::Decoder.new {}
    prelude = [described_class::MAX_TOTAL_BYTE_LENGTH, 0].pack('NN')
    prelude << [Zlib.crc32(prelude)].pack('N')
    expect { decoder.call(prelude) }.to raise_error(
      described_class::InvalidPayloadLengthError
    ) do |error|
      expect(error.byte_position).to eq(4)
    end
  end

  it 'does not deliver a message whose message CRC is invalid' do
    delivered = false
    decoder = described_class::Decoder.new { delivered = true }
    frame = eventstream_frame('secret')
    frame.setbyte(12, frame.getbyte(12) ^ 0xff)

    expect { decoder.call(frame) }.to raise_error(described_class::MessageCrcError) do |error|
      expect(error.message_number).to eq(1)
      expect(error.byte_position).to eq(0)
      expect(error.message).not_to include('secret')
    end
    expect(delivered).to be(false)
  end

  it 'distinguishes reserved-but-unknown legal header types from invalid type bytes' do
    unknown_header = [1].pack('C') + 'a' + [10].pack('C')
    invalid_header = [1].pack('C') + 'a' + [128].pack('C')

    expect do
      described_class::Decoder.new {}.call(eventstream_frame('', unknown_header))
    end.to raise_error(described_class::UnknownHeaderTypeError) do |error|
      expect(error.message_number).to eq(1)
      expect(error.byte_position).to eq(14)
    end

    expect do
      described_class::Decoder.new {}.call(eventstream_frame('', invalid_header))
    end.to raise_error(described_class::InvalidHeaderTypeError) do |error|
      expect(error.byte_position).to eq(14)
    end
  end

  it 'reports malformed headers and invalid header values without exposing payload data' do
    malformed = eventstream_frame('secret', +'x')
    expect do
      described_class::Decoder.new {}.call(malformed)
    end.to raise_error(described_class::InvalidHeaderError) do |error|
      expect(error.message_number).to eq(1)
      expect(error.byte_position).to eq(12)
      expect(error.message).not_to include('secret')
    end

    missing_type = [1].pack('C') + 'n'
    expect do
      described_class::Decoder.new {}.call(eventstream_frame('secret', missing_type))
    end.to raise_error(described_class::InvalidHeaderError) do |error|
      expect(error.byte_position).to eq(14)
    end

    truncated_int = [1].pack('C') + 'n' + [4].pack('C')
    expect do
      described_class::Decoder.new {}.call(eventstream_frame('secret', truncated_int))
    end.to raise_error(described_class::InvalidHeaderError) do |error|
      expect(error.byte_position).to eq(15)
    end

    invalid_utf8 = eventstream_frame('secret', eventstream_headers_bytes('x', +"\xff"))
    expect do
      described_class::Decoder.new {}.call(invalid_utf8)
    end.to raise_error(described_class::InvalidHeaderValueError) do |error|
      expect(error.message).not_to include('secret')
    end
  end

  it 'is idempotently finished and rejects later chunks' do
    decoder = described_class::Decoder.new {}

    expect(decoder.finish).to be(decoder)
    expect(decoder.finish).to be(decoder)
    expect { decoder.call('x') }.to raise_error(described_class::Error)
  end

  it 're-raises truncation until the decoder is finished successfully' do
    decoder = described_class::Decoder.new {}
    decoder.call(eventstream_frame.byteslice(0, 1))

    expect { decoder.finish }.to raise_error(described_class::TruncatedMessageError)
    expect { decoder.finish }.to raise_error(described_class::TruncatedMessageError)
  end

  def eventstream_headers_bytes(name, value)
    [name.bytesize].pack('C') + name + [7].pack('C') +
      [value.bytesize].pack('n') + value
  end
end
