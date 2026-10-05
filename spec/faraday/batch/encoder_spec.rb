# frozen_string_literal: true

RSpec.describe Faraday::Batch::Encoder do
  let(:batch) do
    Faraday::Batch::Request.new.tap do |request|
      request.request(:get, '/articles/1?include=author', nil,
                      { 'X-Trace' => 'abc' }, id: 'one')
      request.request(:post, '/articles', '{"title":"hello"}',
                      { 'Content-Type' => 'application/json' }, id: 'two')
    end
  end

  describe '#headers' do
    subject(:encoder) { described_class.new(batch, boundary: 'batch-boundary') }

    it 'uses multipart/mixed with the declared boundary' do
      expect(encoder.headers).to eq(
        'Content-Type' => 'multipart/mixed; boundary="batch-boundary"'
      )
    end
  end

  describe '#body' do
    subject(:encoder) { described_class.new(batch, boundary: 'batch-boundary') }

    let(:body) { encoder.body }

    it 'wraps every part in boundary delimiters' do
      expect(body).to start_with("--batch-boundary\r\n")
      expect(body).to end_with("--batch-boundary--\r\n")
      expect(body.scan('--batch-boundary').size).to eq(3)
    end

    it 'assigns the Content-ID envelope header per part' do
      expect(body).to include("Content-ID: one\r\n")
      expect(body).to include("Content-ID: two\r\n")
    end

    it 'encapsulates each sub-request as application/http' do
      expect(body).to include('Content-Type: application/http; msgtype="request"')
      expect(body).to include("GET /articles/1?include=author HTTP/1.1\r\n")
      expect(body).to include("POST /articles HTTP/1.1\r\n")
    end

    it 'keeps each part method, relative target, headers and body' do
      expect(body).to include("X-Trace: abc\r\n")
      expect(body).to include("Content-Type: application/json\r\n")
      expect(body).to include('{"title":"hello"}')
    end

    it 'returns a frozen-in-time binary string' do
      first = encoder.body
      expect(first.encoding).to eq(Encoding::BINARY)
      expect(encoder.body).to eq(first)
      expect(encoder.body).not_to equal(first)
    end
  end

  describe 'duplicate IDs' do
    it 'is rejected by the batch before encoding' do
      expect do
        Faraday::Batch::Request.new.tap do |request|
          request.request(:get, '/a', nil, {}, id: 'dup')
          request.request(:get, '/b', nil, {}, id: 'dup')
        end
      end.to raise_error(Faraday::Batch::DuplicateIdError, /dup/)
    end

    it 'raises when duplicate ids somehow reach the encoder' do
      part_one = Faraday::Batch::Part.new(:get, '/a', nil, {}, id: 'dup')
      part_two = Faraday::Batch::Part.new(:get, '/b', nil, {}, id: 'dup')
      request = Faraday::Batch::Request.new
      request.parts.concat([part_one, part_two])

      expect { described_class.new(request, boundary: 'x') }
        .to raise_error(Faraday::Batch::DuplicateIdError, /dup/)
    end
  end

  describe 'boundary generation' do
    let(:binary_body) { (0..255).map(&:chr).join.dup.force_encoding(Encoding::BINARY) }

    it 'generates a boundary that does not occur in a sub-request body' do
      batch.request(:put, '/binary', binary_body, {}, id: 'three')
      encoder = described_class.new(batch)

      expect(binary_body.include?(encoder.boundary)).to be(false)
      expect(encoder.body).to include("PUT /binary HTTP/1.1\r\n")
      expect(encoder.body).to include(binary_body)
    end

    it 'rejects an explicit boundary that occurs in a sub-request body' do
      batch.request(:put, '/binary', 'payload containing forced-boundary', {}, id: 'three')

      expect do
        described_class.new(batch, boundary: 'forced-boundary')
      end.to raise_error(Faraday::Error, /forced-boundary/)
    end

    it 'retries generated candidates that collide with a body' do
      payload = 'stable payload'
      candidates = ['collide', 'collide', 'safe-boundary']
      allow(SecureRandom).to receive(:hex) { candidates.shift || 'never' }

      boundary = described_class.generate_boundary(['FaradayBatchBoundarycollide' + payload])
      expect(boundary).to eq('FaradayBatchBoundarysafe-boundary')
    end

    it 'raises after exhausting unique-boundary retries' do
      allow(SecureRandom).to receive(:hex).and_return('collide')

      expect { described_class.generate_boundary(['FaradayBatchBoundarycollide']) }
        .to raise_error(Faraday::Error, /unique multipart boundary/)
    end
  end

  describe 'IO bodies' do
    it 'reads the stream into the part body' do
      stream = StringIO.new("streamed\x00data".b)
      batch.request(:post, '/upload', stream, {}, id: 'upload')
      encoder = described_class.new(batch)

      expect(encoder.body).to include("streamed\x00data".b)
    end

    it 'rejects bodies that are neither strings nor IOs' do
      batch.request(:post, '/object', { nested: :hash }, {}, id: 'object')

      expect { described_class.new(batch).body }
        .to raise_error(Faraday::Error, /String or IO/)
    end
  end

  describe 'empty batch' do
    it 'emits only the closing boundary' do
      encoder = described_class.new(Faraday::Batch::Request.new, boundary: 'b')
      expect(encoder.body).to eq("--b--\r\n".b)
    end
  end
end
