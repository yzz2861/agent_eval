# frozen_string_literal: true

RSpec.describe Faraday::Request::Batch do
  def response_part(id, status, body = '', headers: {})
    lines = ["HTTP/1.1 #{status} "] + headers.map { |name, value| "#{name}: #{value}" }
    envelope = "Content-Type: application/http\r\nContent-ID: #{id}"
    "#{envelope}\r\n\r\n#{lines.join("\r\n")}\r\n\r\n#{body}"
  end

  def build_multipart(part_chunks, boundary)
    body = part_chunks.map { |chunk| "--#{boundary}\r\n#{chunk}\r\n" }.join
    "#{body}--#{boundary}--\r\n".b
  end

  let(:calls) { [] }
  let(:stubs) do
    Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/batch') do |env|
        calls << {
          content_type: env.request_headers['Content-Type'],
          body: env.body
        }
        [200, { 'Content-Type' => 'multipart/mixed; boundary="resp"' },
         build_multipart([
           response_part('two', 500, 'boom'),
           response_part('one', 200, 'hi')
         ], 'resp')]
      end
    end
  end

  let(:connection) do
    Faraday.new do |builder|
      builder.use described_class
      builder.adapter :test, stubs
    end
  end

  let(:batch) do
    Faraday::Batch::Request.new.tap do |request|
      request.request(:get, '/a', nil, {}, id: 'one')
      request.request(:post, '/b', 'payload', { 'Content-Type' => 'text/plain' }, id: 'two')
    end
  end

  describe 'request encoding' do
    before { connection.post('/batch', batch) }

    it 'sends a single multipart/mixed outer request' do
      expect(calls.size).to eq(1)
      expect(calls.first[:content_type]).to start_with('multipart/mixed; boundary=')
    end

    it 'embeds method, relative target, headers, body and Content-ID per part' do
      body = calls.first[:body]
      expect(body).to include('Content-ID: one')
      expect(body).to include("GET /a HTTP/1.1")
      expect(body).to include('Content-ID: two')
      expect(body).to include("POST /b HTTP/1.1")
      expect(body).to include('Content-Type: text/plain')
      expect(body).to include('payload')
    end

    it 'uses a safe generated boundary' do
      boundary = calls.first[:content_type][/boundary="(.+)"/, 1]
      expect(boundary).to start_with('FaradayBatchBoundary')
      expect(calls.first[:body].scan(boundary).size).to eq(3)
    end
  end

  describe 'response decoding' do
    subject(:result) { connection.post('/batch', batch).body }

    it 'returns a batch response ordered by request Content-ID' do
      expect(result).to be_a(Faraday::Batch::Response)
      expect(result.map(&:id)).to eq(%w[one two])
      expect(result['one'].status).to eq(200)
      expect(result['two'].status).to eq(500)
    end

    it 'keeps per-item failures despite the outer 200' do
      expect(result.outer_status).to eq(200)
      expect(result).not_to be_success
      expect(result.failed.map(&:id)).to eq(['two'])
    end

    it 'does not resend the batch' do
      result
      expect(calls.size).to eq(1)
    end
  end

  describe 'binary sub-bodies' do
    it 'round-trips a part whose body contains bytes resembling a boundary' do
      binary = (0..255).map(&:chr).join.b
      binary_batch = Faraday::Batch::Request.new
      binary_batch.request(:put, '/blob', binary,
                           { 'Content-Type' => 'application/octet-stream' }, id: 'blob')

      sent = nil
      binary_stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/batch') do |env|
          sent = env.body
          boundary = env.request_headers['Content-Type'][/boundary="(.+)"/, 1]
          [200,
           { 'Content-Type' => "multipart/mixed; boundary=#{boundary}" },
           build_multipart([response_part('blob', 200, 'stored')], boundary)]
        end
      end
      binary_connection = Faraday.new do |builder|
        builder.use described_class
        builder.adapter :test, binary_stubs
      end

      result = binary_connection.post('/batch', binary_batch).body
      expect(sent).to include(binary)
      expect(result['blob'].status).to eq(200)
      expect(result['blob'].body).to eq('stored')
    end
  end

  describe 'missing sub-responses' do
    it 'represents every requested id explicitly', :aggregate_failures do
      partial_stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/batch') do
          [200, { 'Content-Type' => 'multipart/mixed; boundary="resp"' },
           build_multipart([response_part('one', 200)], 'resp')]
        end
      end
      partial_connection = Faraday.new do |builder|
        builder.use described_class
        builder.adapter :test, partial_stubs
      end

      partial = partial_connection.post('/batch', batch).body
      expect(partial.size).to eq(2)
      expect(partial['one']).to be_success
      expect(partial['two']).to be_missing
      expect(partial['two'].error).to be_a(Faraday::Batch::MissingResponseError)
    end
  end

  describe 'non-batch requests' do
    it 'passes ordinary bodies through untouched' do
      stubs.post('/plain', 'text') { [200, { 'Content-Type' => 'text/plain' }, 'ok'] }

      response = connection.post('/plain', 'text')
      expect(response.body).to eq('ok')
      expect(calls).to be_empty
    end
  end

  describe 'duplicate ids' do
    it 'rejects the batch before sending' do
      expect do
        Faraday::Batch::Request.new.tap do |bad|
          bad.request(:get, '/a', nil, {}, id: 'dup')
          bad.request(:get, '/b', nil, {}, id: 'dup')
        end
      end.to raise_error(Faraday::Batch::DuplicateIdError)
    end
  end
end
