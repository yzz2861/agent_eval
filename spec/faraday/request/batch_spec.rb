# frozen_string_literal: true

RSpec.describe Faraday::Request::Batch do
  let(:received_request) { [] }

  def build_connection(response_block)
    Faraday.new do |builder|
      builder.request :batch
      builder.adapter :test do |stub|
        stub.post('/batch', &response_block)
      end
    end
  end

  # Decodes the incoming multipart request, responds with the given results
  # in the given (possibly shuffled) order.
  def batch_response(results, boundary: 'upstream-boundary')
    lambda do |env|
      request = Faraday::Batch::Coder.decode_request(
        env.body, env.request_headers['Content-Type']
      )
      received_request.concat(request)
      encoded = Faraday::Batch::Coder.encode_response(results, boundary: boundary)
      [200, { 'Content-Type' => encoded.content_type }, encoded.body]
    end
  end

  let(:parts) do
    [
      Faraday::Batch::Part.new(method: :get, path: '/users/1', body: nil, content_id: '1'),
      Faraday::Batch::Part.new(
        method: :post, path: '/users', body: 'payload',
        headers: { 'Content-Type' => 'text/plain' }, content_id: '2'
      )
    ]
  end

  it 'sends one multipart/mixed request carrying every part and its Content-ID' do
    conn = build_connection(batch_response([
      Faraday::Batch::PartResult.new('1', 200, {}, 'one'),
      Faraday::Batch::PartResult.new('2', 201, {}, 'two')
    ]))

    conn.post('/batch', parts)

    aggregate_failures do
      expect(received_request.size).to eq(2)
      expect(received_request.map(&:content_id)).to eq(%w[1 2])
      expect(received_request.map(&:method)).to eq(%i[get post])
      expect(received_request.map(&:path)).to eq(['/users/1', '/users'])
      expect(received_request[1].headers['Content-Type']).to eq('text/plain')
      expect(received_request[1].encoded_body).to eq('payload')
    end
  end

  it 'correlates out-of-order responses back to the request order' do
    conn = build_connection(batch_response([
      Faraday::Batch::PartResult.new('2', 201, {}, 'two'),
      Faraday::Batch::PartResult.new('1', 200, {}, 'one')
    ]))

    batch = conn.post('/batch', parts).body

    expect(batch).to be_a(Faraday::Batch::BatchResult)
    expect(batch.content_ids).to eq(%w[1 2])
    expect(batch['1'].body).to eq('one')
    expect(batch['2'].status).to eq(201)
  end

  it 'keeps per-item HTTP status and errors without treating outer 200 as success' do
    conn = build_connection(batch_response([
      Faraday::Batch::PartResult.new('1', 200, {}, 'ok'),
      Faraday::Batch::PartResult.new('2', 422, { 'Content-Type' => 'application/json' }, 'bad')
    ]))

    batch = conn.post('/batch', parts).body

    aggregate_failures do
      expect(batch.outer_status).to eq(200)
      expect(batch.all_succeeded?).to be(false)
      expect(batch['1']).to be_success
      expect(batch['2']).not_to be_success
      expect(batch['2'].status).to eq(422)
      expect(batch['2'].error).to be_a(Faraday::UnprocessableContentError)
      expect(batch.failed.map(&:content_id)).to eq(['2'])
    end
  end

  it 'explicitly presents parts missing from the response' do
    conn = build_connection(batch_response([
      Faraday::Batch::PartResult.new('1', 200, {}, 'ok')
    ]))

    batch = conn.post('/batch', parts).body

    aggregate_failures do
      expect(batch.results.size).to eq(2)
      expect(batch['2'].status).to be_nil
      expect(batch['2'].error).to be_a(Faraday::Batch::MissingPartError)
      expect(batch.missing.map(&:content_id)).to eq(['2'])
    end
  end

  it 'does not raise for a batch of per-item errors and never retries the request' do
    calls = 0
    conn = Faraday.new do |builder|
      builder.request :batch
      builder.adapter :test do |stub|
        stub.post('/batch') do
          calls += 1
          encoded = Faraday::Batch::Coder.encode_response([
            Faraday::Batch::PartResult.new('1', 500, {}, 'err'),
            Faraday::Batch::PartResult.new('2', 503, {}, 'err')
          ])
          [200, { 'Content-Type' => encoded.content_type }, encoded.body]
        end
      end
    end

    batch = conn.post('/batch', parts).body

    expect(calls).to eq(1)
    expect(batch.results.map { |result| result.error.class }).to eq(
      [Faraday::ServerError, Faraday::ServerError]
    )
  end

  it 'rejects duplicate Content-IDs before making the request' do
    duplicated = [
      Faraday::Batch::Part.new(method: :get, path: '/a', content_id: 'dup'),
      Faraday::Batch::Part.new(method: :get, path: '/b', content_id: 'dup')
    ]
    conn = build_connection(batch_response([]))

    expect { conn.post('/batch', duplicated) }
      .to raise_error(Faraday::Batch::DuplicateContentIdError)
    expect(received_request).to be_empty
  end

  it 'turns a non-multipart outer failure into explicit missing results' do
    conn = Faraday.new do |builder|
      builder.request :batch
      builder.adapter :test do |stub|
        stub.post('/batch') { [500, { 'Content-Type' => 'text/plain' }, 'gateway down'] }
      end
    end

    response = conn.post('/batch', parts)
    batch = response.body

    aggregate_failures do
      expect(response.status).to eq(500)
      expect(batch.outer_status).to eq(500)
      expect(batch.outer_body).to eq('gateway down')
      expect(batch.results.map(&:status)).to eq([nil, nil])
      expect(batch.results).to all(be_a(Faraday::Batch::PartResult))
      expect(batch.results.map { |result| result.error.class })
        .to eq([Faraday::Batch::MissingPartError, Faraday::Batch::MissingPartError])
    end
  end

  it 'leaves ordinary non-batch requests untouched' do
    conn = Faraday.new do |builder|
      builder.request :batch
      builder.adapter :test do |stub|
        stub.post('/plain', 'hello') { [200, {}, 'world'] }
      end
    end

    expect(conn.post('/plain', 'hello').body).to eq('world')
  end

  it 'leaves array bodies that are not Parts untouched' do
    conn = Faraday.new do |builder|
      builder.request :json
      builder.request :batch
      builder.adapter :test do |stub|
        stub.post('/items', '[{"id":1}]') { [200, {}, 'ok'] }
      end
    end

    expect(conn.post('/items', [{ id: 1 }]).body).to eq('ok')
  end

  it 'supports binary sub-bodies even when they contain boundary-like bytes' do
    binary_body = "\x00\xff\r\nboundary-like\x80".b
    binary_parts = [
      Faraday::Batch::Part.new(method: :put, path: '/files/1', body: binary_body, content_id: 'bin')
    ]
    conn = build_connection(batch_response([
      Faraday::Batch::PartResult.new('bin', 200, {}, binary_body)
    ]))

    batch = conn.post('/batch', binary_parts).body

    aggregate_failures do
      expect(received_request.first.encoded_body).to eq(binary_body)
      expect(batch['bin'].body).to eq(binary_body)
    end
  end
end
