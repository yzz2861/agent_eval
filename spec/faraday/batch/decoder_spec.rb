# frozen_string_literal: true

RSpec.describe Faraday::Batch::Decoder do
  def part(id:, status:, reason: 'OK', headers: {}, body: '')
    lines = ["HTTP/1.1 #{status} #{reason}"]
    headers.each { |name, value| lines << "#{name}: #{value}" }
    envelope = [
      'Content-Type: application/http',
      "Content-ID: #{id}"
    ].join("\r\n")
    "#{envelope}\r\n\r\n#{lines.join("\r\n")}\r\n\r\n#{body}"
  end

  def multipart(parts, boundary: 'batch-boundary', content_type: nil)
    body = parts.map { |chunk| "--#{boundary}\r\n#{chunk}\r\n" }.join
    body = "#{body}--#{boundary}--\r\n".dup.force_encoding(Encoding::BINARY)
    type = content_type || %(multipart/mixed; boundary="#{boundary}")
    [{ 'Content-Type' => type }, body]
  end

  let(:ids) { %w[one two missing] }

  context 'out of order sub-responses' do
    subject(:decoded) do
      headers, body = multipart([
        part(id: '<two>', status: 201, body: 'created'),
        part(id: 'one', status: 200, headers: { 'X-Foo' => 'bar' }, body: 'ok')
      ])
      described_class.decode(ids, 200, headers, body)
    end

    it 'orders results by the requested ids, not wire order' do
      expect(decoded.map(&:id)).to eq(%w[one two missing])
      expect(decoded.results.map(&:status)).to eq([200, 201, nil])
    end

    it 'normalizes angle-bracketed Content-IDs' do
      expect(decoded['two'].status).to eq(201)
      expect(decoded['two'].body).to eq('created')
    end

    it 'looks items up by index' do
      expect(decoded[0].id).to eq('one')
      expect(decoded[0].headers['X-Foo']).to eq('bar')
    end

    it 'represents the missing item explicitly' do
      missing = decoded['missing']
      expect(missing).to be_missing
      expect(missing.error).to be_a(Faraday::Batch::MissingResponseError)
      expect(decoded.missing.map(&:id)).to eq(['missing'])
    end

    it 'is not successful because an item is missing' do
      expect(decoded).not_to be_success
    end
  end

  context 'per-item HTTP errors' do
    subject(:decoded) do
      headers, body = multipart([
        part(id: 'one', status: 200, body: 'ok'),
        part(id: 'two', status: 404, reason: 'Not Found', body: 'nope'),
        part(id: 'missing', status: 500, reason: 'Boom')
      ])
      described_class.decode(ids, 200, headers, body)
    end

    it 'preserves each inner status despite the outer 200' do
      expect(decoded.outer_status).to eq(200)
      expect(decoded['one']).to be_success
      expect(decoded['two']).to be_error
      expect(decoded['two'].status).to eq(404)
      expect(decoded['two'].body).to eq('nope')
      expect(decoded.failed.map(&:id)).to contain_exactly('two', 'missing')
    end

    it 'does not treat an outer 200 as overall success' do
      expect(decoded).not_to be_success
    end
  end

  context 'unexpected and duplicate Content-IDs' do
    subject(:decoded) do
      headers, body = multipart([
        part(id: 'two', status: 200),
        part(id: 'one', status: 200, body: 'first'),
        part(id: 'one', status: 200, body: 'duplicate'),
        part(id: 'stranger', status: 200)
      ])
      described_class.decode(ids, 200, headers, body)
    end

    it 'keeps the first matching result and reports extras separately' do
      expect(decoded['one'].body).to eq('first')
      expect(decoded.unexpected.map(&:id)).to contain_exactly('one', 'stranger')
      expect(decoded.unexpected.find { |item| item.id == 'one' }.error)
        .to be_a(Faraday::Batch::ParseError)
    end
  end

  context 'malformed sub-responses' do
    it 'attaches a parse error to the item without an HTTP status line' do
      malformed = [
        'Content-Type: application/http',
        'Content-ID: one',
        '',
        'not an http response'
      ].join("\r\n")
      headers, body = multipart([malformed])
      decoded = described_class.decode(%w[one], 200, headers, body)

      expect(decoded['one'].status).to be_nil
      expect(decoded['one'].error).to be_a(Faraday::Batch::ParseError)
    end

    it 'collects parts without Content-ID as unexpected' do
      anonymous = [
        'Content-Type: application/http',
        '',
        'HTTP/1.1 200 OK',
        '',
        'orphan'
      ].join("\r\n")
      headers, body = multipart([anonymous])
      decoded = described_class.decode(%w[one], 200, headers, body)

      expect(decoded['one']).to be_missing
      expect(decoded.unexpected.size).to eq(1)
    end

    it 'recovers when a part has no header/body separator at all' do
      headers, body = multipart(['totally not a mime part'])
      decoded = described_class.decode(%w[one], 200, headers, body)

      expect(decoded['one']).to be_missing
      expect(decoded.unexpected.first.error).to be_a(Faraday::Batch::ParseError)
    end

    it 'handles a truncated status line without headers' do
      raw = "Content-Type: application/http\r\nContent-ID: one\r\n\r\nHTTP/1.1 200 OK"
      headers, body = multipart([raw])
      decoded = described_class.decode(%w[one], 200, headers, body)

      expect(decoded['one'].status).to eq(200)
      expect(decoded['one'].body).to eq('')
    end
  end

  context 'non-multipart outer responses' do
    it 'fails every item but keeps the outer status for an outer 500' do
      decoded = described_class.decode(ids, 500, { 'Content-Type' => 'text/plain' }, 'gateway error')

      expect(decoded.outer_status).to eq(500)
      expect(decoded.map(&:id)).to eq(ids)
      expect(decoded).to all(be_missing)
      expect(decoded.results.map(&:error)).to all(be_a(Faraday::Batch::ParseError))
    end

    it 'handles a missing boundary parameter gracefully' do
      decoded = described_class.decode(ids, 200, { 'Content-Type' => 'multipart/mixed' }, '')

      expect(decoded).not_to be_success
      expect(decoded.results.first.error).to be_a(Faraday::Batch::ParseError)
    end

    it 'does not treat an outer 200 non-multipart body as success' do
      decoded = described_class.decode(ids, 200, { 'Content-Type' => 'application/json' }, '{}')

      expect(decoded.outer_status).to eq(200)
      expect(decoded).not_to be_success
      expect(decoded.results.map(&:error)).to all(be_a(Faraday::Batch::ParseError))
    end

    it 'recovers when the declared boundary is absent from a non-empty body' do
      decoded = described_class.decode(ids, 200,
                                       { 'Content-Type' => 'multipart/mixed; boundary="ghost"' },
                                       'unrelated body')

      expect(decoded.results.map(&:error)).to all(be_a(Faraday::Batch::ParseError))
    end
  end

  context 'binary-safe boundary scanning' do
    it 'does not split on boundary bytes appearing inside a part body' do
      decoy = "prefix--batch-boundary-midline--batch-boundary--suffix".b
      raw = part(id: 'one', status: 200, body: decoy)
      headers, body = multipart([raw])
      decoded = described_class.decode(%w[one], 200, headers, body)

      expect(decoded['one'].status).to eq(200)
      expect(decoded['one'].body).to eq(decoy)
    end

    it 'accepts an unquoted boundary parameter' do
      raw = part(id: 'one', status: 204, reason: 'No Content', body: '')
      headers, body = multipart([raw], content_type: 'multipart/mixed; boundary=batch-boundary')
      decoded = described_class.decode(ids, 200, headers, body)

      expect(decoded['one'].status).to eq(204)
    end
  end
end
