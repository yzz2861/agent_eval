# frozen_string_literal: true

RSpec.describe Faraday::Batch::Coder do
  describe '.encode_request' do
    let(:parts) do
      [
        Faraday::Batch::Part.new(method: :get, path: '/users/1', content_id: '1'),
        Faraday::Batch::Part.new(
          method: 'POST', path: '/users', body: '{"name":"Ada"}',
          headers: { 'Content-Type' => 'application/json' }, content_id: '2'
        )
      ]
    end

    it 'encodes parts as multipart/mixed with a boundary' do
      encoded = described_class.encode_request(parts, boundary: 'batch-boundary')

      expect(encoded.content_type).to eq(
        'multipart/mixed; boundary="batch-boundary"'
      )
      expect(encoded.content_ids).to eq(%w[1 2])
      expect(encoded.body).to start_with("--batch-boundary#{"\r\n"}")
      expect(encoded.body).to end_with("\r\n--batch-boundary--\r\n")
    end

    it 'wraps each sub-request as application/http with method, target and Content-ID' do
      encoded = described_class.encode_request(parts, boundary: 'batch-boundary')
      decoded = described_class.decode_request(encoded.body, encoded.content_type)

      aggregate_failures do
        expect(decoded.size).to eq(2)
        expect(decoded[0].method).to eq(:get)
        expect(decoded[0].path).to eq('/users/1')
        expect(decoded[0].content_id).to eq('1')
        expect(decoded[0].encoded_body).to be_nil

        expect(decoded[1].method).to eq(:post)
        expect(decoded[1].path).to eq('/users')
        expect(decoded[1].content_id).to eq('2')
        expect(decoded[1].encoded_body).to eq('{"name":"Ada"}')
        expect(decoded[1].headers['Content-Type']).to eq('application/json')
      end
    end

    it 'preserves relative targets untouched' do
      part = Faraday::Batch::Part.new(method: :get, path: 'relative?x=1', content_id: 'x')
      encoded = described_class.encode_request([part], boundary: 'b')
      decoded = described_class.decode_request(encoded.body, encoded.content_type)

      expect(decoded.first.path).to eq('relative?x=1')
    end

    it 'accepts parts built from keyword hashes' do
      encoded = described_class.encode_request(
        [{ method: :get, path: '/x', content_id: 'h' }], boundary: 'b'
      )
      decoded = described_class.decode_request(encoded.body, encoded.content_type)

      expect(decoded.first.path).to eq('/x')
    end

    it 'generates unique Content-IDs when none are provided' do
      generated = [
        Faraday::Batch::Part.new(method: :get, path: '/a'),
        Faraday::Batch::Part.new(method: :get, path: '/b')
      ]
      encoded = described_class.encode_request(generated, boundary: 'b')

      expect(encoded.content_ids.uniq).to eq(encoded.content_ids)
      expect(encoded.content_ids).to all(be_a(String).and(have_attributes(length: 16)))
    end

    it 'reads IO-like bodies once' do
      io = StringIO.new('streamed-body')
      part = Faraday::Batch::Part.new(method: :put, path: '/io', body: io, content_id: 'io')
      encoded = described_class.encode_request([part], boundary: 'b')
      decoded = described_class.decode_request(encoded.body, encoded.content_type)

      expect(decoded.first.encoded_body).to eq('streamed-body')
    end

    it 'rejects duplicate Content-IDs before sending' do
      duplicated = [
        Faraday::Batch::Part.new(method: :get, path: '/a', content_id: 'dup'),
        Faraday::Batch::Part.new(method: :get, path: '/b', content_id: 'dup')
      ]

      expect { described_class.encode_request(duplicated, boundary: 'b') }
        .to raise_error(Faraday::Batch::DuplicateContentIdError, /dup/)
    end

    it 'rejects a part without a method' do
      part = Faraday::Batch::Part.new(path: '/a', content_id: '1')

      expect { described_class.encode_request([part], boundary: 'b') }
        .to raise_error(Faraday::Batch::InvalidPartError, /method/)
    end

    it 'rejects a part without a target' do
      part = Faraday::Batch::Part.new(method: :get, content_id: '1')

      expect { described_class.encode_request([part], boundary: 'b') }
        .to raise_error(Faraday::Batch::InvalidPartError, /target/)
    end

    it 'rejects an invalid explicit boundary' do
      expect { described_class.encode_request(parts, boundary: 'bad boundary') }
        .to raise_error(Faraday::Batch::BoundaryCollisionError, /invalid multipart boundary/)
    end

    it 'rejects an empty batch' do
      expect { described_class.encode_request([], boundary: 'b') }
        .to raise_error(Faraday::Batch::InvalidPartError, /empty batch/)
    end
  end

  describe 'binary-safe boundaries' do
    it 'round-trips a binary body that embeds delimiter-like bytes' do
      # The bytes contain the delimiter but not on a complete delimiter line
      # (the suffix is not CRLF), so they are safe.
      body = "\x00\xff\r\n--b1X\r\nfake-delimiter\x80".b
      part = Faraday::Batch::Part.new(method: :put, path: '/binary', body: body, content_id: 'x')
      encoded = described_class.encode_request([part], boundary: 'b1')
      decoded = described_class.decode_request(encoded.body, encoded.content_type)

      expect(decoded.first.encoded_body).to eq(body)
      expect(decoded.first.encoded_body.encoding).to eq(Encoding::BINARY)
    end

    it 'round-trips binary bodies containing a delimiter prefix using a generated boundary' do
      # This body contains a *complete* delimiter line, so an explicit matching
      # boundary is ambiguous for any multipart parser. The encoder must pick a
      # non-colliding boundary automatically.
      body = "\r\n--faraday-batch-collision\r\n".b
      part = Faraday::Batch::Part.new(method: :put, path: '/binary', body: body, content_id: 'y')
      encoded = described_class.encode_request([part])
      decoded = described_class.decode_request(encoded.body, encoded.content_type)

      expect(decoded.first.encoded_body).to eq(body)
    end

    it 'raises when an explicit boundary collides with a sub-body' do
      body = "\r\n--b3\r\n".b
      part = Faraday::Batch::Part.new(method: :put, path: '/binary', body: body, content_id: 'z')

      expect { described_class.encode_request([part], boundary: 'b3') }
        .to raise_error(Faraday::Batch::BoundaryCollisionError, /collides/)
    end

    it 'generates a valid boundary by default' do
      encoded = described_class.encode_request(
        [Faraday::Batch::Part.new(method: :get, path: '/a', content_id: '1')]
      )

      expect(encoded.boundary).to match(Faraday::Batch::BOUNDARY_VALUE)
      expect(encoded.boundary.length).to be <= 70
    end

    it 'tolerates an RFC 2046 preamble and epilogue when decoding' do
      encoded = described_class.encode_request(
        [Faraday::Batch::Part.new(method: :get, path: '/a', content_id: '1')], boundary: 'b'
      )
      wire = "ignore this preamble\r\n" + encoded.body + "and this epilogue"

      expect(described_class.decode_request(wire, encoded.content_type).size).to eq(1)
    end
  end

  describe '.decode_response' do
    let(:ids) { %w[1 2 3] }

    def encode_results(results, boundary: 'response-boundary')
      described_class.encode_response(results, boundary: boundary)
    end

    it 'correlates out-of-order parts back to request order' do
      encoded = encode_results([
        Faraday::Batch::PartResult.new('3', 200, {}, 'third'),
        Faraday::Batch::PartResult.new('1', 200, { 'X-Id' => 'one' }, 'first'),
        Faraday::Batch::PartResult.new('2', 200, {}, 'second')
      ])
      batch = described_class.decode_response(encoded.body, encoded.content_type, ids)

      expect(batch.content_ids).to eq(ids)
      expect(batch.map { |result| [result.content_id, result.body] }).to eq([
        ['1', 'first'], ['2', 'second'], ['3', 'third']
      ])
      expect(batch['1'].headers['X-Id']).to eq('one')
      expect(batch.fetch('2').body).to eq('second')
    end

    it 'keeps per-item HTTP status and errors instead of treating 200 as success' do
      encoded = encode_results([
        Faraday::Batch::PartResult.new('1', 200, {}, 'ok'),
        Faraday::Batch::PartResult.new('2', 404, {}, 'missing'),
        Faraday::Batch::PartResult.new('3', 500, {}, 'boom')
      ])
      batch = described_class.decode_response(
        encoded.body, encoded.content_type, ids, outer_status: 200
      )

      aggregate_failures do
        expect(batch.outer_status).to eq(200)
        expect(batch.all_succeeded?).to be(false)
        expect(batch['1']).to be_success
        expect(batch['2']).not_to be_success
        expect(batch['2'].error).to be_a(Faraday::ResourceNotFound)
        expect(batch['3'].error).to be_a(Faraday::ServerError)
        expect(batch.failed.map(&:content_id)).to eq(%w[2 3])
      end
    end

    it 'does not attach an error to a 3xx redirect part' do
      encoded = encode_results([
        Faraday::Batch::PartResult.new('1', 301, { 'Location' => '/elsewhere' }, '')
      ])
      batch = described_class.decode_response(encoded.body, encoded.content_type, ['1'])

      expect(batch['1'].status).to eq(301)
      expect(batch['1'].error).to be_nil
      expect(batch['1']).not_to be_success
    end

    it 'explicitly presents requested IDs missing from the response' do
      encoded = encode_results([
        Faraday::Batch::PartResult.new('1', 200, {}, 'ok')
      ])
      batch = described_class.decode_response(
        encoded.body, encoded.content_type, ids, outer_status: 200
      )

      aggregate_failures do
        expect(batch.results.size).to eq(3)
        expect(batch['2'].status).to be_nil
        expect(batch['2'].error).to be_a(Faraday::Batch::MissingPartError)
        expect(batch['3'].error).to be_a(Faraday::Batch::MissingPartError)
        expect(batch.missing.map(&:content_id)).to eq(%w[2 3])
        expect(batch.all_succeeded?).to be(false)
      end
    end

    it 'rejects duplicate Content-IDs in the response' do
      encoded = encode_results([
        Faraday::Batch::PartResult.new('1', 200, {}, 'a'),
        Faraday::Batch::PartResult.new('1', 200, {}, 'b')
      ])

      expect do
        described_class.decode_response(encoded.body, encoded.content_type, ['1'])
      end.to raise_error(Faraday::Batch::DuplicateContentIdError)
    end

    it 'rejects a response part without a Content-ID' do
      body = "--b\r\nContent-Type: application/http\r\n\r\n" \
             "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n\r\n--b--\r\n"

      expect do
        described_class.decode_response(body, 'multipart/mixed; boundary="b"', ['1'])
      end.to raise_error(Faraday::Batch::MalformedBatchError, /Content-ID/)
    end

    it 'round-trips a binary sub-response body containing the boundary' do
      # Delimiter-like bytes without a complete delimiter line.
      body = "\x00\r\n--response-boundary\xff".b
      encoded = encode_results([
        Faraday::Batch::PartResult.new('1', 200, {}, body)
      ])
      batch = described_class.decode_response(encoded.body, encoded.content_type, ['1'])

      expect(batch['1'].body).to eq(body)
    end

    it 'raises when the content type is not multipart/mixed' do
      expect do
        described_class.decode_response('x', 'application/json', ['1'])
      end.to raise_error(Faraday::Batch::MalformedBatchError, /boundary/)
    end
  end

  describe '.missing_batch' do
    it 'builds explicit missing results for every requested ID' do
      batch = described_class.missing_batch(
        %w[1 2], outer_status: 500,
        outer_headers: { 'Content-Type' => 'text/plain' },
        outer_body: 'outage'
      )

      aggregate_failures do
        expect(batch.outer_status).to eq(500)
        expect(batch.outer_body).to eq('outage')
        expect(batch.results.map(&:status)).to eq([nil, nil])
        expect(batch.results.map { |result| result.error.class })
          .to eq([Faraday::Batch::MissingPartError, Faraday::Batch::MissingPartError])
      end
    end
  end

  describe '.multipart?' do
    it 'matches multipart/mixed regardless of parameters or case' do
      expect(described_class.multipart?('multipart/mixed; boundary="x"')).to be(true)
      expect(described_class.multipart?('MULTIPART/MIXED')).to be(true)
      expect(described_class.multipart?('application/json')).to be(false)
      expect(described_class.multipart?(nil)).to be(false)
    end
  end
end
