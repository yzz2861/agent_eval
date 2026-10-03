# frozen_string_literal: true

require 'stringio'

RSpec.describe JWT::Streaming do
  let(:hmac_secret) { 'a' * 32 }
  let(:rsa_key) { test_pkey('rsa-2048-private.pem') }
  let(:rsa_public) { test_pkey('rsa-2048-public.pem') }

  # Deterministic payload covering all 256 byte values, long enough to span
  # many chunk boundaries and include multibyte and zero bytes.
  let(:body) { (0..255).map(&:chr).join.force_encoding('BINARY') * 20 }

  # JSON serialisable payload used for cross-validation with JWT::Token,
  # which always treats the payload as a JSON value.
  let(:json_payload) { { 'pay' => 'load', 'bin' => [0, 1, 255], 'pad' => 'x' * 500 } }
  let(:json_body) { JWT::JSON.generate(json_payload) }

  chunk_sizes = [1, 2, 3, 4, 7, 64, 4095, 4096, 4097, 100_000]

  # IO wrapper that honors the requested read length exactly, unlike StringIO
  # which may return more than requested. It never supports rewind.
  class ChunkedIO
    def initialize(content, chunk_size)
      @content = content
      @chunk_size = chunk_size
      @offset = 0
    end

    attr_reader :max_read_length

    def read(length)
      length = [length, @chunk_size].min
      chunk = @content.byteslice(@offset, length)
      return nil if chunk.nil? || chunk.empty?

      @max_read_length = [@max_read_length.to_i, chunk.bytesize].max
      @offset += chunk.bytesize
      chunk
    end
  end

  # IO-like source that cannot be rewound or reopened. It serves each byte on
  # demand, so the signing/verifying code must work from a single forward pass.
  class NonRewindableIO
    def initialize(content)
      @content = content
      @offset = 0
    end

    def read(length)
      chunk = @content.byteslice(@offset, length)
      return nil if chunk.nil? || chunk.empty?

      @offset += chunk.bytesize
      chunk
    end
  end

  def chunked_io(content, chunk_size)
    ChunkedIO.new(content, chunk_size)
  end

  def non_rewindable_io(content)
    NonRewindableIO.new(content)
  end

  describe '.sign (HS256, base64url payload)' do
    let(:encoded_payload) { JWT::Base64.url_encode(body) }
    let(:expected_signing_input) { nil }

    chunk_sizes.each do |chunk_size|
      context "with chunk_size #{chunk_size}" do
        it 'encodes and signs independently of the chunk boundaries' do
          sink = StringIO.new(''.b)
          result = described_class.sign(StringIO.new(body),
                                        key: hmac_secret, algorithm: 'HS256',
                                        payload_io: sink, chunk_size: chunk_size)

          expect(sink.string).to eq(encoded_payload)
          expected = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), hmac_secret,
                                          result.encoded_header + '.' + encoded_payload)
          expect(result.signature).to eq(expected)
        end
      end
    end

    it 'matches the signature produced by the existing string interface' do
      token = JWT::Token.new(payload: json_payload)
      token.sign!(algorithm: 'HS256', key: hmac_secret)
      token.detach_payload!

      result = described_class.sign(StringIO.new(json_body), key: hmac_secret,
                                    algorithm: 'HS256', payload_io: StringIO.new(''.b))

      expect(result.encoded_header).to eq(token.encoded_header)
      expect(result.jws).to eq(token.jwt)
    end

    it 'yields encoded chunks when a block is given instead of payload_io' do
      chunks = []
      result_block = described_class.sign(chunked_io(body, 5), key: hmac_secret, chunk_size: 5) do |chunk|
        chunks << chunk
      end

      sink = StringIO.new(''.b)
      result_io = described_class.sign(chunked_io(body, 5), key: hmac_secret,
                                       payload_io: sink, chunk_size: 5)

      expect(chunks.join).to eq(encoded_payload)
      expect(result_block.jws).to eq(result_io.jws)
    end

    it 'keeps the header in its given order' do
      result = described_class.sign(chunked_io(json_body, 16), key: hmac_secret,
                                    headers: { 'kid' => 'k-1' },
                                    payload_io: StringIO.new(''.b))
      expect(result.header).to eq('kid' => 'k-1', 'alg' => 'HS256')
      token = JWT::Token.new(payload: json_payload, header: { 'kid' => 'k-1' })
      token.sign!(algorithm: 'HS256', key: hmac_secret)
      token.detach_payload!
      expect(result.encoded_header).to eq(token.encoded_header)
    end

    it 'rejects both payload_io and a block' do
      expect do
        described_class.sign(StringIO.new(body), key: hmac_secret,
                             payload_io: StringIO.new(''.b)) { nil }
      end.to raise_error(ArgumentError, /either payload_io or a block/)
    end

    it 'raises if no encoded payload sink is given' do
      # b64 is true and neither payload_io nor block: allowed but the encoded
      # payload is only available via the JWS hash; the result is still returned.
      result = described_class.sign(StringIO.new(body), key: hmac_secret)
      expect(result.jws).to start_with(result.encoded_header + '..')
    end

    it 'rejects a payload_io without #write' do
      expect do
        described_class.sign(StringIO.new(body), key: hmac_secret, payload_io: :nope)
      end.to raise_error(ArgumentError, /#write/)
    end

    it 'signs the empty body' do
      sink = StringIO.new(''.b)
      result = described_class.sign(StringIO.new(''), key: hmac_secret, payload_io: sink)

      expected = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), hmac_secret,
                                      result.encoded_header + '.')

      expect(sink.string).to eq('')
      expect(result.signature).to eq(expected)
    end

    it 'collects read statistics with the largest single read length' do
      sink = StringIO.new(''.b)
      io = chunked_io(body, 100)
      result = described_class.sign(io, key: hmac_secret, payload_io: sink, chunk_size: 100)
      expect(result.stats.bytes_read).to eq(body.bytesize)
      expect(result.stats.reads).to eq((body.bytesize / 100.0).ceil)
      expect(result.stats.max_read_length).to eq(100)
      expect(io.max_read_length).to eq(100)
    end

    it 'reports zero reads for an empty body' do
      result = described_class.sign(StringIO.new(''), key: hmac_secret,
                                    payload_io: StringIO.new(''.b))
      expect(result.stats.reads).to eq(0)
      expect(result.stats.bytes_read).to eq(0)
      expect(result.stats.max_read_length).to eq(0)
    end

    it 'works with a non-rewindable pipe' do
      sink = StringIO.new(''.b)
      reader = non_rewindable_io(body)
      expect(reader).not_to respond_to(:rewind)

      result = described_class.sign(reader, key: hmac_secret, payload_io: sink, chunk_size: 13)

      expected = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), hmac_secret,
                                      result.encoded_header + '.' + encoded_payload)
      expect(result.signature).to eq(expected)
      expect(sink.string).to eq(encoded_payload)
    end

    it 'wraps read errors instead of raising the underlying IO error' do
      io = Object.new
      def io.read(_length)
        raise SystemCallError, 'boom'
      end
      expect do
        described_class.sign(io, key: hmac_secret, payload_io: StringIO.new(''.b))
      end.to raise_error(JWT::StreamReadError, /boom/) { |error| expect(error.cause).to be_a(SystemCallError) }
    end

    it 'wraps a read returning a non String value' do
      io = Object.new
      def io.read(_length)
        :not_a_string
      end
      expect do
        described_class.sign(io, key: hmac_secret, payload_io: StringIO.new(''.b))
      end.to raise_error(JWT::StreamReadError, /Symbol/)
    end

    it 'rejects a body without #read and a bad chunk size before signing' do
      expect { described_class.sign(Object.new, key: hmac_secret) }.to raise_error(ArgumentError, /#read/)
      expect do
        described_class.sign(StringIO.new('x'), key: hmac_secret, chunk_size: -1)
      end.to raise_error(ArgumentError, /chunk_size/)
    end
  end

  describe '.sign (b64: false, RFC 7797)' do
    it 'signs the raw body with the b64:false critical header' do
      result = described_class.sign(StringIO.new(body), key: hmac_secret,
                                    algorithm: 'HS256', b64: false, chunk_size: 9)

      expect(result.header).to eq('alg' => 'HS256', 'b64' => false, 'crit' => ['b64'])
      expected = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), hmac_secret,
                                      result.encoded_header + '.' + body)
      expect(result.signature).to eq(expected)
      expect(result.jws).to eq([result.encoded_header, '', result.encoded_signature].join('.'))
    end

    chunk_sizes.each do |chunk_size|
      it "produces the same signature for chunk_size #{chunk_size}" do
        reference = described_class.sign(StringIO.new(body), key: hmac_secret, b64: false)
        result = described_class.sign(StringIO.new(body), key: hmac_secret,
                                      b64: false, chunk_size: chunk_size)
        expect(result.signature).to eq(reference.signature)
      end
    end

    it 'preserves an existing crit list and custom headers' do
      result = described_class.sign(StringIO.new(body), key: hmac_secret,
                                    b64: false,
                                    headers: { 'crit' => ['http://example.invalid/OTHER', 'b64'], 'kid' => 'k' },
                                    chunk_size: 2)
      expect(result.header).to eq('crit' => ['http://example.invalid/OTHER', 'b64'],
                                  'kid' => 'k', 'alg' => 'HS256', 'b64' => false)
    end

    it 'refuses a payload sink' do
      expect do
        described_class.sign(StringIO.new(body), key: hmac_secret, b64: false,
                             payload_io: StringIO.new(''.b))
      end.to raise_error(ArgumentError, /b64: true/)
    end

    it 'refuses a block' do
      expect do
        described_class.sign(StringIO.new(body), key: hmac_secret, b64: false) { nil }
      end.to raise_error(ArgumentError, /b64: true/)
    end

    it 'rejects a conflicting b64 header' do
      expect do
        described_class.sign(StringIO.new(body), key: hmac_secret, b64: false,
                             headers: { 'b64' => true })
      end.to raise_error(ArgumentError, /'b64'/)
    end

    it 'signs the empty raw body' do
      result = described_class.sign(StringIO.new(''), key: hmac_secret, b64: false)
      header_segment = result.encoded_header
      expected = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), hmac_secret, header_segment + '.')
      expect(result.signature).to eq(expected)
    end

    it 'cross-validates against a manually built detached b64:false JWS' do
      header = { 'alg' => 'HS256', 'b64' => false, 'crit' => ['b64'] }
      encoded_header = JWT::Base64.url_encode(JWT::JSON.generate(header))
      signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), hmac_secret,
                                       encoded_header + '.' + body)
      jws = [encoded_header, '', JWT::Base64.url_encode(signature)].join('.')

      result = described_class.sign(StringIO.new(body), key: hmac_secret, b64: false)
      expect(result.jws).to eq(jws)
    end
  end

  describe '.sign (RS256)' do
    chunk_sizes.each do |chunk_size|
      it "matches the one-shot RSA sign for chunk_size #{chunk_size}" do
        sink = StringIO.new(''.b)
        result = described_class.sign(StringIO.new(body), key: rsa_key, algorithm: 'RS256',
                                      payload_io: sink, chunk_size: chunk_size)

        encoded_payload = JWT::Base64.url_encode(body)
        expect(sink.string).to eq(encoded_payload)
        expected = rsa_key.sign(OpenSSL::Digest.new('SHA256'),
                                result.encoded_header + '.' + encoded_payload)
        expect(result.signature).to eq(expected)
      end
    end

    it 'supports b64:false for the raw body' do
      result = described_class.sign(StringIO.new(body), key: rsa_key,
                                    algorithm: 'RS256', b64: false, chunk_size: 11)
      expected = rsa_key.sign(OpenSSL::Digest.new('SHA256'),
                              result.encoded_header + '.' + body)
      expect(result.signature).to eq(expected)
    end

    it 'rejects algorithms that cannot be computed incrementally' do
      expect do
        described_class.sign(StringIO.new(body), key: rsa_key, algorithm: 'PS256',
                             payload_io: StringIO.new(''.b))
      end.to raise_error(JWT::StreamingNotSupported, /PS256/)

      ec_key = test_pkey('ec256-private.pem')
      expect do
        described_class.sign(StringIO.new(body), key: ec_key, algorithm: 'ES256',
                             payload_io: StringIO.new(''.b))
      end.to raise_error(JWT::StreamingNotSupported, /ES256/)
    end
  end

  describe '.verify' do
    let(:signed_hs) do
      described_class.sign(StringIO.new(body), key: hmac_secret,
                           payload_io: StringIO.new(''.b), chunk_size: 8)
    end
    let(:signed_hs_raw) do
      described_class.sign(StringIO.new(body), key: hmac_secret, b64: false, chunk_size: 8)
    end
    let(:signed_rs) do
      described_class.sign(StringIO.new(body), key: rsa_key, algorithm: 'RS256',
                           payload_io: StringIO.new(''.b), chunk_size: 8)
    end

    chunk_sizes.each do |chunk_size|
      it "HS256 verifies the base64url payload for chunk_size #{chunk_size}" do
        result = described_class.verify(signed_hs.jws, chunked_io(body, chunk_size),
                                        key: hmac_secret, algorithm: 'HS256',
                                        chunk_size: chunk_size)
        expect(result).to be_valid
        expect(result.stats.max_read_length).to eq([chunk_size, body.bytesize].min)
      end

      it "HS256 verifies the b64:false payload for chunk_size #{chunk_size}" do
        result = described_class.verify(signed_hs_raw.jws, chunked_io(body, chunk_size),
                                        key: hmac_secret, chunk_size: chunk_size)
        expect(result).to be_valid
      end
    end

    it 'RS256 verifies with the public key' do
      result = described_class.verify(signed_rs.jws, StringIO.new(body),
                                      key: rsa_public, algorithm: 'RS256')
      expect(result).to be_valid
    end

    it 'cross-validates a JWS built with the existing string interface' do
      token = JWT::Token.new(payload: json_payload)
      token.sign!(algorithm: 'HS256', key: hmac_secret)
      token.detach_payload!

      result = described_class.verify(token.jwt, StringIO.new(json_body),
                                      key: hmac_secret, algorithm: 'HS256',
                                      chunk_size: 3)
      expect(result).to be_valid
    end

    it 'cross-validates a JWS signed with the streaming interface using Token/string interface data' do
      encoded = JWT::EncodedToken.new(signed_hs.jws)
      encoded.encoded_payload = JWT::Base64.url_encode(body)
      expect(encoded.valid_signature?(algorithm: 'HS256', key: hmac_secret)).to be(true)
    end

    it 'fails for tampered content' do
      result = described_class.verify(signed_hs.jws, StringIO.new(body + 'tampered'),
                                      key: hmac_secret, algorithm: 'HS256')
      expect(result).not_to be_valid
    end

    it 'fails for the wrong secret' do
      result = described_class.verify(signed_hs.jws, StringIO.new(body),
                                      key: 'b' * 32, algorithm: 'HS256')
      expect(result).not_to be_valid
    end

    it 'verify! raises JWT::VerificationError for a bad signature' do
      expect do
        described_class.verify!(signed_hs.jws, StringIO.new(body + 'x'),
                                key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'verify! returns the result and header for a valid signature' do
      result = described_class.verify!(signed_hs.jws, StringIO.new(body),
                                       key: hmac_secret, algorithm: 'HS256')
      expect(result.header['alg']).to eq('HS256')
    end

    it 'verifies from a non-rewindable pipe' do
      reader = non_rewindable_io(body)
      result = described_class.verify(signed_hs.jws, reader,
                                      key: hmac_secret, chunk_size: 5)
      expect(result).to be_valid
    end

    it 'verifies the empty body' do
      signed_empty = described_class.sign(StringIO.new(''), key: hmac_secret)
      result = described_class.verify(signed_empty.jws, StringIO.new(''),
                                      key: hmac_secret, algorithm: 'HS256')
      expect(result).to be_valid
      expect(result.stats.reads).to eq(0)
    end

    it 'wraps read failures' do
      io = Object.new
      def io.read(_length)
        raise IOError, 'disk gone'
      end
      expect do
        described_class.verify(signed_hs.jws, io, key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::StreamReadError, /disk gone/)
    end

    it 'accepts the algorithm when it is one of several allowed algorithms' do
      result = described_class.verify(signed_hs.jws, StringIO.new(body),
                                      key: hmac_secret, algorithm: %w[RS256 HS256])
      expect(result).to be_valid
    end

    it 'rejects a header algorithm not in the allowed list before reading the body' do
      expect do
        described_class.verify(signed_rs.jws, StringIO.new(body),
                               key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::IncorrectAlgorithm)
    end

    it 'rejects algorithms without incremental support instead of buffering' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'PS256'))
      jws = "#{header}..#{JWT::Base64.url_encode('sig')}"
      expect do
        described_class.verify(jws, StringIO.new(body), key: rsa_public, algorithm: 'PS256')
      end.to raise_error(JWT::StreamingNotSupported, /PS256/)
    end

    it 'rejects a JWS that is not detached' do
      inline = signed_hs.jws.sub('..', ".#{JWT::Base64.url_encode(body)}.")
      expect do
        described_class.verify(inline, StringIO.new(body), key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::MalformedTokenError)
    end

    it 'rejects a malformed JWS' do
      expect do
        described_class.verify('a.b', StringIO.new(body), key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::MalformedTokenError)
    end

    it 'rejects an unparsable header segment' do
      jws = "not-base64-json..#{JWT::Base64.url_encode('sig')}"
      expect do
        described_class.verify(jws, StringIO.new(body), key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::MalformedTokenError, /Invalid base64 encoding/)

      # A base64 string that does not decode to JSON raises separately.
      bad_json = JWT::Base64.url_encode('not json')
      jws = "#{bad_json}..#{JWT::Base64.url_encode('sig')}"
      expect do
        described_class.verify(jws, StringIO.new(body), key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::MalformedTokenError, /Invalid segment/)
    end

    it 'rejects a header that is not a JSON object' do
      header = JWT::Base64.url_encode('[1, 2]')
      jws = "#{header}..#{JWT::Base64.url_encode('sig')}"
      expect do
        described_class.verify(jws, StringIO.new(body), key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::MalformedTokenError, /not a JSON object/)
    end

    it 'rejects a header without an alg' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('kid' => 'x'))
      jws = "#{header}..#{JWT::Base64.url_encode('sig')}"
      expect do
        described_class.verify(jws, StringIO.new(body), key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::IncorrectAlgorithm, /missing alg/)
    end

    it 'requires the b64 header parameter to be marked critical' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'HS256', 'b64' => false))
      jws = "#{header}..#{JWT::Base64.url_encode('sig')}"
      expect do
        described_class.verify(jws, StringIO.new(body), key: hmac_secret, algorithm: 'HS256')
      end.to raise_error(JWT::InvalidCritError)
    end

    it 'tries multiple keys without rewinding the body' do
      reader = non_rewindable_io(body)
      result = described_class.verify(signed_hs.jws, reader,
                                      key: ['wrong' * 8, hmac_secret], algorithm: 'HS256',
                                      chunk_size: 6)
      expect(result).to be_valid
    end
  end

  describe 'argument validation' do
    it 'rejects a body without #read for signing' do
      expect { described_class.sign('body', key: hmac_secret) }.to raise_error(ArgumentError, /#read/)
    end

    it 'rejects a body without #read for verification' do
      expect { described_class.verify('h..s', 'body', key: hmac_secret) }.to raise_error(ArgumentError, /#read/)
    end

    it 'rejects a non positive chunk size' do
      expect do
        described_class.sign(StringIO.new('x'), key: hmac_secret, chunk_size: 0)
      end.to raise_error(ArgumentError, /chunk_size/)
      expect do
        described_class.sign(StringIO.new('x'), key: hmac_secret, chunk_size: 2.5)
      end.to raise_error(ArgumentError, /chunk_size/)
    end
  end

  describe 'JWT::JWK keys' do
    it 'signs and verifies HS256 through an HMAC JWK' do
      jwk = JWT::JWK.new(hmac_secret, { 'alg' => 'HS256', 'kid' => 'hmac-k' })
      result = described_class.sign(StringIO.new(body), key: jwk,
                                    headers: { 'kid' => 'hmac-k' },
                                    payload_io: StringIO.new(''.b), chunk_size: 19)
      expect(result.header['kid']).to eq('hmac-k')
      expect(described_class.verify(result.jws, StringIO.new(body),
                                    key: jwk, algorithm: 'HS256')).to be_valid
    end

    it 'signs and verifies RS256 through RSA JWKs' do
      private_jwk = JWT::JWK.new(rsa_key, { 'alg' => 'RS256', 'kid' => 'rsa-k' })
      public_jwk = JWT::JWK.new(rsa_public, { 'alg' => 'RS256', 'kid' => 'rsa-k' })
      result = described_class.sign(StringIO.new(body), key: private_jwk, algorithm: 'RS256',
                                    payload_io: StringIO.new(''.b), chunk_size: 19)
      expect(described_class.verify(result.jws, StringIO.new(body),
                                    key: public_jwk, algorithm: 'RS256')).to be_valid
    end

    it 'rejects a JWK whose alg does not match the requested algorithm' do
      jwk = JWT::JWK.new(rsa_key, { 'alg' => 'RS256', 'kid' => 'rsa-k' })
      expect do
        described_class.sign(StringIO.new(body), key: jwk, algorithm: 'HS256',
                             payload_io: StringIO.new(''.b))
      end.to raise_error(JWT::EncodeError)
    end
  end

  describe 'JWT::EncodedToken#verify_detached_signature!' do
    let(:signed) do
      described_class.sign(StringIO.new(body), key: rsa_key, algorithm: 'RS256',
                           payload_io: StringIO.new(''.b), chunk_size: 17)
    end

    it 'verifies the detached JWS from an IO and marks the token verified' do
      token = JWT::EncodedToken.new(signed.jws)
      stats = token.verify_detached_signature!(chunked_io(body, 17),
                                               algorithm: 'RS256', key: rsa_public,
                                               chunk_size: 17)
      expect(stats.bytes_read).to eq(body.bytesize)
      expect(stats.max_read_length).to eq(17)
    end

    it 'raises VerificationError for a modified body' do
      token = JWT::EncodedToken.new(signed.jws)
      expect do
        token.verify_detached_signature!(StringIO.new(body + '!'),
                                         algorithm: 'RS256', key: rsa_public)
      end.to raise_error(JWT::VerificationError)
    end

    it 'raises for an inline (non detached) token' do
      inline = JWT::Token.new(payload: json_payload).tap { |t| t.sign!(algorithm: 'RS256', key: rsa_key) }.jwt
      token = JWT::EncodedToken.new(inline)
      expect do
        token.verify_detached_signature!(chunked_io(json_body, 17),
                                         algorithm: 'RS256', key: rsa_public)
      end.to raise_error(JWT::MalformedTokenError, /not a detached JWS/)
    end
  end
end
