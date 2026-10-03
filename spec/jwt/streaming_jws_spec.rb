# frozen_string_literal: true

RSpec.describe JWT::StreamingJWS do
  let(:payload) { "the quick brown fox jumps over the lazy dog\x00\xFF".b }
  let(:hmac_key) { 'a' * 32 }
  let(:rsa_key) { test_pkey('rsa-2048-private.pem') }
  let(:rsa_public_key) { test_pkey('rsa-2048-public.pem') }
  let(:chunk_sizes) { [1, 2, 3, 5, 7, 16, 4096] }

  def classic_jws(payload:, key:, algorithm:, base64_payload:)
    header = { 'alg' => algorithm }
    unless base64_payload
      header['b64'] = false
      header['crit'] = ['b64']
    end

    encoded_header = JWT::Base64.url_encode(JSON.generate(header))
    signing_payload = base64_payload ? JWT::Base64.url_encode(payload) : payload
    signature = JWT::JWA.resolve(algorithm).sign(
      data: "#{encoded_header}.#{signing_payload}",
      signing_key: key
    )
    [encoded_header, '', JWT::Base64.url_encode(signature)].join('.')
  end

  def detached_jws(algorithm: 'HS256')
    encoded_header = JWT::Base64.url_encode(JSON.generate('alg' => algorithm))
    encoded_signature = JWT::Base64.url_encode('signature')
    "#{encoded_header}..#{encoded_signature}"
  end

  [
    { algorithm: 'HS256', key: :hmac_key, verification_key: :hmac_key },
    { algorithm: 'RS256', key: :rsa_key, verification_key: :rsa_public_key }
  ].each do |definition|
    algorithm = definition[:algorithm]

    describe algorithm do
      let(:signing_key) { send(definition[:key]) }
      let(:verification_key) { send(definition[:verification_key]) }

      shared_examples 'streaming detached JWS' do |base64_payload|
        it 'matches the string interface across chunk boundaries' do
          expected = classic_jws(
            payload: payload,
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload
          )
          expected_payload = base64_payload ? JWT::Base64.url_encode(payload) : payload

          chunk_sizes.each do |chunk_size|
            payload_io = TrackingIO.new(payload)
            payload_output = StringIO.new
            result = described_class.sign(
              payload_io,
              key: signing_key,
              algorithm: algorithm,
              base64_payload: base64_payload,
              chunk_size: chunk_size,
              payload_output: payload_output
            )

            expect(result.jws).to eq(expected)
            expect(result.to_s).to eq(expected)
            expect(payload_output.string).to eq(expected_payload)
            expect(result.stats.bytes_read).to eq(payload.bytesize)
            expect(result.stats.max_read_length).to eq([chunk_size, payload.bytesize].min)
            expect(payload_io.max_read_length).to eq([chunk_size, payload.bytesize].min)

            verification_io = TrackingIO.new(payload)
            stats = described_class.verify(
              result.jws,
              verification_io,
              key: verification_key,
              chunk_size: chunk_size
            )

            expect(stats.bytes_read).to eq(payload.bytesize)
            expect(stats.max_read_length).to eq([chunk_size, payload.bytesize].min)
            expect(verification_io.rewind_count).to eq(0)
          end
        end

        it 'verifies a JWS produced by the string interface' do
          jws = classic_jws(
            payload: payload,
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload
          )

          chunk_sizes.each do |chunk_size|
            expect(described_class.valid?(
              jws,
              TrackingIO.new(payload),
              key: verification_key,
              chunk_size: chunk_size
            )).to be(true)
          end
        end

        it 'works through JWT::EncodedToken with a detached payload' do
          interoperable_payload = JSON.generate('example' => 'payload')
          output = StringIO.new
          result = described_class.sign(
            TrackingIO.new(interoperable_payload),
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload,
            payload_output: output
          )
          encoded_token = JWT::EncodedToken.new(result.jws)
          encoded_token.encoded_payload = output.string

          expect(encoded_token.verify_signature!(algorithm: algorithm, key: verification_key)).to be_nil
        end

        it 'rejects changed content' do
          result = described_class.sign(
            TrackingIO.new(payload),
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload
          )
          changed = payload + ' changed'

          expect(described_class.valid?(
            result.jws,
            TrackingIO.new(changed),
            key: verification_key
          )).to be(false)
          expect do
            described_class.verify(result.jws, TrackingIO.new(changed), key: verification_key)
          end.to raise_error(JWT::VerificationError, 'Signature verification failed')
        end

        it 'handles an empty body' do
          result = described_class.sign(
            TrackingIO.new(''),
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload
          )
          output = StringIO.new
          empty_result = described_class.sign(
            TrackingIO.new(''),
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload,
            payload_output: output
          )

          expect(empty_result.jws).to eq(result.jws)
          expect(output.string).to eq('')
          expect(result.stats).to have_attributes(bytes_read: 0, read_count: 0, max_read_length: 0)
          expect(described_class.verify(result.jws, TrackingIO.new(''), key: verification_key)).to have_attributes(
            bytes_read: 0,
            read_count: 0,
            max_read_length: 0
          )
        end

        it 'works with an input that cannot rewind' do
          output = StringIO.new
          result = described_class.sign(
            NonRewindableIO.new(payload, chunk_size: 13),
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload,
            chunk_size: 13,
            payload_output: output
          )

          expected_payload = base64_payload ? JWT::Base64.url_encode(payload) : payload
          expect(output.string).to eq(expected_payload)

          stats = described_class.verify(
            result.jws,
            NonRewindableIO.new(payload, chunk_size: 17),
            key: verification_key,
            chunk_size: 17
          )
          expect(stats).to have_attributes(bytes_read: payload.bytesize, max_read_length: 17)
        end

        it 'handles variable short reads without rewinding' do
          result = described_class.sign(
            VariableReadIO.new(payload),
            key: signing_key,
            algorithm: algorithm,
            base64_payload: base64_payload,
            chunk_size: 32
          )
          verify_io = VariableReadIO.new(payload)

          expect(described_class.verify(result.jws, verify_io, key: verification_key, chunk_size: 32)).to have_attributes(
            bytes_read: payload.bytesize,
            max_read_length: 11
          )
          expect(verify_io.rewind_count).to eq(0)
        end
      end

      context 'with a base64url encoded payload' do
        include_examples 'streaming detached JWS', true
      end

      context 'with b64 false' do
        include_examples 'streaming detached JWS', false

        it 'sets the required JWS headers' do
          result = described_class.sign(
            TrackingIO.new(payload),
            key: signing_key,
            algorithm: algorithm,
            headers: { 'custom' => 'value' },
            base64_payload: false
          )

          header = JSON.parse(JWT::Base64.url_decode(result.jws.split('.').first))
          expect(header).to eq(
            'alg' => algorithm,
            'b64' => false,
            'crit' => ['b64'],
            'custom' => 'value'
          )
        end

        it 'can infer b64 false from the header' do
          result = described_class.sign(
            TrackingIO.new(payload),
            key: signing_key,
            algorithm: algorithm,
            headers: { 'b64' => false, 'crit' => ['b64', 'other'] }
          )

          expect(described_class.verify(result.jws, TrackingIO.new(payload), key: verification_key)).to have_attributes(
            bytes_read: payload.bytesize
          )
        end

        it 'rejects a conflicting b64 header' do
          expect do
            described_class.sign(
              TrackingIO.new(payload),
              key: signing_key,
              algorithm: algorithm,
              base64_payload: true,
              headers: { 'b64' => false }
            )
          end.to raise_error(JWT::EncodeError, 'The b64 header does not match base64_payload')
        end
      end
    end
  end

  it 'normalizes a lowercase supported algorithm in the header' do
    result = described_class.sign(StringIO.new('body'), key: 'a' * 32, algorithm: 'hs256')

    header = JSON.parse(JWT::Base64.url_decode(result.jws.split('.').first))
    expect(header['alg']).to eq('HS256')
    expect(described_class.verify(result.jws, StringIO.new('body'), key: 'a' * 32)).to have_attributes(
      bytes_read: 4
    )
  end

  describe 'JWK keys' do
    it 'supports an HMAC JWK' do
      jwk = JWT::JWK::HMAC.new('a' * 32, alg: 'HS256')
      result = described_class.sign(TrackingIO.new(payload), key: jwk, algorithm: 'HS256')

      expect(described_class.verify(result.jws, TrackingIO.new(payload), key: jwk)).to have_attributes(
        bytes_read: payload.bytesize
      )
    end

    it 'supports an RSA JWK' do
      jwk = JWT::JWK::RSA.new(rsa_key, alg: 'RS256')
      result = described_class.sign(TrackingIO.new(payload), key: jwk, algorithm: 'RS256')

      expect(described_class.verify(result.jws, TrackingIO.new(payload), key: jwk)).to have_attributes(
        bytes_read: payload.bytesize
      )
    end
  end

  describe 'unsupported algorithms' do
    %w[HS384 HS512 RS384 RS512 PS256 ES256 none].each do |algorithm|
      it "rejects #{algorithm} before reading the payload" do
        io = TrackingIO.new('payload')
        jws = detached_jws

        expect { described_class.sign(io, key: 'secret', algorithm: algorithm) }
          .to raise_error(JWT::EncodeError, "Streaming JWS does not support algorithm #{algorithm}")
        expect(io.read_count).to eq(0)

        expect { described_class.verify(jws, io, key: 'secret', algorithm: algorithm) }
          .to raise_error(JWT::IncorrectAlgorithm, "Streaming JWS does not support algorithm #{algorithm}")
        expect(io.read_count).to eq(0)
      end
    end
  end

  describe 'input errors' do
    it 'rejects multiple verification keys because the body can only be read once' do
      expect do
        described_class.sign(TrackingIO.new(''), key: ['a' * 32, 'b' * 32], algorithm: 'HS256')
      end.to raise_error(ArgumentError, 'Streaming JWS supports a single key because the payload may not be rewindable')

      expect do
        described_class.verify(detached_jws, TrackingIO.new(''), key: ['a' * 32, 'b' * 32])
      end.to raise_error(ArgumentError, 'Streaming JWS supports a single key because the payload may not be rewindable')
    end

    it 'wraps read failures while signing' do
      expect { described_class.sign(FailingIO.new, key: 'a' * 32, algorithm: 'HS256') }
        .to raise_error(JWT::StreamingPayloadError, 'Failed to read streaming payload: boom')
    end

    it 'wraps read failures while verifying' do
      signed = described_class.sign(StringIO.new('body'), key: 'a' * 32, algorithm: 'HS256').jws

      expect { described_class.verify(signed, FailingIO.new, key: 'a' * 32) }
        .to raise_error(JWT::StreamingPayloadError, 'Failed to read streaming payload: boom')
    end

    it 'wraps payload output failures' do
      output = Object.new
      def output.write(*)
        raise 'disk full'
      end

      expect do
        described_class.sign(TrackingIO.new('body'), key: 'a' * 32, algorithm: 'HS256', payload_output: output)
      end.to raise_error(JWT::StreamingPayloadError, 'Failed to write streaming payload: disk full')
    end

    it 'requires a readable payload' do
      expect { described_class.sign(Object.new, key: 'a' * 32, algorithm: 'HS256') }
        .to raise_error(ArgumentError, 'Payload must respond to read')
      expect { described_class.verify(detached_jws, Object.new, key: 'a' * 32) }
        .to raise_error(ArgumentError, 'Payload must respond to read')
    end

    it 'requires a positive integer chunk size' do
      expect { described_class.sign(TrackingIO.new(''), key: 'a' * 32, algorithm: 'HS256', chunk_size: 0) }
        .to raise_error(ArgumentError, 'Chunk size must be a positive integer')
      expect { described_class.verify(detached_jws, TrackingIO.new(''), key: 'a' * 32, chunk_size: 2.5) }
        .to raise_error(ArgumentError, 'Chunk size must be a positive integer')
    end
  end

  describe 'malformed JWS' do
    it 'requires three compact segments with a detached payload' do
      expect { described_class.verify('a.b.c', StringIO.new('b'), key: 'a' * 32) }
        .to raise_error(JWT::MalformedTokenError, 'Streaming JWS only verifies detached payloads')
    end

    it 'requires the requested algorithm to match the header' do
      signed = described_class.sign(StringIO.new('body'), key: 'a' * 32, algorithm: 'HS256').jws

      expect do
        described_class.verify(signed, StringIO.new('body'), key: 'a' * 32, algorithm: 'RS256')
      end.to raise_error(JWT::IncorrectAlgorithm, 'Expected a different algorithm')
    end

    it 'does not read the payload for a malformed JWS' do
      io = TrackingIO.new('body')

      expect { described_class.verify('bogus', io, key: 'a' * 32) }
        .to raise_error(JWT::MalformedTokenError)
      expect(io.read_count).to eq(0)
    end

    it 'requires a Boolean b64 header' do
      header = JWT::Base64.url_encode(JSON.generate('alg' => 'HS256', 'b64' => 'false'))
      jws = [header, '', detached_jws.split('.').last].join('.')

      expect { described_class.verify(jws, TrackingIO.new(''), key: 'a' * 32) }
        .to raise_error(JWT::MalformedTokenError, 'The b64 header must be a Boolean')
    end

    it 'requires b64 to be marked critical when false' do
      header = JWT::Base64.url_encode(JSON.generate('alg' => 'HS256', 'b64' => false))
      jws = [header, '', detached_jws.split('.').last].join('.')

      expect { described_class.verify(jws, TrackingIO.new(''), key: 'a' * 32) }
        .to raise_error(JWT::MalformedTokenError, "The crit header must include 'b64' when b64 is false")
    end

    it 'requires the crit header to be an array' do
      header = JWT::Base64.url_encode(JSON.generate('alg' => 'HS256', 'b64' => false, 'crit' => 'b64'))
      jws = [header, '', detached_jws.split('.').last].join('.')

      expect { described_class.verify(jws, TrackingIO.new(''), key: 'a' * 32) }
        .to raise_error(JWT::MalformedTokenError, 'The crit header must be an Array')
    end
  end

  class TrackingIO
    attr_reader :read_count, :max_read_length, :rewind_count

    def initialize(payload)
      @payload = payload
      @position = 0
      @read_count = 0
      @max_read_length = 0
      @rewind_count = 0
    end

    def read(length)
      chunk = @payload.byteslice(@position, length)
      @position += chunk.to_s.bytesize
      @read_count += 1
      @max_read_length = [@max_read_length, chunk.to_s.bytesize].max
      chunk
    end

    def rewind(*)
      @rewind_count += 1
      raise NotImplementedError, 'cannot rewind'
    end
  end

  class NonRewindableIO
    def initialize(payload, chunk_size:)
      @io = StringIO.new(payload)
      @chunk_size = chunk_size
    end

    def read(length)
      raise ArgumentError, 'unexpected length' unless length == @chunk_size

      @io.read(length)
    end
  end

  class VariableReadIO < NonRewindableIO
    attr_reader :rewind_count

    def initialize(payload)
      @io = StringIO.new(payload)
      @lengths = [3, 7, 1, 11, 2].cycle
      @rewind_count = 0
    end

    def read(length)
      @io.read([length, @lengths.next].min)
    end

    def rewind(*)
      @rewind_count += 1
      raise NotImplementedError, 'cannot rewind'
    end
  end

  class FailingIO
    def read(_length)
      raise 'boom'
    end
  end
end
