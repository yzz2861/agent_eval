# frozen_string_literal: true

RSpec.describe JWT::JWE::Compact do
  let(:deterministic_rng) { double('rng', random_bytes: iv) }
  let(:nil_rng) { double('rng', random_bytes: nil) }
  let(:key) { SecureRandom.random_bytes(32) }
  let(:iv) { SecureRandom.random_bytes(12) }
  let(:plaintext) { 'plaintext message' }
  let(:token) { described_class.encrypt(plaintext, key, iv: iv) }

  def with_segment(token, index, value)
    segments = token.split('.')
    segments[index] = value
    segments.join('.')
  end

  def base64url(data)
    JWT::Base64.url_encode(data)
  end

  def header_segment(header)
    base64url(JSON.generate(header))
  end

  describe '.encrypt/.decrypt' do
    it 'round trips a JWE compact token' do
      expect(token.split('.').size).to eq(5)
      expect(described_class.decrypt(token, key)).to eq(plaintext)
    end

    it 'supports empty plaintext and binary plaintext' do
      empty_token = described_class.encrypt('', key, iv: iv)
      binary = (0..255).map(&:chr).join.dup.force_encoding(Encoding::BINARY)
      binary_token = described_class.encrypt(binary, key, iv: iv)

      expect(described_class.decrypt(empty_token, key)).to eq('')
      expect(described_class.decrypt(binary_token, key)).to eq(binary)
    end

    it 'uses a deterministic injected random source' do
      first = described_class.encrypt(plaintext, key, rng: deterministic_rng)
      second = described_class.encrypt(plaintext, key, rng: deterministic_rng)

      expect(first).to eq(second)
      expect(described_class.decrypt(first, key)).to eq(plaintext)
    end

    it 'reproduces a token with an explicit IV' do
      first = described_class.encrypt(plaintext, key, iv: iv)
      second = described_class.encrypt(plaintext, key, iv: iv)

      expect(first).to eq(second)
    end

    it 'supports a reusable instance with an injected random source' do
      jwe = described_class.new(rng: deterministic_rng)

      expect(jwe.decrypt(jwe.encrypt(plaintext, key), key)).to eq(plaintext)
    end

    it 'accepts a callable random source' do
      first = described_class.encrypt(plaintext, key, rng: ->(_length) { iv })
      second = described_class.encrypt(plaintext, key, rng: ->(_length) { iv })

      expect(first).to eq(second)
    end

    it 'generates a fresh IV by default' do
      expect(described_class.encrypt(plaintext, key)).not_to eq(described_class.encrypt(plaintext, key))
    end

    it 'returns a nested JWS unchanged for explicit verification' do
      signing_key = 'jws-signing-secret-0000000000'
      nested_jws = JWT.encode({ 'data' => 'nested' }, signing_key, 'HS256')
      nested_token = described_class.encrypt(nested_jws, key, iv: iv)

      decrypted = described_class.decrypt(nested_token, key)
      payload, header = JWT.decode(decrypted, signing_key, true, algorithm: 'HS256')

      expect(decrypted).to eq(nested_jws)
      expect(payload).to eq('data' => 'nested')
      expect(header).to include('alg' => 'HS256')
    end
  end

  describe '.encrypt validation' do
    it 'requires plaintext to be a string' do
      expect { described_class.encrypt({ 'a' => 1 }, key) }
        .to raise_error(JWT::EncodeError, 'JWE plaintext must be a String')
    end

    [nil, 31, 33, SecureRandom.random_bytes(31), SecureRandom.random_bytes(33)].each do |invalid_key|
      it "rejects key #{invalid_key.inspect}" do
        expect { described_class.encrypt(plaintext, invalid_key) }
          .to raise_error(JWT::EncodeError, 'JWE key must be a 32-byte String')
      end
    end

    [11, 13].each do |length|
      it "rejects a #{length}-byte explicit IV" do
        expect { described_class.encrypt(plaintext, key, iv: SecureRandom.random_bytes(length)) }
          .to raise_error(JWT::EncodeError, 'JWE IV must be a 12-byte String')
      end
    end

    it 'rejects a random source that does not generate a string IV' do
      expect { described_class.encrypt(plaintext, key, rng: nil_rng) }
        .to raise_error(JWT::EncodeError, 'JWE IV must be a 12-byte String')
    end

    it 'rejects a random source without random_bytes or call' do
      expect { described_class.encrypt(plaintext, key, rng: Object.new) }
        .to raise_error(JWT::EncodeError, 'JWE random source must respond to random_bytes or call')
    end
  end

  describe '.decrypt validation' do
    it 'rejects the wrong key without returning plaintext' do
      expect { described_class.decrypt(token, SecureRandom.random_bytes(32)) }
        .to raise_error(JWT::VerificationError, 'JWE authentication failed')
    end

    it 'rejects a key with the wrong length' do
      expect { described_class.decrypt(token, SecureRandom.random_bytes(31)) }
        .to raise_error(JWT::VerificationKeyError, 'JWE key must be a 32-byte String')
    end

    it 'rejects tokens with the wrong number of segments' do
      expect { described_class.decrypt(token.sub('.', ''), key) }
        .to raise_error(JWT::MalformedTokenError, 'JWE Compact serialization must contain five segments')
    end

    it 'rejects illegal base64url encoding' do
      malformed = with_segment(token, 1, 'not base64url!')

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::Base64DecodeError, 'Invalid base64url encoding')
    end

    it 'rejects padded base64url encoding' do
      padded = base64url('abc') + '='
      malformed = with_segment(token, 3, padded)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::Base64DecodeError, 'Invalid base64url encoding')
    end

    it 'rejects duplicate protected header members' do
      duplicate_header = base64url('{"alg":"dir","enc":"A256GCM","enc":"A256GCM"}')
      malformed = with_segment(token, 0, duplicate_header)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::MalformedTokenError, 'Invalid JWE protected header')
    end

    it 'rejects a protected header that is not a JSON object' do
      malformed = with_segment(token, 0, header_segment(['dir', 'A256GCM']))

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::MalformedTokenError, 'JWE protected header must be a JSON object')
    end

    it 'rejects unsupported algorithms without fallback' do
      header = header_segment('alg' => 'RSA1_5', 'enc' => 'A256GCM')
      malformed = with_segment(token, 0, header)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::IncorrectAlgorithm, 'Only alg=dir and enc=A256GCM are supported')
    end

    it 'rejects unsupported content encryption algorithms without fallback' do
      header = header_segment('alg' => 'dir', 'enc' => 'A128GCM')
      malformed = with_segment(token, 0, header)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::IncorrectAlgorithm, 'Only alg=dir and enc=A256GCM are supported')
    end

    it 'rejects compression' do
      header = header_segment('alg' => 'dir', 'enc' => 'A256GCM', 'zip' => 'DEF')
      malformed = with_segment(token, 0, header)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::JWE::UnsupportedCompression, 'JWE compression is not supported')
    end

    it 'rejects a non-empty direct encrypted key segment' do
      malformed = with_segment(token, 1, base64url('unexpected'))

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::MalformedTokenError, 'The dir algorithm requires an empty encrypted key segment')
    end

    it 'rejects an IV with the wrong decoded length' do
      malformed = with_segment(token, 2, base64url(SecureRandom.random_bytes(11)))

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::MalformedTokenError, 'JWE IV must be 12 bytes')
    end

    it 'rejects an authentication tag with the wrong decoded length' do
      malformed = with_segment(token, 4, base64url(SecureRandom.random_bytes(15)))

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::MalformedTokenError, 'JWE authentication tag must be 16 bytes')
    end

    it 'rejects a modified protected header because it is AAD' do
      alternate_header = header_segment('alg' => 'dir', 'enc' => 'A256GCM', 'kid' => 'changed')
      malformed = with_segment(token, 0, alternate_header)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::VerificationError, 'JWE authentication failed')
    end

    it 'rejects a modified IV' do
      segments = token.split('.')
      modified_iv = segments[2].sub(/\A(.)/) { |char| char == 'A' ? 'B' : 'A' }
      malformed = with_segment(token, 2, modified_iv)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::VerificationError, 'JWE authentication failed')
    end

    it 'rejects modified ciphertext' do
      segments = token.split('.')
      modified_ciphertext = segments[3].sub(/\A(.)/) { |char| char == 'A' ? 'B' : 'A' }
      malformed = with_segment(token, 3, modified_ciphertext)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::VerificationError, 'JWE authentication failed')
    end

    it 'rejects a modified authentication tag' do
      segments = token.split('.')
      modified_tag = segments[4].sub(/\A(.)/) { |char| char == 'A' ? 'B' : 'A' }
      malformed = with_segment(token, 4, modified_tag)

      expect { described_class.decrypt(malformed, key) }
        .to raise_error(JWT::VerificationError, 'JWE authentication failed')
    end
  end

  describe 'JWT.decode isolation' do
    it 'does not interpret a five segment JWE as a JWT' do
      expect { JWT.decode(token, key, true, algorithm: 'HS256') }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
    end
  end
end
