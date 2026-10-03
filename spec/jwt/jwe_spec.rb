# frozen_string_literal: true

RSpec.describe JWT::JWE do
  let(:key) { 'a' * 32 }
  let(:iv) { 'b' * 12 }
  let(:payload) { 'the answer is 42' }
  let(:iv_generator) { double(random_bytes: iv) }

  let(:jwe) do
    described_class.encrypt(
      payload: payload,
      key: key,
      headers: { kid: 'key-1' },
      iv_generator: iv_generator
    )
  end

  describe '.encrypt' do
    it 'produces a compact JWE with five segments' do
      expect(jwe.split('.', -1).length).to eq(5)
    end

    it 'uses dir with A256GCM and an empty encrypted key' do
      encoded_header, encrypted_key = jwe.split('.', -1)
      header = ::JSON.parse(JWT::Base64.url_decode(encoded_header))

      expect(header).to eq('alg' => 'dir', 'enc' => 'A256GCM', 'kid' => 'key-1')
      expect(encrypted_key).to eq('')
    end

    it 'supports binary payloads and empty plaintext' do
      binary_payload = (0..255).map(&:chr).join
      encrypted = described_class.encrypt(payload: binary_payload, key: key, iv_generator: iv_generator)
      empty = described_class.encrypt(payload: '', key: key, iv_generator: iv_generator)

      expect(described_class.decrypt(jwe: encrypted, key: key)).to eq(binary_payload)
      expect(described_class.decrypt(jwe: empty, key: key)).to eq('')
    end

    it 'uses the injected random source for the IV' do
      expect(described_class.decrypt(jwe: jwe, key: key)).to eq(payload)
      expect(iv_generator).to have_received(:random_bytes).with(12)
    end

    it 'exposes the compact implementation directly' do
      encrypted = described_class::Compact.encrypt(
        payload: payload,
        key: key,
        headers: { cty: 'JWT' },
        iv_generator: iv_generator
      )

      expect(described_class::Compact.decrypt(jwe: encrypted, key: key)).to eq(payload)
    end

    it 'does not allow overriding alg or enc' do
      expect do
        described_class.encrypt(payload: payload, key: key, headers: { alg: 'other' }, iv_generator: iv_generator)
      end.to raise_error(JWT::EncodeError, 'Header alg is reserved')

      expect do
        described_class.encrypt(payload: payload, key: key, headers: { enc: 'other' }, iv_generator: iv_generator)
      end.to raise_error(JWT::EncodeError, 'Header enc is reserved')
    end

    it 'rejects compression explicitly' do
      expect do
        described_class.encrypt(payload: payload, key: key, headers: { zip: 'DEF' }, iv_generator: iv_generator)
      end.to raise_error(JWT::EncodeError, 'Compression is not supported')
    end

    it 'requires a 32-byte key' do
      expect { described_class.encrypt(payload: payload, key: 'short', iv_generator: iv_generator) }
        .to raise_error(JWT::EncodeError, 'Key must be a 32-byte String')
    end

    it 'requires a string payload' do
      expect { described_class.encrypt(payload: { 'answer' => 42 }, key: key, iv_generator: iv_generator) }
        .to raise_error(JWT::EncodeError, 'Payload must be a String')
    end

    it 'requires the injected random source to return 12 bytes' do
      short_generator = double(random_bytes: 'short')

      expect { described_class.encrypt(payload: payload, key: key, iv_generator: short_generator) }
        .to raise_error(JWT::EncodeError, 'IV generator must return a 12-byte String')
    end

    it 'requires the injected random source to provide random bytes' do
      expect { described_class.encrypt(payload: payload, key: key, iv_generator: Object.new) }
        .to raise_error(JWT::EncodeError, 'IV generator must respond to random_bytes')
    end
  end

  describe '.decrypt' do
    it 'round-trips a payload' do
      expect(described_class.decrypt(jwe: jwe, key: key)).to eq(payload)
    end

    it 'authenticates the exact protected header bytes as AAD' do
      segments = jwe.split('.', -1)
      changed_header = { 'alg' => 'dir', 'enc' => 'A256GCM', 'kid' => 'key-2' }
      segments[0] = JWT::Base64.url_encode(::JSON.generate(changed_header))

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::VerificationError, 'JWE authentication failed')
    end

    it 'round-trips a nested compact JWS without verifying it automatically' do
      nested_jws = JWT.encode({ 'answer' => 42 }, 'jws-secret', 'HS256')
      nested_jwe = described_class.encrypt(
        payload: nested_jws,
        key: key,
        headers: { cty: 'JWT' },
        iv_generator: iv_generator
      )

      decrypted_plaintext = described_class.decrypt(jwe: nested_jwe, key: key)
      decoded_jws, header = JWT.decode(decrypted_plaintext, 'jws-secret', true, algorithm: 'HS256')

      expect(decrypted_plaintext).to eq(nested_jws)
      expect(decoded_jws).to eq('answer' => 42)
      expect(header).to include('alg' => 'HS256')
    end

    it 'keeps JWE separate from JWS decoding' do
      expect { JWT.decode(jwe, key, true, algorithm: 'HS256') }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
    end

    %w[protected_header encrypted_key iv ciphertext authentication_tag].each_with_index do |name, index|
      it "does not return plaintext when #{name} is tampered with" do
        segments = jwe.split('.', -1)

        if name == 'encrypted_key'
          segments[index] = 'QQ'
        elsif segments[index].length > 1
          segments[index] = mutate_last_character(segments[index])
        else
          segments[index] = 'QQ'
        end

        expect { described_class.decrypt(jwe: segments.join('.'), key: key) }.to raise_error do |error|
          expect(error).to be_a(JWT::Error)
          expect(error.message).not_to include(payload)
        end
      end
    end

    it 'fails when the wrong key is used' do
      expect { described_class.decrypt(jwe: jwe, key: 'z' * 32) }
        .to raise_error(JWT::VerificationError, 'JWE authentication failed')
    end

    it 'does not fall back to another algorithm' do
      segments = jwe.split('.', -1)
      header = ::JSON.parse(JWT::Base64.url_decode(segments[0]))
      header['alg'] = 'RSA1_5'
      segments[0] = JWT::Base64.url_encode(::JSON.generate(header))

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::IncorrectAlgorithm, 'Expected alg to be dir')
    end

    it 'does not fall back to another content encryption algorithm' do
      segments = jwe.split('.', -1)
      header = ::JSON.parse(JWT::Base64.url_decode(segments[0]))
      header['enc'] = 'A128GCM'
      segments[0] = JWT::Base64.url_encode(::JSON.generate(header))

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::IncorrectAlgorithm, 'Expected enc to be A256GCM')
    end

    it 'rejects compression from a token header' do
      compressed_jwe = build_jwe(headers: { 'alg' => 'dir', 'enc' => 'A256GCM', 'zip' => 'DEF' })

      expect { described_class.decrypt(jwe: compressed_jwe, key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Compression is not supported')
    end

    it 'rejects compression marked as a critical extension' do
      compressed_jwe = build_jwe(headers: { 'alg' => 'dir', 'enc' => 'A256GCM', 'crit' => ['zip'] })

      expect { described_class.decrypt(jwe: compressed_jwe, key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Compression is not supported')
    end

    it 'rejects duplicate protected header members' do
      header = '{"alg":"dir","alg":"dir","enc":"A256GCM"}'
      segments = jwe.split('.', -1)
      segments[0] = JWT::Base64.url_encode(header)

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Invalid protected header')
    end

    it 'rejects a protected header that is not a JSON object' do
      segments = jwe.split('.', -1)
      segments[0] = JWT::Base64.url_encode('[]')

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Protected header must be a JSON object')
    end

    it 'rejects an empty protected header segment' do
      segments = jwe.split('.', -1)
      segments[0] = ''

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Protected header is empty')
    end

    it 'rejects invalid segment counts' do
      expect { described_class.decrypt(jwe: 'a.b.c.d', key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
      expect { described_class.decrypt(jwe: 'a.b.c.d.e.f', key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
    end

    it 'rejects non-canonical Base64url in Base64url encoded segments' do
      [0, 2, 3, 4].each do |index|
        segments = jwe.split('.', -1)
        segments[index] = '='

        expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
          .to raise_error(JWT::Base64DecodeError, 'Invalid base64 encoding')
      end
    end

    it 'requires the dir encrypted key segment to remain empty' do
      segments = jwe.split('.', -1)
      segments[1] = '='

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Encrypted key must be empty for dir algorithm')
    end

    it 'requires a 32-byte key' do
      expect { described_class.decrypt(jwe: jwe, key: 'short') }
        .to raise_error(JWT::VerificationKeyError, 'Key must be a 32-byte String')
    end

    it 'requires an exact 12-byte IV' do
      segments = jwe.split('.', -1)
      segments[2] = JWT::Base64.url_encode('short')

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::MalformedTokenError, 'IV must be 12 bytes')
    end

    it 'requires an exact 16-byte authentication tag' do
      segments = jwe.split('.', -1)
      segments[4] = JWT::Base64.url_encode('short')

      expect { described_class.decrypt(jwe: segments.join('.'), key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Authentication tag must be 16 bytes')
    end
  end

  def mutate_last_character(segment)
    replacement = segment.end_with?('A') ? 'B' : 'A'
    segment[0..-2] + replacement
  end

  def build_jwe(headers:)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    encoded_header = JWT::Base64.url_encode(::JSON.generate(headers))
    cipher.auth_data = encoded_header
    ciphertext = cipher.update(payload) + cipher.final

    [
      encoded_header,
      '',
      JWT::Base64.url_encode(iv),
      JWT::Base64.url_encode(ciphertext),
      JWT::Base64.url_encode(cipher.auth_tag)
    ].join('.')
  end
end
