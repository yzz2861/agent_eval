# frozen_string_literal: true

RSpec.describe 'strict JSON parsing of tokens' do
  let(:payload) { { 'user' => 'some@user.tld' } }
  let(:secret) { 'secret' }

  def sign_raw(header_json, raw_payload_json, key: secret)
    header_segment = Base64.urlsafe_encode64(header_json, padding: false)
    payload_segment = Base64.urlsafe_encode64(raw_payload_json, padding: false)
    signature = Base64.urlsafe_encode64(
      OpenSSL::HMAC.digest('SHA256', key, "#{header_segment}.#{payload_segment}"),
      padding: false
    )
    [header_segment, payload_segment, signature].join('.')
  end

  def encode_segments(header_json, payload_json)
    sign_raw(header_json, payload_json.to_json)
  end

  shared_examples 'a strict token parser' do
    it 'parses a normal token' do
      token = JWT.encode(payload, secret, 'HS256')
      expect(parse.call(token)).to eq([payload, { 'alg' => 'HS256' }])
    end

    it 'rejects duplicate members in the header even with a valid signature' do
      token = encode_segments('{"alg":"HS256","alg":"none"}', payload)
      expect { parse.call(token) }.to raise_error(JWT::MalformedTokenError, /duplicate_member at position/)
    end

    it 'rejects duplicate members in the payload even with a valid signature' do
      token = sign_raw('{"alg":"HS256"}', '{"user":"a","user":"b"}')
      expect { parse.call(token) }.to raise_error(JWT::MalformedTokenError, /duplicate_member at position/)
    end

    it 'rejects nested duplicate members in the payload' do
      token = sign_raw('{"alg":"HS256"}', '{"a":{"b":1,"b":2}}')
      expect { parse.call(token) }.to raise_error(JWT::MalformedTokenError, /duplicate_member/)
    end

    it 'rejects keys that become equal after unescaping' do
      token = sign_raw('{"alg":"HS256"}', '{"a":1,"\u0061":2}')
      expect { parse.call(token) }.to raise_error(JWT::MalformedTokenError, /duplicate_member/)
    end

    it 'accepts duplicate string values' do
      token = JWT.encode({ 'a' => %w[x x], 'b' => 'x' }, secret, 'HS256')
      expect(parse.call(token).first).to eq('a' => %w[x x], 'b' => 'x')
    end

    it 'decodes multibyte UTF-8 from base64 segments encoded as ASCII-8BIT' do
      token = JWT.encode({ 'name' => "caf\u00e9 \u{1F600}" }, secret, 'HS256')
      expect(parse.call(token).first).to eq('name' => "caf\u00e9 \u{1F600}")
    end

    it 'rejects invalid UTF-8 in the payload' do
      raw = '{"a":"'.b << 0xFF << '"}'.b
      token = sign_raw('{"alg":"HS256"}', raw)
      expect { parse.call(token) }.to raise_error(JWT::MalformedTokenError, /invalid_encoding at position/)
    end

    it 'rejects payloads deeper than the depth limit' do
      token = JWT.encode({ 'a' => { 'b' => { 'c' => 1 } } }, secret, 'HS256')
      expect { parse.call(token, json_max_depth: 2) }
        .to raise_error(JWT::MalformedTokenError, /depth_exceeded/)
    end

    it 'rejects payloads exceeding the member limit' do
      token = JWT.encode({ 'a' => [1, 2, 3, 4, 5] }, secret, 'HS256')
      expect { parse.call(token, json_max_members: 4) }
        .to raise_error(JWT::MalformedTokenError, /member_limit_exceeded/)
    end

    it 'rejects payloads with numbers longer than the lexical limit' do
      token = JWT.encode({ 'a' => 123_456_789_012 }, secret, 'HS256')
      expect { parse.call(token, json_max_number_length: 10) }
        .to raise_error(JWT::MalformedTokenError, /number_too_long/)
    end

    it 'does not include payload fragments in parsing error messages' do
      secret_value = 'super-secret-claim-value'
      raw = { a: secret_value }.to_json.chomp('}') + ',"a":"duplicate"}'
      token = sign_raw('{"alg":"HS256"}', raw)
      begin
        parse.call(token)
        raise 'expected an error'
      rescue JWT::MalformedTokenError => e
        expect(e.message).not_to include(secret_value)
        expect(e.message).to match(/\AInvalid JSON: [a-z_]+ at position \d+\z/)
      end
    end
  end

  describe 'JWT::EncodedToken (strict by default)' do
    def parse_token(token, json_max_depth: nil, json_max_members: nil, json_max_number_length: nil)
      encoded = JWT::EncodedToken.new(
        token,
        max_depth: json_max_depth,
        max_members: json_max_members,
        max_number_length: json_max_number_length
      )
      encoded.verify_signature!(algorithm: 'HS256', key: secret)
      [encoded.unverified_payload, encoded.header]
    end

    include_examples 'a strict token parser' do
      let(:parse) { ->(token, **limits) { parse_token(token, **limits) } }
    end

    it 'rejects the duplicate header while reading the header before signature checks' do
      token = encode_segments('{"alg":"HS256","alg":"none"}', payload)
      expect { JWT::EncodedToken.new(token).header }.to raise_error(JWT::MalformedTokenError, /duplicate_member/)
    end

    it 'keeps error messages free of payload content when the signature fails' do
      secret_value = 'do-not-leak-me'
      token = JWT.encode({ 'a' => secret_value }, secret, 'HS256')
      expect do
        JWT::EncodedToken.new(token).verify_signature!(algorithm: 'HS256', key: 'wrong-key')
      end.to raise_error(JWT::VerificationError, 'Signature verification failed') do |error|
        expect(error.message).not_to include(secret_value)
      end
    end

    context 'with a detached payload' do
      let(:detached) do
        JWT::Token.new(payload: payload).tap do |token|
          token.sign!(algorithm: 'HS256', key: secret)
          token.detach_payload!
        end
      end

      it 'parses the attached payload strictly' do
        encoded = JWT::EncodedToken.new(detached.jwt)
        encoded.encoded_payload = detached.encoded_payload
        expect(encoded.unverified_payload).to eq(payload)
      end

      it 'rejects duplicate members in the attached payload' do
        encoded = JWT::EncodedToken.new(detached.jwt)
        encoded.encoded_payload = Base64.urlsafe_encode64('{"a":1,"a":2}', padding: false)
        expect { encoded.unverified_payload }.to raise_error(JWT::MalformedTokenError, /duplicate_member/)
      end
    end

    context 'with an unencoded (b64: false) payload' do
      let(:encoded_token) { 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature' }

      it 'rejects duplicate members in the raw payload' do
        encoded = JWT::EncodedToken.new(encoded_token)
        encoded.encoded_payload = '{"a":1,"a":2}'
        expect { encoded.unverified_payload }.to raise_error(JWT::MalformedTokenError, /duplicate_member/)
      end

      it 'parses a valid raw payload' do
        encoded = JWT::EncodedToken.new(encoded_token)
        encoded.encoded_payload = '{"foo":"bar"}'
        expect(encoded.unverified_payload).to eq('foo' => 'bar')
      end
    end

    context 'when strict parsing is disabled' do
      it 'keeps the historical last value wins behavior' do
        token = sign_raw('{"alg":"HS256"}', '{"a":1,"a":2}')
        encoded = JWT::EncodedToken.new(token, strict_json: false)
        expect(encoded.header).to eq('alg' => 'HS256')
        expect(encoded.unverified_payload).to eq('a' => 2)
      end
    end
  end

  describe 'JWT.decode with strict_json: true' do
    include_examples 'a strict token parser' do
      let(:parse) { ->(token, **limits) { JWT.decode(token, secret, true, { algorithm: 'HS256', strict_json: true, **limits }) } }
    end

    it 'rejects duplicate headers before trusting the claimed algorithm' do
      token = encode_segments('{"alg":"HS256","alg":"none"}', payload)
      expect { JWT.decode(token, secret, true, algorithm: 'HS256', strict_json: true) }
        .to raise_error(JWT::MalformedTokenError, /duplicate_member/)
    end

    it 'rejects a malformed payload even when signature verification is disabled' do
      token = sign_raw('{"alg":"HS256"}', '{"a":1,"a":2}')
      expect { JWT.decode(token, nil, false, strict_json: true) }
        .to raise_error(JWT::MalformedTokenError, /duplicate_member/)
    end

    it 'does not crash with a TypeError when the header parses to an array' do
      header_segment = Base64.urlsafe_encode64('[1,2,3]', padding: false)
      payload_segment = Base64.urlsafe_encode64('{}', padding: false)
      token = "#{header_segment}.#{payload_segment}."
      expect { JWT.decode(token, nil, false, strict_json: true) }.not_to raise_error
    end

    it 'reports a non object header as malformed when the signature is verified' do
      header_segment = Base64.urlsafe_encode64('[1,2,3]', padding: false)
      payload_segment = Base64.urlsafe_encode64('{}', padding: false)
      signature = Base64.urlsafe_encode64(
        OpenSSL::HMAC.digest('SHA256', secret, "#{header_segment}.#{payload_segment}"),
        padding: false
      )
      token = "#{header_segment}.#{payload_segment}.#{signature}"
      expect { JWT.decode(token, secret, true, algorithm: 'HS256', strict_json: true) }
        .to raise_error(JWT::MalformedTokenError, 'Token header not a JSON object')
    end
  end

  describe 'JWT.decode by default' do
    let(:token) { sign_raw('{"alg":"HS256"}', '{"a":1,"a":2}') }

    it 'keeps the historical lenient behavior for backwards compatibility' do
      expect(JWT.decode(token, secret, true, algorithm: 'HS256').first).to eq('a' => 2)
    end

    it 'still verifies normal tokens' do
      normal = JWT.encode(payload, secret, 'HS256')
      expect(JWT.decode(normal, secret, true, algorithm: 'HS256')).to eq([payload, { 'alg' => 'HS256' }])
    end
  end
end
