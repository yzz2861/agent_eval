# frozen_string_literal: true

RSpec.describe 'strict JSON decoding' do
  let(:secret) { 'strict-secret' }

  def sign(header_json, payload_json, key: secret)
    header_segment = JWT::Base64.url_encode(header_json)
    payload_segment = JWT::Base64.url_encode(payload_json)
    signature = OpenSSL::HMAC.digest('SHA256', key, "#{header_segment}.#{payload_segment}")
    [header_segment, payload_segment, JWT::Base64.url_encode(signature)].join('.')
  end

  describe 'duplicate members' do
    it 'rejects a duplicate header member even before the signature is checked' do
      token = sign(%q({"alg":"HS256","alg":"none"}), %q({"data":"payload"}))

      expect do
        JWT.decode(token, 'wrong-key', true, algorithms: ['HS256', 'none'])
      end.to raise_error(JWT::MalformedTokenError, /duplicate_member at position \d+/)
    end

    it 'rejects a duplicate payload member on a correctly signed token' do
      token = sign(%q({"alg":"HS256"}), %q({"a":1,"a":2}))

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /duplicate_member at position \d+/)
    end

    it 'rejects a duplicate nested payload member' do
      token = sign(%q({"alg":"HS256"}), %q({"outer":{"b":1,"b":2}}))

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /duplicate_member at position \d+/)
    end

    it 'rejects keys that are equal after escape decoding' do
      token = sign(%q({"alg":"HS256"}), '{"\\u0061":1,"a":2}')

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /duplicate_member at position \d+/)
    end

    it 'rejects nested keys that are equal after escape decoding' do
      token = sign(%q({"alg":"HS256","\\u0061lg":"nope"}), %q({"a":1}))

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /duplicate_member at position \d+/)
    end

    it 'rejects duplicate members when verification is disabled' do
      token = sign(%q({"alg":"HS256","alg":"HS256"}), %q({"a":1}))

      expect do
        JWT.decode(token, nil, false)
      end.to raise_error(JWT::MalformedTokenError, /duplicate_member at position \d+/)
    end

    it 'accepts repeated string values' do
      token = sign(%q({"alg":"HS256"}), %q({"a":"same","b":"same","c":["same"]}))

      payload, header = JWT.decode(token, secret, true, algorithms: ['HS256'])
      expect(payload).to eq('a' => 'same', 'b' => 'same', 'c' => ['same'])
      expect(header).to eq('alg' => 'HS256')
    end

    it 'accepts the same key used in different nested objects' do
      token = sign(%q({"alg":"HS256"}), %q({"a":{"k":1},"b":{"k":2}}))

      payload, = JWT.decode(token, secret, true, algorithms: ['HS256'])
      expect(payload).to eq('a' => { 'k' => 1 }, 'b' => { 'k' => 2 })
    end
  end

  describe 'structural limits' do
    it 'rejects an excessively deep payload' do
      depth = JWT::StrictJSON.const_get(:MAX_DEPTH) + 1
      payload_json = '[' * depth + '1' + ']' * depth
      token = sign(%q({"alg":"HS256"}), payload_json)

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /depth_exceeded at position \d+/)
    end

    it 'rejects an object with too many members' do
      count = JWT::StrictJSON.const_get(:MAX_OBJECT_MEMBERS) + 1
      members = (1..count).map { |index| %Q("k#{index}":#{index}) }
      token = sign(%q({"alg":"HS256"}), "{#{members.join(',')}}")

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /too_many_members at position \d+/)
    end

    it 'rejects an overlong number' do
      token = sign(%q({"alg":"HS256"}), %Q({"exp":#{10**25}}))

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /number_too_long at position \d+/)
    end
  end

  describe 'invalid UTF-8' do
    it 'rejects invalid UTF-8 in the payload even with a valid signature' do
      header_segment = JWT::Base64.url_encode(%q({"alg":"HS256"}))
      payload_segment = JWT::Base64.url_encode("{\"k\":\":\xff\"}".b)
      signature = OpenSSL::HMAC.digest('SHA256', secret, "#{header_segment}.#{payload_segment}")
      token = [header_segment, payload_segment, JWT::Base64.url_encode(signature)].join('.')

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::MalformedTokenError, /invalid_utf8 at position \d+/)
    end
  end

  describe 'detached payload' do
    it 'rejects a detached payload containing duplicate members once attached' do
      prepared = JWT::Token.new(payload: { 'a' => 1 })
      prepared.detach_payload!
      prepared.sign!(algorithm: 'HS256', key: secret)

      token = JWT::EncodedToken.new(prepared.jwt)
      token.encoded_payload = JWT::Base64.url_encode(%q({"a":1,"a":2}))

      expect do
        token.unverified_payload
      end.to raise_error(JWT::MalformedTokenError, /duplicate_member at position \d+/)
    end

    it 'verifies an attached detached payload that parses strictly' do
      prepared = JWT::Token.new(payload: { 'pay' => 'load', 'same' => 'x', 'other' => 'x' })
      prepared.detach_payload!
      prepared.sign!(algorithm: 'HS256', key: secret)

      token = JWT::EncodedToken.new(prepared.jwt)
      token.encoded_payload = prepared.encoded_payload
      token.verify!(signature: { algorithm: 'HS256', key: secret })

      expect(token.payload).to eq('pay' => 'load', 'same' => 'x', 'other' => 'x')
    end
  end

  describe 'signature failures' do
    it 'does not include payload content in the error message' do
      secret_value = 'PAYLOAD-THAT-MUST-NOT-LEAK'
      token = sign(%q({"alg":"HS256"}), %Q({"data":"#{secret_value}"}), key: 'the-real-key')

      error = begin
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      rescue JWT::VerificationError => e
        e
      end

      expect(error).to be_a(JWT::VerificationError)
      expect(error.message).to eq('Signature verification failed')
      expect(error.message).not_to include(secret_value)
    end

    it 'does not parse the payload at all when the signature is invalid' do
      header_segment = JWT::Base64.url_encode(%q({"alg":"HS256"}))
      payload_segment = JWT::Base64.url_encode('not even json')
      token = "#{header_segment}.#{payload_segment}.badsignature"

      expect do
        JWT.decode(token, secret, true, algorithms: ['HS256'])
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end
  end

  describe 'normal tokens' do
    it 'still verifies a token produced by the library' do
      token = JWT.encode({ 'user_id' => '42', 'exp' => Time.now.to_i + 3600 }, secret, 'HS256', { typ: 'JWT' })

      payload, header = JWT.decode(token, secret, true, algorithms: ['HS256'])
      expect(payload['user_id']).to eq('42')
      expect(header['alg']).to eq('HS256')
    end

    it 'keeps JWT::JSON.parse on standard library semantics for non-security callers' do
      expect(JWT::JSON.parse(%q({"a":1,"a":2}))).to eq('a' => 2)
    end

    it 'uses strict semantics through JWT::JSON.parse_strict' do
      expect do
        JWT::JSON.parse_strict(%q({"a":1,"a":2}))
      end.to raise_error(::JSON::ParserError, /duplicate_member at position \d+/)
    end
  end
end
