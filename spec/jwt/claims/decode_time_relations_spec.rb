# frozen_string_literal: true

RSpec.describe 'JWT.decode time relations' do
  let(:key) { 'secret' }

  def encode_token(payload)
    JWT.encode(payload, key, 'HS256')
  end

  describe 'verify_time_relations option' do
    let(:valid_payload) { { 'iat' => Time.now.to_i - 60, 'nbf' => Time.now.to_i - 30, 'exp' => Time.now.to_i + 60 } }

    it 'defaults to disabled and does not affect decode' do
      token = encode_token('iat' => Time.now.to_i + 10_000, 'exp' => Time.now.to_i - 1)
      expect { JWT.decode(token, key, true, { verify_expiration: false, verify_iat: false }) }.not_to raise_error
    end

    it 'rejects a token issued after its expiration when ordering is enabled' do
      token = encode_token('iat' => Time.now.to_i + 1_000, 'exp' => Time.now.to_i + 500)

      expect { JWT.decode(token, key, true, { verify_time_relations: true }) }
        .to raise_error(JWT::InvalidTimeRelation) do |error|
        expect(error.relation).to eq(:iat_before_exp)
      end
    end

    it 'rejects a token whose lifetime exceeds the configured maximum' do
      token = encode_token('iat' => Time.now.to_i - 7_200, 'exp' => Time.now.to_i + 60)

      expect { JWT.decode(token, key, true, { verify_time_relations: { max_lifetime: { max: 3_600 } } }) }
        .to raise_error(JWT::InvalidTimeRelation) do |error|
        expect(error.relation).to eq(:max_lifetime)
      end
    end

    it 'accepts a well-formed token with bounded lifetime' do
      token = encode_token(valid_payload)

      payload, = JWT.decode(token, key, true, { verify_time_relations: { order: true, max_lifetime: { max: 3_600 } } })
      expect(payload).to eq(valid_payload)
    end

    it 'supports a single injected time via the :now option' do
      fixed_now = Time.at(1_000)
      token = encode_token('iat' => 1_005, 'nbf' => 1_005, 'exp' => 2_000)

      expect do
        JWT.decode(token, key, true, {
          verify_expiration: false,
          verify_not_before: false,
          verify_time_relations: { now: fixed_now, order: true, max_future_iat: { leeway: 5 } }
        })
      end.not_to raise_error
    end
  end
end
