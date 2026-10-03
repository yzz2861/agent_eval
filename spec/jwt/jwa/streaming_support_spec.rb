# frozen_string_literal: true

RSpec.describe 'JWA streaming support' do
  describe 'algorithms that cannot hash incrementally' do
    it 'is rejected for signing instead of buffering the full body' do
      ps = JWT::JWA.resolve('PS256')
      expect { ps.stream_signer }.to raise_error(JWT::StreamingNotSupported, /streaming signing/)
    end

    it 'is rejected for verification instead of buffering the full body' do
      ec = JWT::JWA.resolve('ES256')
      expect { ec.stream_verifier }.to raise_error(JWT::StreamingNotSupported, /streaming verification/)
    end

    it 'is rejected for the none algorithm' do
      none = JWT::JWA.resolve('none')
      expect { none.stream_signer }.to raise_error(JWT::StreamingNotSupported)
      expect { none.stream_verifier }.to raise_error(JWT::StreamingNotSupported)
    end

    it 'is rejected for unknown algorithms' do
      unsupported = JWT::JWA.resolve('nope')
      expect { unsupported.stream_signer }.to raise_error(JWT::StreamingNotSupported)
    end
  end

  describe 'incremental algorithms' do
    %w[HS256 HS384 HS512 RS256 RS384 RS512].each do |alg|
      it "exposes incremental signer and verifier for #{alg}" do
        jwa = JWT::JWA.resolve(alg)
        expect(jwa).to respond_to(:stream_signer)
        expect(jwa).to respond_to(:stream_verifier)
      end
    end
  end
end
