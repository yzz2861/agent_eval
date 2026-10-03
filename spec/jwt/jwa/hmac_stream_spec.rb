# frozen_string_literal: true

RSpec.describe JWT::JWA::Hmac do
  let(:instance) { described_class.new('HS256', OpenSSL::Digest::SHA256) }
  let(:hmac_secret) { 'a' * 32 }

  describe '#stream_signer' do
    it 'produces the same signature as #sign when chunks are streamed' do
      signer = instance.stream_signer(signing_key: hmac_secret)
      data = 'the quick brown fox'
      signer.update(data[0, 4]).update(data[4, 3]).update(data[7..])

      expect(signer.sign).to eq(instance.sign(data: data, signing_key: hmac_secret))
    end

    it 'signs empty data identically to #sign' do
      signer = instance.stream_signer(signing_key: hmac_secret)
      expect(signer.sign).to eq(instance.sign(data: '', signing_key: hmac_secret))
    end

    [nil, ''].each do |bad_key|
      context "with #{bad_key.inspect} key" do
        it 'raises before streaming starts' do
          expect { instance.stream_signer(signing_key: bad_key) }.to raise_error(JWT::EncodeError)
        end
      end
    end
  end

  describe '#stream_verifier' do
    let(:data) { 'streaming verification input' }
    let(:signature) { instance.sign(data: data, signing_key: hmac_secret) }

    it 'verifies when data matches, independently of chunk boundaries' do
      verifier = instance.stream_verifier(signature: signature, verification_key: hmac_secret)
      verifier.update(data[0, 1]).update(data[1..])
      expect(verifier.valid?).to be(true)
    end

    it 'does not verify when data differs' do
      verifier = instance.stream_verifier(signature: signature, verification_key: hmac_secret)
      verifier.update(data + '!')
      expect(verifier.valid?).to be(false)
    end

    it 'rejects a wrong key type' do
      expect { instance.stream_verifier(signature: signature, verification_key: nil) }.to raise_error(JWT::VerificationKeyError)
    end
  end
end
